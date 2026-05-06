mod fixtures;
mod helpers;

use fixtures::mock_socket::MockIcmpv6Socket;
use fixtures::ra::{ra_minimal, ra_with_rdnss_dnssl};
use futures::StreamExt;
use helpers::*;
use ipv6_router_advertisement::{Event, router_events_with_socket};
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::time::{Duration, advance};

#[tokio::test(start_paused = true)]
async fn emits_router_up_after_ra() -> anyhow::Result<()> {
    init_tracing();
    let socket = Arc::new(MockIcmpv6Socket::new());

    let link_up = futures::stream::iter(vec![2u32]);
    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    // RS-Burst
    advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    let sent = socket.sent_packets();
    anyhow::ensure!(
        sent.iter()
            .any(|(_, dst, _)| *dst == Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2)),
        "no RS sent"
    );

    // inject RA
    socket.inject_ra(2, "fe80::1".parse()?, ra_minimal(1800));

    tokio::task::yield_now().await;

    let event = events.next().await.expect("stream ended");

    match event {
        Event::RouterUpdate {
            managed,
            other_config,
            ..
        } => {
            anyhow::ensure!(managed);
            anyhow::ensure!(other_config);
        }
        other => panic!("unexpected event: {:?}", other),
    }

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn rs_burst_aborts_on_ra() -> anyhow::Result<()> {
    init_tracing();
    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32]);

    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    // RS #1
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    assert!(!socket.sent_packets().is_empty(), "RS not sent");

    // Inject RA → should abort further RS
    socket.inject_ra(2, "fe80::1".parse()?, ra_minimal(1800));
    tokio::task::yield_now().await;

    let _ = events.next().await.expect("event expected");

    let sent_after = socket.sent_packets().len();

    // Advance far beyond RS burst window
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::task::yield_now().await;

    anyhow::ensure!(
        sent_after == socket.sent_packets().len(),
        "RS burst was not aborted"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn lifecycle_expiry_emits_event() -> anyhow::Result<()> {
    init_tracing();
    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32]);

    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    socket.inject_ra(2, "fe80::1".parse()?, ra_minimal(1800));
    tokio::task::yield_now().await;

    let _ = events.next().await; // RouterUp

    // Advance beyond router lifetime
    tokio::time::advance(Duration::from_secs(1801)).await;
    tokio::task::yield_now().await;

    let ev = events.next().await.expect("expiry event expected");
    anyhow::ensure!(matches!(ev, Event::RouterDown { .. }));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn parses_rdnss_and_dnssl_end_to_end() -> anyhow::Result<()> {
    init_tracing();
    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32]);

    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    tokio::task::yield_now().await;

    socket.inject_ra(
        2,
        "fe80::1".parse()?,
        ra_with_rdnss_dnssl(1800, 60, &[1, 2], 60, &["example.com"]),
    );

    match events.next().await.unwrap() {
        Event::RouterUpdate { .. } => {}
        other => panic!("unexpected event: {other:?}"),
    }

    match events.next().await.unwrap() {
        Event::RaDns {
            servers, domains, ..
        } => {
            tracing::debug!("servers: {servers:?}");
            anyhow::ensure!(!servers.is_empty(), "servers: {servers:?}");
            anyhow::ensure!(!domains.is_empty(), "domains: {domains:?}");
        }
        other => panic!("unexpected event: {other:?}"),
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn multi_interface_multi_router_expiry() -> anyhow::Result<()> {
    init_tracing();
    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32, 3u32]);

    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    socket.inject_ra(2, "fe80::1".parse()?, ra_minimal(1000));
    socket.inject_ra(2, "fe80::2".parse()?, ra_minimal(1200));
    socket.inject_ra(3, "fe80::3".parse()?, ra_minimal(1800));
    tokio::task::yield_now().await;

    let _ = events.next().await; // if2 up
    let _ = events.next().await; // if3 up

    // Expire only interface 2
    tokio::time::advance(Duration::from_secs(1201)).await;
    tokio::task::yield_now().await;

    match events.next().await.unwrap() {
        Event::RouterDown { ifindex: 2, .. } => {}
        other => panic!("unexpected event: {other:?}"),
    }

    Ok(())
}

#[tokio::test(start_paused = true)]
#[track_caller]
async fn multi_interface_multi_router_dns_expiry() -> anyhow::Result<()> {
    init_tracing();

    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32, 3u32]);
    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    // Initial Router Advertisements
    socket.inject_ra(
        2,
        "fe80::1".parse()?,
        ra_with_rdnss_dnssl(200, 60, &[1, 2, 3], 60, &["example1.com", "example2.com"]),
    );
    socket.inject_ra(
        2,
        "fe80::2".parse()?,
        ra_with_rdnss_dnssl(90, 120, &[3, 4], 100, &["example2.com", "example3.com"]),
    );
    socket.inject_ra(
        3,
        "fe80::3".parse()?,
        ra_with_rdnss_dnssl(280, 280, &[5, 6], 280, &["example3.com", "example4.com"]),
    );
    socket.inject_ra(
        3,
        "fe80::4".parse()?,
        ra_with_rdnss_dnssl(400, 500, &[7, 8], 450, &["example4.com"]),
    );

    // Phase 1: initial aggregation
    let mut evs = collect_events(&mut events, 10).await;

    // Interface 2
    assert_router_updates(&evs, 2, None, None);

    assert_dns(&mut evs, 2, &[1, 2, 3], &["example1.com.", "example2.com."]);
    assert_dns(
        &mut evs,
        2,
        &[1, 2, 3, 4],
        &["example1.com.", "example2.com.", "example3.com."],
    );

    // Interface 3
    assert_router_updates(&evs, 3, None, None);
    assert_dns(&mut evs, 3, &[5, 6], &["example3.com.", "example4.com."]);
    assert_dns(
        &mut evs,
        3,
        &[5, 6, 7, 8],
        &["example3.com.", "example4.com."],
    );

    // Phase 2: DNS expiry on fe80::1 (ifindex 2, 61s)
    tokio::time::advance(Duration::from_secs(61)).await;

    let mut evs = collect_events(&mut events, 5).await;

    // DNS from fe80::1 expired, fe80::2 still contributes
    assert_dns(&mut evs, 2, &[3, 4], &["example2.com.", "example3.com."]);

    // Phase 3: router fe80::2 expires (91s)
    // domains from fe80::2 expire (101s)
    // servers from fe80::2 expire (121s)
    tokio::time::advance(Duration::from_secs(30)).await; // total 91

    let mut evs = collect_events(&mut events, 5).await;

    // Router fe80::1 is still alive → no RouterDown yet
    assert!(
        !evs.iter()
            .any(|e| matches!(e, Event::RouterDown { ifindex: 2 })),
        "did not expect RouterDown for interface 2 yet"
    );
    assert_dns(&mut evs, 2, &[], &[]);

    // Phase 4: router fe80::1 expires (200s)
    tokio::time::advance(Duration::from_secs(110)).await; // total 201

    let evs = collect_events(&mut events, 5).await;
    assert_router_down(&evs, 2);

    // Phase 5: interface 3 refresh fe80::3
    tokio::time::advance(Duration::from_secs(50)).await; // total 251

    socket.inject_ra(
        3,
        "fe80::3".parse()?,
        ra_with_rdnss_dnssl(80, 70, &[5, 6], 60, &["example3.com", "example4.com"]),
    );
    let evs = collect_events(&mut events, 5).await;
    anyhow::ensure!(evs.is_empty(), "events should be empty but: {evs:?}");
    // old ra would have expired at 260. but we just keep alive, so no update
    tokio::time::advance(Duration::from_secs(60)).await; // total 291

    let mut evs = collect_events(&mut events, 5).await;
    assert_dns(&mut evs, 3, &[7, 8], &["example4.com."]);

    // Phase 6: step by step expire the remaining router and dns
    tokio::time::advance(Duration::from_secs(110)).await; // total 401
    tokio::task::yield_now().await;

    let mut evs = collect_events(&mut events, 5).await;
    assert_router_down(&evs, 3);
    assert_dns(&mut evs, 3, &[], &[]);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn parses_prefix_end_to_end() -> anyhow::Result<()> {
    init_tracing();

    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32]);
    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    socket.inject_ra(
        2,
        "fe80::1".parse()?,
        fixtures::ra::ra_with_prefix(
            1800,
            ip(10),
            64,
            300, // valid lifetime
            100, // preferred lifetime
        ),
    );

    // RouterUpdate first
    match events.next().await.unwrap() {
        Event::RouterUpdate { .. } => {}
        other => panic!("unexpected event: {other:?}"),
    }

    // Prefix event
    match events.next().await.unwrap() {
        Event::RaPrefix { ifindex, prefixes } => {
            anyhow::ensure!(ifindex == 2);
            anyhow::ensure!(prefixes.len() == 1);
            anyhow::ensure!(prefixes[0].prefix == ip(10));
            anyhow::ensure!(prefixes[0].prefix_len == 64);
        }
        other => panic!("unexpected event: {other:?}"),
    }

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn prefix_valid_lifetime_expiry_emits_update() -> anyhow::Result<()> {
    init_tracing();

    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32]);
    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    socket.inject_ra(
        2,
        "fe80::1".parse()?,
        fixtures::ra::ra_with_prefix(
            1000,
            ip(20),
            64,
            60, // valid lifetime
            30, // preferred lifetime
        ),
    );

    // RouterUpdate + RaPrefix
    let _ = events.next().await;
    let _ = events.next().await;

    // After preferred lifetime (soft expiry)
    tokio::time::advance(Duration::from_secs(31)).await;
    tokio::task::yield_now().await;

    match events.next().await.unwrap() {
        Event::RaPrefixSoftExpiry { ifindex, prefix } => {
            anyhow::ensure!(ifindex == 2);
            anyhow::ensure!(prefix.prefix == ip(20));
        }
        other => panic!("unexpected event: {other:?}"),
    }

    // After valid lifetime
    tokio::time::advance(Duration::from_secs(40)).await;
    tokio::task::yield_now().await;

    match events.next().await.unwrap() {
        Event::RaPrefix { prefixes, .. } => {
            anyhow::ensure!(prefixes.is_empty());
        }
        other => panic!("unexpected event: {other:?}"),
    }

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn multi_interface_multi_router_prefix_expiry() -> anyhow::Result<()> {
    init_tracing();

    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32, 3u32]);
    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    // Interface 2
    socket.inject_ra(
        2,
        "fe80::1".parse()?,
        fixtures::ra::ra_with_prefix(200, ip(10), 64, 60, 30),
    );
    socket.inject_ra(
        2,
        "fe80::2".parse()?,
        fixtures::ra::ra_with_prefix(300, ip(20), 56, 120, 0),
    );

    // Interface 3
    socket.inject_ra(
        3,
        "fe80::3".parse()?,
        fixtures::ra::ra_with_prefix(500, ip(30), 64, 400, 0),
    );

    // drain initial events
    let mut evs = collect_events(&mut events, 10).await;

    // if2 prefixes aggregated
    assert_prefixes(&mut evs, 2, &[ip(10)]);
    assert_prefixes(&mut evs, 2, &[ip(10), ip(20)]);

    // if3 prefixes aggregated
    assert_prefixes(&mut evs, 3, &[ip(30)]);

    // Expire prefix ip(10) on if2
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;

    let mut evs = collect_events(&mut events, 5).await;
    assert_prefixes(&mut evs, 2, &[ip(20)]);
    assert!(
        !evs.iter().any(|e| matches!(e, Event::RouterDown { .. })),
        "router should still be alive"
    );

    Ok(())
}

#[tokio::test(start_paused = true)]
async fn multi_interface_multi_router_dns_and_prefix_expiry() -> anyhow::Result<()> {
    init_tracing();

    let socket = Arc::new(MockIcmpv6Socket::new());
    let link_up = futures::stream::iter(vec![2u32]);
    let mut events = router_events_with_socket(link_up, Arc::clone(&socket));

    socket.inject_ra(
        2,
        "fe80::1".parse()?,
        ra_with_rdnss_dnssl(200, 60, &[1, 2], 60, &["example.com"]),
    );
    socket.inject_ra(
        2,
        "fe80::1".parse()?,
        fixtures::ra::ra_with_prefix(200, ip(10), 64, 120, 60),
    );

    let mut evs = collect_events(&mut events, 10).await;
    assert_dns(&mut evs, 2, &[1, 2], &["example.com."]);
    assert_prefixes(&mut evs, 2, &[ip(10)]);

    // Let DNS expire first
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;

    let mut evs = collect_events(&mut events, 5).await;
    assert_dns(&mut evs, 2, &[], &[]);
    assert!(!evs.iter().any(|e| matches!(e, Event::RouterDown { .. })));

    // Let prefix expire next
    tokio::time::advance(Duration::from_secs(61)).await;
    tokio::task::yield_now().await;

    let mut evs = collect_events(&mut events, 5).await;
    assert_prefixes(&mut evs, 2, &[]);

    Ok(())
}
