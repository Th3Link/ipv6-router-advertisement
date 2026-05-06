#![allow(dead_code)]
use futures::StreamExt;
use ipv6_router_advertisement::{Event, InterfaceIndex};
use std::net::Ipv6Addr;
use tokio::time::Duration;
use tracing_subscriber::{EnvFilter, fmt};

pub fn init_tracing() {
    let _ = fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("trace".parse().unwrap()))
        .with_test_writer()
        .try_init();
}

/// Convenience helper to create documentation IPv6 addresses (`2001:db8::x`)
/// for tests.
///
/// The parameter `x` is placed into the least significant 16 bits.
pub fn ip(x: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, x)
}

pub async fn collect_events(
    events: &mut (impl futures::Stream<Item = Event> + Unpin),
    max: usize,
) -> Vec<Event> {
    let mut out = Vec::new();

    for _ in 0..max {
        match tokio::time::timeout(Duration::from_millis(1), events.next()).await {
            Ok(Some(ev)) => out.push(ev),
            _ => break, // no more events in this phase
        }
    }

    out
}

/// Asserts that a `RaPrefix` event exists for the given interface
/// and that it contains exactly the expected prefix set.
///
/// This helper removes the matching event from `events`.
#[track_caller]
pub fn assert_prefixes(events: &mut Vec<Event>, ifindex: u32, expected: &[Ipv6Addr]) {
    let pos = events
        .iter()
        .position(|e| match e {
            Event::RaPrefix { ifindex: idx, .. } => *idx == ifindex,
            _ => false,
        })
        .expect("expected RaPrefix event not found");

    let event = events.remove(pos);

    match event {
        Event::RaPrefix { prefixes, .. } => {
            let mut got: Vec<Ipv6Addr> = prefixes.iter().map(|p| p.prefix).collect();

            let mut expected = expected.to_vec();

            got.sort();
            expected.sort();

            assert_eq!(got, expected, "prefix mismatch for interface {ifindex}");
        }
        _ => unreachable!("event type already matched"),
    }
}
#[track_caller]
pub fn assert_router_updates(
    events: &[Event],
    ifindex: InterfaceIndex,
    expected_managed: Option<bool>,
    expected_other_config: Option<bool>,
) {
    let ev = events
        .iter()
        .find_map(|e| match e {
            Event::RouterUpdate {
                ifindex: i,
                managed,
                other_config,
            } if *i == ifindex => Some((*managed, *other_config)),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!("expected RouterUpdate for ifindex {ifindex}, but none was found");
        });

    let (managed, other_config) = ev;

    if let Some(expected) = expected_managed {
        assert!(
            managed == expected,
            "managed flag mismatch for ifindex {ifindex}: expected {expected}, got {managed}"
        );
    }

    if let Some(expected) = expected_other_config {
        assert!(
            other_config == expected,
            "other_config flag mismatch for ifindex {ifindex}: expected {expected}, got {other_config}"
        );
    }
}

#[track_caller]
pub fn assert_router_down(events: &[Event], ifindex: InterfaceIndex) {
    assert!(
        events.iter().any(|e| matches!(
            e,
            Event::RouterDown { ifindex: i } if *i == ifindex
        )),
        "expected RouterDown for ifindex {ifindex}"
    );
}

#[track_caller]
pub fn assert_dns(
    events: &mut Vec<Event>,
    ifindex: InterfaceIndex,
    servers: &[u16],
    domains: &[&str],
) {
    // Normalize expected servers
    let mut expected_servers: Vec<Ipv6Addr> = servers
        .iter()
        .map(|i| format!("2001:db8::{i}").parse().unwrap())
        .collect();
    expected_servers.sort();

    // Normalize expected domains
    let mut expected_domains: Vec<String> = domains.iter().map(|s| s.to_string()).collect();
    expected_domains.sort();

    // Find *any* matching RaDns event for this interface
    let idx = events.iter().position(|e| match e {
        Event::RaDns {
            ifindex: i,
            servers,
            domains,
        } if *i == ifindex => {
            let mut got_servers = servers.clone();
            got_servers.sort();

            let mut got_domains = domains.clone();
            got_domains.sort();

            got_servers == expected_servers && got_domains == expected_domains
        }
        _ => false,
    });

    let idx = match idx {
        Some(i) => i,
        None => {
            panic!(
                "missing matching RaDns event for ifindex {ifindex}\n\
                 expected servers={:?}\n\
                 expected domains={:?}\n\
                 remaining events={:#?}",
                expected_servers, expected_domains, events,
            );
        }
    };

    // Remove the matched event so it cannot be reused
    let ev = events.remove(idx);

    tracing::trace!(
        ifindex,
        event = ?ev,
        "asserted and consumed RaDns event",
    );
}
