mod fixtures;
mod helpers;
mod pcap;

use fixtures::mock_socket::MockIcmpv6Socket;
use helpers::{assert_dns, assert_router_updates, collect_events, init_tracing};
use ipv6_router_advertisement::router_events_with_socket;
use pcap::*;
use std::sync::Arc;

#[tokio::test(start_paused = true)]
async fn replay_pcap_flat_produces_expected_events() -> anyhow::Result<()> {
    init_tracing();

    let socket = Arc::new(MockIcmpv6Socket::new());
    let frames = loader::load_ra_frames_from_pcap("tests/data/pcap/radvd-prefix-dns.pcapng", 2)?;
    let mut events = router_events_with_socket(futures::stream::empty(), socket.clone());

    replay_flat::replay(&socket, frames).await;

    let evs = collect_events(&mut events, 10).await;

    assert_router_updates(&evs, 2, None, None);
    assert_dns(&mut evs.clone(), 2, &[1, 2], &["example.com."]);

    Ok(())
}
