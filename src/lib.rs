#![doc = include_str!("../README.md")]

//! Policy-free IPv6 Router Advertisement processing.
//!
//! This crate listens for ICMPv6 Router Advertisements, performs parsing,
//! lifecycle handling and aggregation, and emits aggregated router events
//! as a stream.
//!
//! Dropping the returned stream immediately aborts all background processing.

mod aggregator;
mod detector;
pub mod icmpv6_socket;
mod lifecycle;
pub mod router_advertisement;

use aggregator::Aggregator;
use detector::detect;
use futures::StreamExt;
use futures::{
    future::{AbortHandle, Abortable},
    Stream,
};
use icmpv6_socket::{Icmpv6Socket, RealIcmpv6Socket};
use lifecycle::Lifecycle;
use router_advertisement::RouterAdvertisement;
use router_advertisement::{decode_router_advertisement, send_router_solicitation_burst};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Duration, Instant};
use tokio_stream::wrappers::ReceiverStream;
use tracing::debug;

/// IPv6 address identifying a router.
pub type RouterIp = Ipv6Addr;

/// Interface index on which router information applies.
pub type InterfaceIndex = u32;

/// Trait for types that carry a protocol-defined lifetime.
///
/// Implementors represent data whose validity is explicitly bounded
/// by a duration as advertised on the wire (e.g. via Router Advertisements).
///
/// The returned lifetime:
/// - is interpreted relative to the time of reception,
/// - is converted into an absolute expiration timestamp by the lifecycle layer,
/// - may be zero to indicate an explicit withdrawal of previously advertised data.
///
/// This trait intentionally carries **no time semantics** beyond exposing
/// the raw lifetime value; expiration handling is performed by higher layers.
pub trait Lifetime {
    /// Returns the advertised lifetime of this item.
    fn lifetime(&self) -> Duration;
}

/// IPv6 Prefix Information as advertised via the Prefix Information Option (PIO)
/// in an ICMPv6 Router Advertisement (RFC 4861).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrefixInfo {
    /// IPv6 network prefix advertised by the router.
    ///
    /// This is the base address of the prefix. Bits beyond `prefix_len`
    /// MUST be ignored.
    pub prefix: Ipv6Addr,

    /// Length of the IPv6 prefix in bits.
    ///
    /// Typical values are:
    /// - 64 for SLAAC prefixes
    /// - 48 / 56 / 60 for delegated prefixes
    pub prefix_len: u8,
}

/// Aggregated, policy-free router events emitted by this crate.
///
/// These events represent changes in the *effective* Router Advertisement
/// (RA) state as observed on a given interface.
///
/// ## Event semantics
///
/// - Events are emitted **only when the aggregated state changes**.
/// - Multiple Router Advertisements may be coalesced into a single event.
/// - Events are always scoped to a single interface (`ifindex`).
/// - Each event carries the **complete current state** of the affected section.
///
/// This crate performs **no policy decisions**:
/// it does not start DHCPv6, configure addresses, or modify the system.
/// Consumers are expected to interpret these events according to their
/// own policy (e.g. via a network manager or FSM).
#[derive(Debug, Clone)]
pub enum Event {
    /// At least one active router is available on this interface.
    ///
    /// This event is emitted when:
    /// - the first router becomes active on the interface, or
    /// - router flags (M/O) change as a result of aggregation.
    RouterUpdate {
        /// Network interface index.
        ifindex: InterfaceIndex,
        /// Managed (M) flag is set by at least one active router.
        managed: bool,
        /// Other Configuration (O) flag is set by at least one active router.
        other_config: bool,
    },

    /// All previously known routers on this interface have expired.
    ///
    /// This event is emitted when the last active router on the interface
    /// expires according to its advertised lifetime.
    RouterDown {
        /// Network interface index.
        ifindex: InterfaceIndex,
    },

    /// DNS information learned via Router Advertisements (RDNSS/DNSSL).
    ///
    /// This event represents the **complete current DNS state** for the
    /// interface, aggregated across all active routers.
    ///
    /// - `servers` contains the deduplicated DNS server list.
    /// - `domains` contains the deduplicated DNS search domain list.
    ///
    /// An empty list explicitly indicates that no DNS information
    /// remains valid for the interface.
    RaDns {
        /// Network interface index.
        ifindex: InterfaceIndex,
        /// Aggregated DNS servers.
        servers: Vec<Ipv6Addr>,
        /// Aggregated DNS search domains.
        domains: Vec<String>,
    },

    /// Prefix information learned via Router Advertisements (PIO).
    ///
    /// This event represents the **complete set of currently valid prefixes**
    /// for the interface, aggregated across all active routers.
    ///
    /// Prefixes are lease-based and may expire independently.
    RaPrefix {
        /// Network interface index.
        ifindex: InterfaceIndex,
        /// Aggregated valid prefixes.
        prefixes: Vec<PrefixInfo>,
    },

    /// Advisory event indicating that a prefix has reached its preferred lifetime.
    ///
    /// This event does **not** remove the prefix. It signals that the prefix
    /// should no longer be preferred for new address assignments, while
    /// remaining valid until its hard lifetime expires.
    RaPrefixSoftExpiry {
        /// Network interface index.
        ifindex: InterfaceIndex,
        /// The prefix whose preferred lifetime has expired.
        prefix: PrefixInfo,
    },
}

/// Stream of aggregated, policy-free router events.
///
/// This stream is backed by an internal background task which:
/// - receives Router Advertisements via a raw ICMPv6 socket,
/// - performs lifecycle tracking and aggregation,
/// - emits semantic router events.
///
/// ## Cancellation
///
/// Dropping this stream **immediately aborts** all background processing,
/// including:
/// - the ICMPv6 receive loop,
/// - lifecycle timers,
/// - any outstanding Router Solicitation bursts.
///
/// No explicit shutdown or cancellation handle is required.
pub struct RouterEventStream {
    /// Internal receiver yielding aggregated router events.
    inner: ReceiverStream<Event>,
    /// Abort handle used to immediately cancel all background tasks on drop.
    abort: AbortHandle,
}

/// Delegates polling to the underlying receiver stream.
///
/// `RouterEventStream` implements `Stream<Item = Event>` and yields
/// aggregated router events as they occur.
///
/// The stream ends only when the underlying task is terminated.
impl Stream for RouterEventStream {
    type Item = Event;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// Aborts all background processing immediately when the stream is dropped.
///
/// This ensures that no background tasks remain alive once the consumer
/// stops polling the str
impl Drop for RouterEventStream {
    fn drop(&mut self) {
        // Immediate cancellation of all background processing.
        self.abort.abort();
    }
}

impl RouterEventStream {
    pub fn empty() -> Self {
        let (_tx, rx) = mpsc::channel::<Event>(1);
        let (abort, _) = AbortHandle::new_pair();

        RouterEventStream {
            inner: ReceiverStream::new(rx),
            abort,
        }
    }
}

/// Start processing IPv6 Router Advertisements and return a stream of
/// aggregated router events.
///
/// # Cancellation
///
/// Dropping the returned stream **immediately aborts** all background
/// processing, closes the ICMPv6 socket and stops any outstanding Router
/// Solicitation activity.
///
/// # Parameters
///
/// - `link_up_rx`: Broadcast receiver emitting interface indices whose
///   links have transitioned to `UP`.
///
/// # Returns
///
/// A `Stream<Item = Event>` producing aggregated, policy-free router events.
///
/// # Notes
///
/// - The stream owns all background tasks.
/// - No external shutdown or cancellation handle is required.
/// - This function requires Tokio and Linux.
///
/// # Example
///
/// ```no_run
/// use futures::StreamExt;
/// use tokio_stream::wrappers::BroadcastStream;
///
/// # async fn example() -> anyhow::Result<()> {
/// let (link_tx, link_rx) = tokio::sync::broadcast::channel(16);
///
/// // Convert broadcast receiver into a Stream of interface indices
/// let link_up_stream = BroadcastStream::new(link_rx)
///     .filter_map(|res| async move { res.ok() });
///
/// let mut events = ipv6_router_advertisement::router_events(link_up_stream);
///
/// // Signal that interface 2 is up
/// let _ = link_tx.send(2);
///
/// while let Some(event) = events.next().await {
///     println!("router event: {:?}", event);
/// }
/// # Ok(())
/// # }
/// ```
pub fn router_events<S>(link_up: S) -> RouterEventStream
where
    S: Stream<Item = InterfaceIndex> + Send + 'static,
{
    let socket = match RealIcmpv6Socket::new() {
        Ok(s) => Arc::new(s),
        Err(e) => {
            debug!("failed to create RA socket: {:?}", e);
            return RouterEventStream::empty();
        }
    };

    router_events_with_socket(link_up, socket)
}

/// Creates a stream of aggregated router events using a custom ICMPv6 socket.
///
/// This function wires together the complete processing pipeline:
///
/// - interface-up notifications,
/// - Router Advertisement reception via the provided socket,
/// - detector, lifecycle, and aggregation layers.
///
/// The returned stream yields high-level, policy-free `Event`s describing
/// changes in the effective RA state per interface.
///
/// ## Parameters
///
/// - `link_up`: A stream producing interface indices when interfaces become active.
/// - `socket`: An ICMPv6 socket used to receive Router Advertisements.
///
/// ## Returns
///
/// A `RouterEventStream` yielding aggregated router events.
pub fn router_events_with_socket<S, I>(link_up: S, socket: Arc<I>) -> RouterEventStream
where
    S: Stream<Item = InterfaceIndex> + Send + 'static,
    I: Icmpv6Socket + Send + Sync + 'static,
{
    let (event_tx, event_rx) = mpsc::channel::<Event>(16);
    let (abort_handle, abort_reg) = AbortHandle::new_pair();

    tokio::spawn(async move {
        let mut link_up = Box::pin(link_up);

        let mut aggregator = Aggregator::default();
        let mut lifecycle = Lifecycle::default();
        let mut pending_rs = HashMap::new();

        let task = async {
            loop {
                let now = Instant::now();
                tokio::select! {
                    Some(ifindex) = link_up.next() => {
                        start_rs_burst(
                            Arc::clone(&socket),
                            &mut pending_rs,
                            ifindex,
                        );
                    }

                    Ok((ifindex, router_ip, payload)) = socket.receive() => {
                        let Ok(ra) =
                            decode_router_advertisement(ifindex, router_ip, &payload)
                        else {
                            continue;
                        };

                        let lifecycle_events =
                            handle_router_advertisement(
                                ra,
                                &mut lifecycle,
                                &mut pending_rs,
                                now
                            );

                        if !emit_aggregated(
                            &mut aggregator,
                            lifecycle_events,
                            &event_tx,
                        ).await {
                            return;
                        }
                    }

                    _ = lifecycle_sleep(&lifecycle) => {
                        let (expired, soft_expiry) = lifecycle.expire(Instant::now());
                        emit_soft_expiry(&aggregator, soft_expiry, &event_tx).await;
                        if !emit_aggregated(
                            &mut aggregator,
                            expired,
                            &event_tx,
                        ).await {
                            return;
                        }
                    }
                }
            }
        };

        let _ = Abortable::new(task, abort_reg).await;
    });

    RouterEventStream {
        inner: ReceiverStream::new(event_rx),
        abort: abort_handle,
    }
}

/// Await until the next lifecycle expiration, if any.
///
/// This function converts the next expiration timestamp provided by
/// `Lifecycle` into an awaitable future.
///
/// If no expiration is scheduled, this function awaits indefinitely.
///
/// ## Notes
///
/// - This function performs no lifecycle logic itself.
/// - It exists solely to bridge timestamp-based lifecycle data
///   with Tokio's async scheduling.
async fn lifecycle_sleep(lifecycle: &Lifecycle) {
    if let Some(deadline) = lifecycle.next_expiry() {
        sleep_until(deadline).await;
    } else {
        futures::future::pending::<()>().await;
    }
}

/// Emit soft-expiry events for prefixes whose preferred lifetime expired.
///
/// Soft expiry is a *status change*, not a structural change:
/// the prefix remains valid until its hard (valid) lifetime expires.
/// Therefore, these events intentionally bypass the aggregator diff logic.
///
/// Returns `false` if the output stream has been dropped and no further
/// events should be produced.
async fn emit_soft_expiry(
    aggregator: &Aggregator,
    lifecycle_events: Vec<lifecycle::Event>,
    tx: &mpsc::Sender<Event>,
) -> bool {
    for ev in lifecycle_events {
        let lifecycle::Event::PrefixSoftExpiry { key, prefix_info } = ev else {
            continue;
        };

        // Soft expiry is only meaningful if the prefix still exists
        let Some(prefixes) = aggregator.get_prefixes(&key) else {
            // Prefix already gone (hard expiry won), nothing to emit
            continue;
        };

        if !prefixes.contains(&prefix_info) {
            continue;
        }

        let out = Event::RaPrefixSoftExpiry {
            ifindex: key.ifindex,
            prefix: prefix_info,
        };

        if tx.send(out).await.is_err() {
            return false; // consumer dropped the stream
        }
    }

    true
}

/// Aggregate lifecycle events and emit resulting router events.
///
/// Returns `false` if the output stream has been dropped and no further
/// events should be produced.
///
/// ## Returns
///
/// - `true` if all events were successfully emitted
/// - `false` if the consumer has dropped the stream
async fn emit_aggregated(
    aggregator: &mut Aggregator,
    events: Vec<lifecycle::Event>,
    tx: &mpsc::Sender<Event>,
) -> bool {
    let aggregated = aggregator.process(events);

    for ev in aggregated {
        if tx.send(ev).await.is_err() {
            return false; // stream dropped
        }
    }
    true
}

/// Process a received Router Advertisement.
///
/// This function:
/// - cancels any pending Router Solicitation for the interface,
/// - converts the RA into policy-free detector events,
/// - updates lifecycle state using the current timestamp,
/// - returns resulting lifecycle events for aggregation.
fn handle_router_advertisement(
    ra: RouterAdvertisement,
    lifecycle: &mut Lifecycle,
    pending_rs: &mut HashMap<InterfaceIndex, AbortHandle>,
    now: Instant,
) -> Vec<lifecycle::Event> {
    if let Some(handle) = pending_rs.remove(&ra.ifindex) {
        handle.abort();
    }

    let detector_events = detect(ra);
    lifecycle.update(detector_events, now)
}

/// Start a Router Solicitation burst for the given interface.
///
/// Any previously running solicitation burst for the same interface
/// is immediately aborted.
///
/// The solicitation burst runs in a background task and is expected
/// to be cancelled either:
/// - when a Router Advertisement is received, or
/// - when the parent event stream is dropped.
fn start_rs_burst<I: Icmpv6Socket + 'static>(
    socket: Arc<I>,
    pending_rs: &mut HashMap<InterfaceIndex, AbortHandle>,
    ifindex: InterfaceIndex,
) {
    if let Some(handle) = pending_rs.remove(&ifindex) {
        handle.abort();
    }

    let (rs_abort, rs_reg) = AbortHandle::new_pair();
    pending_rs.insert(ifindex, rs_abort);

    tokio::spawn(async move {
        let rs_task = async {
            send_router_solicitation_burst(&*socket, ifindex, 3, Duration::from_secs(1)).await;
        };
        let _ = Abortable::new(rs_task, rs_reg).await;
    });
}

#[cfg(test)]
mod tests {
    use detector::{DnsServers, Key};

    use super::*;

    #[tokio::test]
    async fn stream_drop_aborts_background_task() -> anyhow::Result<()> {
        use tokio_stream::wrappers::ReceiverStream;

        let (_tx, rx) = tokio::sync::mpsc::channel::<u32>(1);
        let stream = router_events(ReceiverStream::new(rx));

        // Drop immediately
        drop(stream);

        // If this test hangs, abort handling is broken.
        Ok(())
    }

    #[test]
    fn lifecycle_expiry_triggers_router_down() -> anyhow::Result<()> {
        let mut lifecycle = Lifecycle::default();
        let mut aggregator = Aggregator::default();

        let now = Instant::now();

        // Pretend we detected a router
        let events = lifecycle.update(
            vec![detector::Event::Router {
                key: Key::new(1, Ipv6Addr::LOCALHOST),
                managed: false,
                other_config: false,
                lifetime: Duration::from_secs(1),
            }],
            now,
        );
        let _aggregated = aggregator.process(events);

        // Advance time past expiry
        let (expired, _soft_expired) = lifecycle.expire(now + Duration::from_secs(2));
        println!("expired: {expired:?}");
        let aggregated = aggregator.process(expired);
        println!("aggregated: {aggregated:?}");

        anyhow::ensure!(aggregated
            .iter()
            .any(|e| matches!(e, Event::RouterDown { ifindex: 1 })));
        Ok(())
    }

    #[test]
    fn ra_dns_event_is_emitted() -> anyhow::Result<()> {
        let mut aggregator = Aggregator::default();

        let events = vec![lifecycle::Event::DnsServers {
            key: detector::Key::new(1, Ipv6Addr::LOCALHOST),
            servers: vec![DnsServers {
                servers: vec!["2001:db8::1".parse().unwrap()],
                lifetime: Duration::from_secs(1),
            }],
        }];

        let aggregated = aggregator.process(events);

        anyhow::ensure!(aggregated
            .iter()
            .any(|e| matches!(e, Event::RaDns { ifindex: 1, .. })));
        Ok(())
    }
}
