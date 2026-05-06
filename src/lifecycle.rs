//! Lifecycle management for router-related state derived from detector events.
//!
//! This module tracks the lifetime of detected router information and emits
//! lifecycle events when information is added, refreshed, or expires.
//!
//! Responsibilities:
//! - Maintain per-source expiration state.
//! - Convert detector events into lifecycle events.
//! - Emit expiry events when lifetimes elapse.
//!
//! The lifecycle layer is intentionally unaware of aggregation or FSM logic.
//! It produces semantically meaningful events that higher layers can interpret.

use super::PrefixInfo;
use super::detector::Event as DetectorEvent;
use super::detector::{DnsDomains, DnsServers, Key};
use std::collections::HashMap;
use tokio::time::Instant;
use tracing::trace;

/// Absolute expiration timestamp for a lifecycle entry.
type Expiry = tokio::time::Instant;

/// Lifecycle events emitted based on detector input and expiry.
///
/// These events represent changes in the validity of router-related data.
/// They are consumed by higher layers for aggregation and FSM processing.
#[derive(Clone, Debug)]
pub enum Event {
    /// Router configuration update.
    Router {
        key: Key,
        managed: bool,
        other_config: bool,
    },
    /// DNS server list update.
    DnsServers { key: Key, servers: Vec<DnsServers> },
    /// DNS search domain update.
    DnsDomains { key: Key, domains: Vec<DnsDomains> },
    /// Prefix update.
    Prefix { key: Key, prefix_info: PrefixInfo },
    /// Indicates that a previously active entry has expired.
    RouterExpiry { key: Key },
    /// Indicates that a Prefix is expired.
    PrefixExpiry { key: Key, prefix_info: PrefixInfo },
    /// Indicates deprecation: Do not use it further, but its still valid.
    PrefixSoftExpiry { key: Key, prefix_info: PrefixInfo },
}

/// Converts a detector event into a lifecycle event.
///
/// Detector events describe observed router state, while lifecycle events
/// express changes in validity and lifetime
impl From<DetectorEvent> for Event {
    fn from(ev: DetectorEvent) -> Self {
        use DetectorEvent::*;
        match ev {
            Router {
                key,
                managed,
                other_config,
                lifetime,
            } => {
                if lifetime.is_zero() {
                    Event::RouterExpiry { key }
                } else {
                    Event::Router {
                        key,
                        managed,
                        other_config,
                    }
                }
            }
            DnsServers(key, servers) => Event::DnsServers { key, servers },
            DnsDomains(key, domains) => Event::DnsDomains { key, domains },
            Prefix {
                key,
                prefix_info,
                lifetime,
                ..
            } => {
                if lifetime.is_zero() {
                    Event::PrefixExpiry { key, prefix_info }
                } else {
                    Event::Prefix { key, prefix_info }
                }
            }
        }
    }
}

/// A single lifecycle-managed data entry with an absolute expiration time.
///
/// A `LifecycleEntry` represents one independently expiring contribution
/// associated with a logical lifecycle key (e.g., a DNS lifetime group
/// or a prefix lease).
///
/// The entry becomes invalid once `expires_at` is reached. Expiry handling
/// itself is performed by the surrounding `Lifecycle` and not by this type.
///
/// This structure deliberately contains no notion of identity beyond
/// the stored data itself; higher layers are responsible for deciding
/// how expirations are mapped to events or state updates.
struct LifecycleEntry<T> {
    /// Payload data associated with this lifecycle entry.
    data: T,

    /// Absolute timestamp at which the entry expires.
    expires_at: Instant,
}

impl<T> LifecycleEntry<T> {
    /// Creates a new lifecycle entry with the given payload and expiration time.
    pub fn new(data: T, expires_at: Instant) -> Self {
        Self { data, expires_at }
    }
}

/// Storage type for lifecycle-managed entries keyed by their logical owner.
///
/// Each key maps to a set of independently expiring entries. This is required
/// for data types where multiple lifetime groups may coexist under the same
/// logical identity (e.g., DNS options with different lifetimes, or multiple
/// prefix leases from a single router).
///
/// Expiration semantics are handled by the `Lifecycle` using absolute
/// timestamps stored in the individual `LifecycleEntry` values.
type LifecycleStore<T> = HashMap<Key, Vec<LifecycleEntry<T>>>;

/// Lifecycle state manager.
///
/// The `Lifecycle` owns all time-based semantics of router advertisement
/// information. It is the single authority responsible for:
///
/// - Tracking absolute expiration times of all active entries.
/// - Removing expired entries deterministically.
/// - Emitting lifecycle events that describe semantic state changes.
///
/// The lifecycle layer is strictly agnostic of aggregation, policy, or
/// protocol emission logic. It does **not** compute desired RA state;
/// instead, it maintains authoritative per-router state and reports
/// changes to higher layers.
///
/// ## Design notes
///
/// - Router state is singular and expires as a whole.
/// - DNS data is state-based and may contain multiple lifetime groups.
/// - Prefix data is lease-based and expires per prefix.
/// - Soft expiries (preferred lifetimes) are tracked separately and
///   generate advisory events without removing data.
///
/// Aggregation and diffing are intentionally handled by the `Aggregator`.
#[derive(Default)]
pub struct Lifecycle {
    /// Active routers and their absolute expiration timestamps.
    ///
    /// A router expiring here implicitly invalidates all state derived
    /// from that router.
    router_store: HashMap<Key, Expiry>,

    /// DNS server information with lifetime-group semantics.
    ///
    /// Each key may contain multiple entries with different expiration
    /// times, reflecting multiple RDNSS options.
    dns_servers_store: LifecycleStore<DnsServers>,

    /// DNS search domain information with lifetime-group semantics.
    ///
    /// Similar to DNS servers, multiple DNSSL options may be active
    /// simultaneously under the same key.
    dns_domains_store: LifecycleStore<DnsDomains>,

    /// Active prefix leases.
    ///
    /// Each prefix lease expires independently according to its valid
    /// lifetime and produces granular expiry events.
    prefix_store: LifecycleStore<PrefixInfo>,

    /// Preferred-lifetime (soft expiry) tracking for prefixes.
    ///
    /// Entries here generate advisory soft-expiry events but do not
    /// immediately invalidate the corresponding prefix lease.
    soft_prefix_store: LifecycleStore<PrefixInfo>,
}

impl Lifecycle {
    /// Applies detector events and refreshes their associated lifetimes.
    ///
    /// Each detector event:
    /// - refreshes or inserts an entry with a new expiry timestamp
    /// - immediately emits a corresponding lifecycle event
    pub fn update(&mut self, detector_events: Vec<DetectorEvent>, now: Instant) -> Vec<Event> {
        use super::detector::Event::*;
        let _span = tracing::debug_span!("lifecycle_update", now = ?now).entered();
        trace!(input_events = ?detector_events,"detector input events");
        let mut lifecycle_events = Vec::new();
        for detector_event in &detector_events {
            match detector_event {
                Router { key, lifetime, .. } => {
                    if lifetime.is_zero() {
                        self.router_store.remove(key);
                        self.dns_servers_store.remove(key);
                        self.dns_domains_store.remove(key);
                        self.prefix_store.remove(key);
                        self.soft_prefix_store.remove(key);
                        lifecycle_events.push(Event::RouterExpiry { key: *key });
                    } else {
                        self.router_store.insert(*key, now + *lifetime);
                    }
                }
                DnsServers(key, servers) => {
                    let v = servers
                        .iter()
                        .map(|s| LifecycleEntry::new(s.clone(), now + s.lifetime))
                        .collect();
                    self.dns_servers_store.insert(*key, v);
                    self.dns_servers_store.retain(|_, v| !v.is_empty());
                }
                DnsDomains(key, domains) => {
                    let v = domains
                        .iter()
                        .map(|d| LifecycleEntry::new(d.clone(), now + d.lifetime))
                        .collect();
                    self.dns_domains_store.insert(*key, v);
                    self.dns_domains_store.retain(|_, v| !v.is_empty());
                }
                Prefix {
                    key,
                    prefix_info,
                    lifetime,
                    preferred_lifetime,
                } => {
                    if lifetime.is_zero() {
                        self.prefix_store
                            .entry(*key)
                            .and_modify(|v| v.retain(|e| e.data.prefix != prefix_info.prefix));
                        // it does not really matter if we delete other empty prefix lists.
                        self.prefix_store.retain(|_, v| !v.is_empty());
                    } else {
                        let entries = self.prefix_store.entry(*key).or_default();

                        if let Some(existing) = entries
                            .iter_mut()
                            .find(|e| e.data.prefix == prefix_info.prefix)
                        {
                            // Refresh existing lease
                            existing.expires_at = now + *lifetime;
                            existing.data = prefix_info.clone();
                        } else {
                            // New prefix lease
                            entries.push(LifecycleEntry::new(prefix_info.clone(), now + *lifetime));
                        }

                        if !preferred_lifetime.is_zero() && preferred_lifetime != lifetime {
                            self.soft_prefix_store.entry(*key).or_default().push(
                                LifecycleEntry::new(prefix_info.clone(), now + *preferred_lifetime),
                            );
                        }
                    }
                }
            }
            lifecycle_events.push(Event::from(detector_event.clone()));
        }
        trace!(output_events = ?lifecycle_events, "lifecycle events");
        lifecycle_events
    }

    /// Returns the next upcoming expiration timestamp, if any.
    ///
    /// This includes:
    /// - router lifetime expiry
    /// - DNS server lifetime expiry
    /// - DNS domain lifetime expiry
    /// - prefix valid-lifetime expiry
    /// - prefix preferred-lifetime (soft expiry)
    pub fn next_expiry(&self) -> Option<Instant> {
        let _span = tracing::debug_span!("lifecycle_next_expiry").entered();

        let mut next: Option<Instant> = None;

        // Helper: keep the minimum instant
        let mut consider = |instant: Instant| {
            next = Some(match next {
                Some(current) => current.min(instant),
                None => instant,
            });
        };

        // Router expiry (one per router)
        for &expiry in self.router_store.values() {
            consider(expiry);
        }

        // DNS servers expiry (multiple per router)
        for entries in self.dns_servers_store.values() {
            for entry in entries {
                consider(entry.expires_at);
            }
        }

        // DNS domains expiry
        for entries in self.dns_domains_store.values() {
            for entry in entries {
                consider(entry.expires_at);
            }
        }

        // Prefix valid-lifetime expiry
        for entries in self.prefix_store.values() {
            for entry in entries {
                consider(entry.expires_at);
            }
        }

        // Prefix preferred-lifetime (soft expiry)
        for entries in self.soft_prefix_store.values() {
            for entry in entries {
                consider(entry.expires_at);
            }
        }

        tracing::trace!(next_expiry = ?next);
        next
    }

    /// Expires all entries whose lifetime has elapsed.
    ///
    /// Expired entries are removed from internal state and an `Expiry`
    /// lifecycle event is emitted for each.
    pub fn expire(&mut self, now: Instant) -> (Vec<Event>, Vec<Event>) {
        let mut lifecycle_events = Vec::new();
        let mut soft_expiry_events = Vec::new();
        let mut expired_routers = Vec::new();
        let _span = tracing::debug_span!("lifecycle_expire", now = ?now).entered();
        self.router_store.retain(|key, expiry| {
            if *expiry <= now {
                lifecycle_events.push(Event::RouterExpiry { key: *key });
                expired_routers.push(*key);
                false
            } else {
                true
            }
        });

        // never manipulate maps inside retain, even on other maps.
        for key in expired_routers {
            self.dns_servers_store.remove(&key);
            self.dns_domains_store.remove(&key);
            self.prefix_store.remove(&key);
            self.soft_prefix_store.remove(&key);
        }

        for (key, dns) in &mut self.dns_servers_store {
            let before = dns.len();
            dns.retain(|e| e.expires_at > now);
            // this also sents out an empty list if no dns is left. this is intended.
            if before != dns.len() {
                let servers = dns.iter().map(|e| e.data.clone()).collect();
                lifecycle_events.push(Event::DnsServers { key: *key, servers });
            }
        }

        for (key, dns) in &mut self.dns_domains_store {
            let before = dns.len();
            dns.retain(|e| e.expires_at > now);
            // this also sents out an empty list if no dns is left. this is intended.
            if before != dns.len() {
                let domains = dns.iter().map(|e| e.data.clone()).collect();
                lifecycle_events.push(Event::DnsDomains { key: *key, domains });
            }
        }

        for (key, v) in self.prefix_store.iter_mut() {
            v.retain(|v| {
                if v.expires_at <= now {
                    lifecycle_events.push(Event::PrefixExpiry {
                        key: *key,
                        prefix_info: v.data.clone(),
                    });
                    false
                } else {
                    true
                }
            })
        }
        self.prefix_store.retain(|_, v| !v.is_empty());
        for (key, v) in self.soft_prefix_store.iter_mut() {
            v.retain(|v| {
                if v.expires_at <= now {
                    soft_expiry_events.push(Event::PrefixSoftExpiry {
                        key: *key,
                        prefix_info: v.data.clone(),
                    });
                    false
                } else {
                    true
                }
            })
        }
        self.soft_prefix_store.retain(|_, v| !v.is_empty());

        trace!(output_events = ?lifecycle_events, "lifecycle events");
        (lifecycle_events, soft_expiry_events)
    }
}

#[cfg(test)]
mod tests {
    use super::super::InterfaceIndex;
    use super::*;
    use anyhow::{Context, Result};
    use std::net::Ipv6Addr;
    use tokio::time::{Duration, Instant};

    fn if0() -> InterfaceIndex {
        0
    }

    fn ip(a: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, a)
    }

    fn router_event(lifetime: Duration) -> DetectorEvent {
        let key = Key::new(if0(), ip(1));
        DetectorEvent::Router {
            key,
            managed: true,
            other_config: false,
            lifetime,
        }
    }

    fn dns_servers(ips: &[Ipv6Addr], lifetime: Duration) -> DnsServers {
        DnsServers {
            servers: ips.to_vec(),
            lifetime,
        }
    }

    fn prefix(prefix: Ipv6Addr, len: u8) -> PrefixInfo {
        PrefixInfo {
            prefix,
            prefix_len: len,
        }
    }

    #[test]
    fn key_ifindex_extraction() -> Result<()> {
        let key = Key::new(if0(), ip(1));
        anyhow::ensure!(key.ifindex == if0());
        Ok(())
    }

    #[test]
    fn update_inserts_and_emits_event() -> Result<()> {
        let mut lc = Lifecycle::default();
        let now = Instant::now();

        let events = lc.update(vec![router_event(Duration::from_secs(10))], now);

        anyhow::ensure!(events.len() == 1);
        match &events[0] {
            Event::Router { managed, .. } => anyhow::ensure!(*managed),
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        anyhow::ensure!(lc.router_store.len() == 1);
        Ok(())
    }

    #[test]
    fn update_refreshes_expiry() -> Result<()> {
        let mut lc = Lifecycle::default();
        let now = Instant::now();

        let ev = router_event(Duration::from_secs(10));
        lc.update(vec![ev.clone()], now);

        let first_expiry = *lc.router_store.values().next().context("missing entry")?;

        lc.update(vec![ev], now + Duration::from_secs(5));

        let refreshed_expiry = *lc.router_store.values().next().context("missing entry")?;

        anyhow::ensure!(refreshed_expiry > first_expiry);
        Ok(())
    }

    #[test]
    fn expire_emits_expiry_event() -> Result<()> {
        let mut lc = Lifecycle::default();
        let now = Instant::now();

        lc.update(vec![router_event(Duration::from_secs(1))], now);

        let events = lc.expire(now + Duration::from_secs(2));

        anyhow::ensure!(events.0.len() == 1);
        match &events.0[0] {
            Event::RouterExpiry { .. } => {}
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        anyhow::ensure!(lc.router_store.is_empty());
        Ok(())
    }

    #[test]
    fn no_expiry_before_deadline() -> Result<()> {
        let mut lc = Lifecycle::default();
        let now = Instant::now();

        lc.update(vec![router_event(Duration::from_secs(10))], now);

        let events = lc.expire(now + Duration::from_secs(5));
        anyhow::ensure!(events.0.is_empty());
        anyhow::ensure!(!lc.router_store.is_empty());
        Ok(())
    }

    #[test]
    fn prefix_insert_creates_single_lease() {
        let mut lc = Lifecycle::default();
        let now = Instant::now();
        let key = Key::new(if0(), ip(1));

        let events = lc.update(
            vec![DetectorEvent::Prefix {
                key,
                prefix_info: prefix(ip(10), 64),
                lifetime: Duration::from_secs(30),
                preferred_lifetime: Duration::ZERO,
            }],
            now,
        );

        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], Event::Prefix { .. }));

        let entries = &lc.prefix_store[&key];
        assert_eq!(entries.len(), 1);
        assert!(entries[0].expires_at > now);
    }

    #[test]
    fn prefix_refresh_replaces_existing_lease() {
        let mut lc = Lifecycle::default();
        let key = Key::new(if0(), ip(1));
        let now = Instant::now();

        lc.update(
            vec![DetectorEvent::Prefix {
                key,
                prefix_info: prefix(ip(10), 64),
                lifetime: Duration::from_secs(30),
                preferred_lifetime: Duration::ZERO,
            }],
            now,
        );

        lc.update(
            vec![DetectorEvent::Prefix {
                key,
                prefix_info: prefix(ip(10), 64),
                lifetime: Duration::from_secs(60),
                preferred_lifetime: Duration::ZERO,
            }],
            now + Duration::from_secs(10),
        );

        let entries = &lc.prefix_store[&key];
        assert_eq!(entries.len(), 1);
        assert!(entries[0].expires_at > now + Duration::from_secs(40));
    }

    #[test]
    fn prefix_expiry_removes_only_target() {
        let mut lc = Lifecycle::default();
        let now = Instant::now();
        let key = Key::new(if0(), ip(1));

        lc.update(
            vec![
                DetectorEvent::Prefix {
                    key,
                    prefix_info: prefix(ip(10), 64),
                    lifetime: Duration::from_secs(5),
                    preferred_lifetime: Duration::ZERO,
                },
                DetectorEvent::Prefix {
                    key,
                    prefix_info: prefix(ip(20), 56),
                    lifetime: Duration::from_secs(30),
                    preferred_lifetime: Duration::ZERO,
                },
            ],
            now,
        );

        let (events, _) = lc.expire(now + Duration::from_secs(10));

        assert!(events.iter().any(|e| matches!(
            e,
            Event::PrefixExpiry { prefix_info, .. } if prefix_info.prefix == ip(10)
        )));

        let remaining = &lc.prefix_store[&key];
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].data.prefix, ip(20));
    }

    #[test]
    fn prefix_soft_expiry_does_not_remove_lease() {
        let mut lc = Lifecycle::default();
        let now = Instant::now();
        let key = Key::new(if0(), ip(1));

        lc.update(
            vec![DetectorEvent::Prefix {
                key,
                prefix_info: prefix(ip(10), 64),
                lifetime: Duration::from_secs(30),
                preferred_lifetime: Duration::from_secs(10),
            }],
            now,
        );

        let (_, soft_events) = lc.expire(now + Duration::from_secs(15));

        assert!(soft_events.iter().any(|e| matches!(
            e,
            Event::PrefixSoftExpiry { prefix_info, .. }
            if prefix_info.prefix == ip(10)
        )));

        assert_eq!(lc.prefix_store[&key].len(), 1);
    }

    #[test]
    fn dns_expiry_emits_state_update() {
        let mut lc = Lifecycle::default();
        let key = Key::new(if0(), ip(1));
        let now = Instant::now();

        lc.update(
            vec![DetectorEvent::DnsServers(
                key,
                vec![
                    dns_servers(&[ip(10)], Duration::from_secs(5)),
                    dns_servers(&[ip(20)], Duration::from_secs(30)),
                ],
            )],
            now,
        );

        let (events, _) = lc.expire(now + Duration::from_secs(10));

        match &events[0] {
            Event::DnsServers { servers, .. } => {
                assert_eq!(servers.len(), 1);
                assert_eq!(servers[0].servers, vec![ip(20)]);
            }
            _ => panic!("expected DNS state update"),
        }
    }
}
