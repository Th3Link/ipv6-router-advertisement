//! Aggregation and reconciliation layer between lifecycle events and the FSM.
//!
//! This module maintains a source-of-truth state derived from lifecycle events
//! (routers, DNS servers, and DNS domains) and aggregates them per interface.
//!
//! The aggregation produces a *desired state* for Router Advertisements (RA).
//! Differences between old and new aggregated state are converted into coarse-
//! grained FSM events which always carry the **full current state** of the
//! affected RA section.
//!
//! Design principles:
//! - Aggregation is deterministic and idempotent.
//! - Ownership is used deliberately during diffing to avoid unnecessary cloning.
//! - No incremental diffs: if something changes, the full section is resent.
//! - The FSM does not need to understand lifecycle events.

use super::detector::Key;
use super::lifecycle::Event as LifecycleEvent;
use super::Lifetime;
use super::{Event, InterfaceIndex, PrefixInfo};
use std::hash::Hash;
use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
};
use tracing::{debug, trace};

/// Aggregated router configuration for an interface.
///
/// The effective router state is computed by OR-combining all active router
/// sources belonging to the same interface.
#[derive(PartialEq, Clone)]
pub struct Router {
    /// Indicates whether the Managed (M) flag is set in RA.
    pub managed: bool,
    /// Indicates whether the Other Configuration (O) flag is set in RA.
    pub other_config: bool,
}

/// Fully aggregated Router Advertisement state for a single interface.
///
/// This structure represents the *desired state* that should be applied
/// to the RA sender for the given interface.
#[derive(Default, PartialEq)]
pub struct Aggregate {
    /// Aggregated router configuration.
    ///
    /// `None` means that no active router is present and a RouterDown
    /// will be sent on change.
    pub router: Option<Router>,
    /// Aggregated and deduplicated DNS server list. Kind-of preserves order.
    pub dns_servers: Vec<Ipv6Addr>,
    /// Aggregated and deduplicated DNS search domains.
    pub domains: Vec<String>,
    /// Aggregated and deduplicated DNS search domains.
    pub prefixes: Vec<PrefixInfo>,
}

impl Aggregate {
    /// Applies a single source data item to the aggregate.
    ///
    /// This method encodes all aggregation rules:
    /// - Router flags are OR-combined.
    /// - DNS servers and domains are expanded and deduplicated.
    ///
    /// No ordering guarantees are implied beyond "first seen wins".
    pub fn apply_router(&mut self, router: &Router) {
        let r = self.router.get_or_insert(Router {
            managed: false,
            other_config: false,
        });
        r.managed |= router.managed;
        r.other_config |= router.other_config;
    }

    pub fn apply_dns_servers(&mut self, dns_servers: &[Ipv6Addr]) {
        extend_dedup(&mut self.dns_servers, dns_servers.iter().copied());
    }

    pub fn apply_domains(&mut self, domains: &[String]) {
        extend_dedup(&mut self.domains, domains.iter().cloned());
    }

    pub fn apply_prefixes(&mut self, prefixes: &[PrefixInfo]) {
        extend_dedup(&mut self.prefixes, prefixes.iter().cloned());
    }
}

/// Stateful aggregator for lifecycle-derived RA data.
///
/// The aggregator keeps all currently active source entries and can
/// derive the aggregated per-interface state from them.
#[derive(Default)]
pub struct Aggregator {
    /// All active source entries, keyed by their lifecycle identity.
    routers: HashMap<Key, Router>,
    dns_servers: HashMap<Key, Vec<Ipv6Addr>>,
    domains: HashMap<Key, Vec<String>>,
    prefixes: HashMap<Key, Vec<PrefixInfo>>,
}

impl Aggregator {
    /// Processes lifecycle events and returns events describing
    /// the required RA updates.
    ///
    /// The method performs the following steps:
    /// 1. Compute the aggregated state before applying events.
    /// 2. Update the internal source state using lifecycle events.
    /// 3. Compute the new aggregated state.
    /// 4. Diff both states and emit events for changed sections.
    pub fn process(&mut self, lifecycle_events: Vec<LifecycleEvent>) -> Vec<Event> {
        let _span =
            tracing::debug_span!("aggregator_process", input_events = lifecycle_events.len())
                .entered();
        trace!(input_events = ?lifecycle_events,"aggregator input events");
        let old_aggregate = self.aggregate();
        self.update(lifecycle_events);
        let new_aggregate = self.aggregate();
        let diffs = diff_aggregate_parts(old_aggregate, new_aggregate);
        debug!(output_events = ?diffs.len(), "aggregator produced events");

        trace!(output = ?diffs,"aggregator detailed diff");
        diffs
    }

    /// Updates the internal source state using lifecycle events.
    ///
    /// Events either insert, update, or remove source contributions.
    ///
    /// This method performs no aggregation; it only maintains the
    /// current set of active sources.
    fn update(&mut self, lifecycle_events: Vec<LifecycleEvent>) {
        for lifecycle_event in lifecycle_events {
            match lifecycle_event {
                LifecycleEvent::Router {
                    key,
                    managed,
                    other_config,
                } => {
                    self.routers.insert(
                        key,
                        Router {
                            managed,
                            other_config,
                        },
                    );
                }
                LifecycleEvent::DnsServers { key, servers } => {
                    self.dns_servers.insert(
                        key,
                        flatten_sorted_dedup_by_lifetime(&servers, |s| s.servers.clone()),
                    );
                }
                LifecycleEvent::DnsDomains { key, domains } => {
                    self.domains.insert(
                        key,
                        flatten_sorted_dedup_by_lifetime(&domains, |d| d.domains.clone()),
                    );
                }
                LifecycleEvent::Prefix { key, prefix_info } => {
                    // Insert a new empty Prefix vector if this key does not exist yet.
                    // We explicitly match on the stored data to ensure type correctness.
                    let prefixes = self.prefixes.entry(key).or_default();

                    // Prefix identity is defined by the prefix address itself.
                    // If a prefix with the same address already exists, update it.
                    if let Some(existing) =
                        prefixes.iter_mut().find(|p| p.prefix == prefix_info.prefix)
                    {
                        // Replace the existing entry completely to reflect the
                        // new advertised prefix information (e.g., prefix length).
                        *existing = prefix_info;
                    } else {
                        // Otherwise, insert this prefix as a new entry.
                        prefixes.push(prefix_info);
                    }
                }
                LifecycleEvent::RouterExpiry { key } => {
                    self.routers.remove(&key);
                    self.dns_servers.remove(&key);
                    self.domains.remove(&key);
                    self.prefixes.remove(&key);
                }

                LifecycleEvent::PrefixExpiry { key, prefix_info } => {
                    // Look up the existing prefix list for this router/interface.
                    // If the key does not exist, the expiry event is stale and can
                    // be safely ignored.
                    let Some(prefixes) = self.prefixes.get_mut(&key) else {
                        return;
                    };
                    // Remove the expired prefix identified by its address.
                    prefixes.retain(|p| p.prefix != prefix_info.prefix);

                    // If the last prefix for this router was removed, clean up the key
                    // entirely to keep the state minimal and consistent.
                    if prefixes.is_empty() {
                        self.prefixes.remove(&key);
                    }
                }
                LifecycleEvent::PrefixSoftExpiry { key: _, .. } => {}
            }
        }
    }

    /// Computes the aggregated RA state for all interfaces.
    ///
    /// This method is deterministic and free of side effects.
    /// It derives aggregation purely from the current source stat
    fn aggregate(&self) -> HashMap<InterfaceIndex, Aggregate> {
        let mut result: HashMap<InterfaceIndex, Aggregate> = HashMap::new();

        for (key, data) in &self.routers {
            result.entry(key.ifindex).or_default().apply_router(data);
        }
        for (key, data) in &self.dns_servers {
            result
                .entry(key.ifindex)
                .or_default()
                .apply_dns_servers(data);
        }
        for (key, data) in &self.domains {
            result.entry(key.ifindex).or_default().apply_domains(data);
        }
        for (key, data) in &self.prefixes {
            result.entry(key.ifindex).or_default().apply_prefixes(data);
        }
        result
    }

    pub fn get_prefixes(&self, key: &Key) -> Option<Vec<PrefixInfo>> {
        self.prefixes.get(key).cloned()
    }
}

/// Computes FSM events by comparing two aggregated RA states.
///
/// For each interface, the function compares router state, DNS servers,
/// and DNS domains independently.
///
/// If a section differs, an FSM event carrying the **full current state**
/// of that section is emitted.
///
/// ## Ownership rationale
///
/// This function deliberately takes ownership of the aggregated maps
/// instead of borrowing them.
///
/// During diffing, DNS server lists and domain lists must be moved
/// into FSM events. Taking ownership allows moving these values directly
/// without cloning, avoiding unnecessary allocations.
///
/// This is safe because the aggregates are not used after diffing.
fn diff_aggregate_parts(
    mut old: HashMap<InterfaceIndex, Aggregate>,
    mut new: HashMap<InterfaceIndex, Aggregate>,
) -> Vec<Event> {
    let mut updates = Vec::new();

    let ifindices: HashSet<_> = old.keys().chain(new.keys()).copied().collect();

    for ifindex in ifindices {
        let old_agg = old.remove(&ifindex);
        let new_agg = new.remove(&ifindex);

        let old_agg = old_agg.unwrap_or(Aggregate {
            router: None,
            dns_servers: Vec::new(),
            domains: Vec::new(),
            prefixes: Vec::new(),
        });

        let new_agg = new_agg.unwrap_or(Aggregate {
            router: None,
            dns_servers: Vec::new(),
            domains: Vec::new(),
            prefixes: Vec::new(),
        });

        // Router
        if old_agg.router != new_agg.router {
            match &new_agg.router {
                Some(r) => updates.push(Event::RouterUpdate {
                    ifindex,
                    managed: r.managed,
                    other_config: r.other_config,
                }),
                None => updates.push(Event::RouterDown { ifindex }),
            }
        }

        // DNS Servers and Domains
        let dns_changed =
            old_agg.dns_servers != new_agg.dns_servers || old_agg.domains != new_agg.domains;
        if dns_changed {
            updates.push(Event::RaDns {
                ifindex,
                servers: new_agg.dns_servers,
                domains: new_agg.domains,
            });
        }

        // Prefixes
        let prefixes_changed = old_agg.prefixes != new_agg.prefixes;
        if prefixes_changed {
            updates.push(Event::RaPrefix {
                ifindex,
                prefixes: new_agg.prefixes,
            });
        }
    }
    updates
}

/// Extends a vector with elements from an iterator while preserving
/// first-seen order and removing duplicates.
///
/// Elements already present in `target` are not re-added.
///
/// This function is used during aggregation to merge DNS data
/// from multiple independent sources.
fn extend_dedup<T>(target: &mut Vec<T>, src: impl IntoIterator<Item = T>)
where
    T: Eq + Hash, // semantically required for deduplication
    T: Clone,     // required for ownership and data movement
{
    let mut seen: HashSet<T> = target.iter().cloned().collect();

    for item in src {
        if seen.insert(item.clone()) {
            target.push(item);
        }
    }
}

/// Flattens, sorts, and deduplicates items by descending lifetime.
///
/// This helper is primarily intended for DNS aggregation, where multiple
/// lifetime groups (e.g. multiple RDNSS or DNSSL options) may be present
/// for a single router.
///
/// ## Semantics
///
/// - Items are first **sorted by lifetime in descending order**
///   (longest lifetime first).
/// - Items are then **flattened** using the provided extraction function.
/// - Duplicate items are **removed**, preserving the first occurrence.
/// - As a result, items originating from longer-lived sources take
///   precedence over shorter-lived ones.
///
/// This matches the desired DNS behavior:
/// - Lifetimes influence *priority*, not aggregation membership.
/// - The aggregated view is deterministic and stable.
/// - No time-based decisions are made here; expiry is handled elsewhere.
///
/// ## Type Parameters
///
/// - `I`: Input item type. Must implement `Lifetime`.
/// - `O`: Output item type. Must be hashable for deduplication.
/// - `F`: Function extracting an iterable of output items from an input item.
fn flatten_sorted_dedup_by_lifetime<I, O, F, It>(input: &[I], extract: F) -> Vec<O>
where
    I: Lifetime + Clone,
    O: Eq + Hash + Clone,
    F: Fn(&I) -> It,
    It: IntoIterator<Item = O>,
{
    let mut tmp = input.to_vec();

    // longest lifetime first
    tmp.sort_by_key(|s| std::cmp::Reverse(s.lifetime()));

    let mut seen = HashSet::new();

    tmp.into_iter()
        .flat_map(|s| extract(&s))
        .filter(|item| seen.insert(item.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::detector::{DnsDomains, DnsServers};
    use super::*;
    use anyhow::{Context, Result};
    use std::net::Ipv6Addr;
    use tokio::time::Duration;

    fn if0() -> InterfaceIndex {
        InterfaceIndex::from(0u32)
    }

    fn if1() -> InterfaceIndex {
        InterfaceIndex::from(1u32)
    }

    fn ip(a: u8) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, a as u16)
    }

    #[test]
    fn extend_dedup_adds_only_new_items() -> Result<()> {
        let mut v = vec![1, 2, 3];
        extend_dedup(&mut v, vec![3, 4, 2, 5]);

        anyhow::ensure!(v == vec![1, 2, 3, 4, 5]);
        Ok(())
    }

    #[test]
    fn aggregate_apply_router_or_combines_flags() -> Result<()> {
        let mut agg = Aggregate::default();

        agg.apply_router(&Router {
            managed: true,
            other_config: false,
        });
        agg.apply_router(&Router {
            managed: false,
            other_config: true,
        });

        let router = agg.router.context("missing router")?;
        anyhow::ensure!(router.managed);
        anyhow::ensure!(router.other_config);
        Ok(())
    }

    #[test]
    fn aggregate_apply_dns_expands_and_dedups() -> Result<()> {
        let mut agg = Aggregate::default();

        agg.apply_dns_servers(&[ip(1), ip(2)]);
        agg.apply_dns_servers(&[ip(2), ip(3)]);

        anyhow::ensure!(agg.dns_servers == vec![ip(1), ip(2), ip(3)]);
        Ok(())
    }

    #[test]
    fn aggregate_groups_by_interface() -> Result<()> {
        let mut a = Aggregator::default();

        a.routers.insert(
            Key::new(if0(), 1.into()),
            Router {
                managed: true,
                other_config: false,
            },
        );
        a.routers.insert(
            Key::new(if1(), 1.into()),
            Router {
                managed: false,
                other_config: true,
            },
        );

        let result = a.aggregate();

        let r0 = result
            .get(&if0())
            .context("missing if0 aggregate")?
            .router
            .as_ref()
            .context("missing router if0")?;

        let r1 = result
            .get(&if1())
            .context("missing if1 aggregate")?
            .router
            .as_ref()
            .context("missing router if1")?;

        anyhow::ensure!(r0.managed && !r0.other_config);
        anyhow::ensure!(!r1.managed && r1.other_config);
        Ok(())
    }

    #[test]
    fn process_emits_router_up() -> Result<()> {
        let mut a = Aggregator::default();

        let events = vec![LifecycleEvent::Router {
            key: Key::new(if0(), 1.into()),
            managed: true,
            other_config: false,
        }];

        let updates = a.process(events);

        anyhow::ensure!(updates.len() == 1);

        match &updates[0] {
            Event::RouterUpdate {
                ifindex: _,
                managed,
                other_config,
            } => {
                anyhow::ensure!(*managed);
                anyhow::ensure!(!*other_config);
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn process_emits_router_down() -> Result<()> {
        let mut a = Aggregator::default();

        a.process(vec![LifecycleEvent::Router {
            key: Key::new(if0(), 1.into()),
            managed: true,
            other_config: false,
        }]);

        let updates = a.process(vec![LifecycleEvent::RouterExpiry {
            key: Key::new(if0(), 1.into()),
        }]);

        anyhow::ensure!(updates.len() == 1);

        match updates[0] {
            Event::RouterDown { ifindex: _ } => {}
            ref ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn process_emits_router_down_and_others() -> Result<()> {
        let mut a = Aggregator::default();
        let key = Key::new(if0(), 1.into());
        let updates = a.process(vec![
            LifecycleEvent::Router {
                key,
                managed: true,
                other_config: false,
            },
            LifecycleEvent::DnsServers {
                key,
                servers: vec![DnsServers {
                    servers: vec![Ipv6Addr::from(1)],
                    lifetime: Duration::from_secs(1),
                }],
            },
            LifecycleEvent::Prefix {
                key,
                prefix_info: PrefixInfo {
                    prefix: Ipv6Addr::from(1),
                    prefix_len: 64,
                },
            },
        ]);

        anyhow::ensure!(updates.len() == 3, "updates: {updates:?}");

        let updates = a.process(vec![LifecycleEvent::RouterExpiry { key }]);

        anyhow::ensure!(updates.len() == 3, "updates: {updates:?}");

        match updates[0] {
            Event::RouterDown { ifindex: _ } => {}
            ref ev => anyhow::bail!("unexpected event: {:?}", ev),
        }
        match updates[1] {
            Event::RaDns { ifindex: _, .. } => {}
            ref ev => anyhow::bail!("unexpected event: {:?}", ev),
        }
        match updates[2] {
            Event::RaPrefix { ifindex: _, .. } => {}
            ref ev => anyhow::bail!("unexpected event: {:?}", ev),
        }
        Ok(())
    }

    #[test]
    fn process_emits_dns_on_change() -> Result<()> {
        let mut a = Aggregator::default();

        a.process(vec![LifecycleEvent::DnsServers {
            key: Key::new(if0(), 1.into()),
            servers: vec![DnsServers {
                servers: vec![ip(1)],
                lifetime: Duration::from_secs(1),
            }],
        }]);

        let updates = a.process(vec![
            LifecycleEvent::DnsServers {
                key: Key::new(if0(), 2.into()),
                servers: vec![DnsServers {
                    servers: vec![ip(2)],
                    lifetime: Duration::from_secs(1),
                }],
            },
            LifecycleEvent::DnsDomains {
                key: Key::new(if0(), 1.into()),
                domains: vec![DnsDomains {
                    domains: vec!["example.com".into()],
                    lifetime: Duration::from_secs(1),
                }],
            },
        ]);

        anyhow::ensure!(updates.len() == 1);

        match &updates[0] {
            Event::RaDns {
                ifindex: _,
                servers,
                domains,
            } => {
                let mut servers = servers.clone();
                servers.sort();
                anyhow::ensure!(servers == vec![ip(1), ip(2)]);
                anyhow::ensure!(domains == &vec!["example.com"]);
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn process_does_not_emit_when_aggregate_is_identical() -> Result<()> {
        let mut a = Aggregator::default();

        let e = LifecycleEvent::Router {
            key: Key::new(if0(), 1.into()),
            managed: true,
            other_config: false,
        };

        a.process(vec![e.clone()]);
        let updates = a.process(vec![e]);

        anyhow::ensure!(updates.is_empty());
        Ok(())
    }

    #[test]
    fn diff_start_condition_emits_all_sections() -> Result<()> {
        let old = HashMap::new();

        let mut new = HashMap::new();
        new.insert(
            if0(),
            Aggregate {
                router: Some(Router {
                    managed: true,
                    other_config: false,
                }),
                dns_servers: vec![ip(1)],
                domains: vec!["example.com".into()],
                prefixes: vec![],
            },
        );

        let updates = diff_aggregate_parts(old, new);

        anyhow::ensure!(updates.len() == 2);

        let mut saw_router = false;
        let mut saw_dns = false;

        for ev in updates {
            match ev {
                Event::RouterUpdate {
                    ifindex: _,
                    managed,
                    other_config,
                } => {
                    anyhow::ensure!(managed);
                    anyhow::ensure!(!other_config);
                    saw_router = true;
                }
                Event::RaDns {
                    ifindex: _,
                    servers,
                    domains,
                } => {
                    anyhow::ensure!(servers == vec![ip(1)]);
                    anyhow::ensure!(domains == vec!["example.com"]);
                    saw_dns = true;
                }
                other => anyhow::bail!("unexpected event: {:?}", other),
            }
        }

        anyhow::ensure!(saw_router && saw_dns);
        Ok(())
    }

    #[test]
    fn diff_router_down_emits_router_down_only() -> Result<()> {
        let mut old = HashMap::new();
        old.insert(
            if0(),
            Aggregate {
                router: Some(Router {
                    managed: true,
                    other_config: true,
                }),
                dns_servers: vec![ip(1)],
                domains: vec![],
                prefixes: vec![],
            },
        );

        let mut new = HashMap::new();
        new.insert(
            if0(),
            Aggregate {
                router: None,
                dns_servers: vec![ip(1)],
                domains: vec![],
                prefixes: vec![],
            },
        );

        let updates = diff_aggregate_parts(old, new);

        anyhow::ensure!(updates.len() == 1);

        match updates[0] {
            Event::RouterDown { ifindex: _ } => {}
            ref ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn diff_router_and_dns_change_emits_both() -> Result<()> {
        let mut old = HashMap::new();
        old.insert(
            if0(),
            Aggregate {
                router: Some(Router {
                    managed: false,
                    other_config: false,
                }),
                dns_servers: vec![ip(1)],
                domains: vec!["old.example".into()],
                prefixes: vec![],
            },
        );

        let mut new = HashMap::new();
        new.insert(
            if0(),
            Aggregate {
                router: Some(Router {
                    managed: true,
                    other_config: true,
                }),
                dns_servers: vec![ip(2)],
                domains: vec!["new.example".into()],
                prefixes: vec![],
            },
        );

        let updates = diff_aggregate_parts(old, new);

        anyhow::ensure!(updates.len() == 2);

        let mut saw_router = false;
        let mut saw_dns = false;

        for ev in updates {
            match ev {
                Event::RouterUpdate {
                    ifindex: _,
                    managed,
                    other_config,
                } => {
                    anyhow::ensure!(managed);
                    anyhow::ensure!(other_config);
                    saw_router = true;
                }
                Event::RaDns {
                    ifindex: _,
                    servers,
                    domains,
                } => {
                    anyhow::ensure!(servers == vec![ip(2)]);
                    anyhow::ensure!(domains == vec!["new.example"]);
                    saw_dns = true;
                }
                other => anyhow::bail!("unexpected event: {:?}", other),
            }
        }

        anyhow::ensure!(saw_router && saw_dns);
        Ok(())
    }

    #[test]
    fn process_emits_prefix_on_insert() -> Result<()> {
        let mut a = Aggregator::default();
        let key = Key::new(if0(), 1.into());

        let updates = a.process(vec![LifecycleEvent::Prefix {
            key,
            prefix_info: PrefixInfo {
                prefix: ip(0),
                prefix_len: 64,
            },
        }]);

        anyhow::ensure!(updates.len() == 1);

        match &updates[0] {
            Event::RaPrefix { ifindex, prefixes } => {
                anyhow::ensure!(*ifindex == if0());
                anyhow::ensure!(prefixes.len() == 1);
                anyhow::ensure!(prefixes[0].prefix_len == 64);
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn prefix_update_replaces_existing_prefix() -> Result<()> {
        let mut a = Aggregator::default();
        let key = Key::new(if0(), 1.into());

        a.process(vec![LifecycleEvent::Prefix {
            key,
            prefix_info: PrefixInfo {
                prefix: ip(0),
                prefix_len: 64,
            },
        }]);

        let updates = a.process(vec![LifecycleEvent::Prefix {
            key,
            prefix_info: PrefixInfo {
                prefix: ip(0),
                prefix_len: 56,
            },
        }]);

        anyhow::ensure!(updates.len() == 1);

        match &updates[0] {
            Event::RaPrefix { prefixes, .. } => {
                anyhow::ensure!(prefixes.len() == 1);
                anyhow::ensure!(prefixes[0].prefix_len == 56);
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn multiple_prefixes_from_same_router() -> Result<()> {
        let mut a = Aggregator::default();
        let key = Key::new(if0(), 1.into());

        let updates = a.process(vec![
            LifecycleEvent::Prefix {
                key,
                prefix_info: PrefixInfo {
                    prefix: ip(0),
                    prefix_len: 64,
                },
            },
            LifecycleEvent::Prefix {
                key,
                prefix_info: PrefixInfo {
                    prefix: ip(1),
                    prefix_len: 56,
                },
            },
        ]);

        anyhow::ensure!(updates.len() == 1);

        match &updates[0] {
            Event::RaPrefix { prefixes, .. } => {
                anyhow::ensure!(prefixes.len() == 2);
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn prefix_expiry_removes_only_one_prefix() -> Result<()> {
        let mut a = Aggregator::default();
        let key = Key::new(if0(), 1.into());

        a.process(vec![
            LifecycleEvent::Prefix {
                key,
                prefix_info: PrefixInfo {
                    prefix: ip(0),
                    prefix_len: 64,
                },
            },
            LifecycleEvent::Prefix {
                key,
                prefix_info: PrefixInfo {
                    prefix: ip(1),
                    prefix_len: 56,
                },
            },
        ]);

        let updates = a.process(vec![LifecycleEvent::PrefixExpiry {
            key,
            prefix_info: PrefixInfo {
                prefix: ip(0),
                prefix_len: 64,
            },
        }]);

        anyhow::ensure!(updates.len() == 1);

        match &updates[0] {
            Event::RaPrefix { prefixes, .. } => {
                anyhow::ensure!(prefixes.len() == 1);
                anyhow::ensure!(prefixes[0].prefix == ip(1));
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn last_prefix_expired_emits_empty_prefix_state() -> Result<()> {
        let mut a = Aggregator::default();
        let key = Key::new(if0(), 1.into());

        a.process(vec![LifecycleEvent::Prefix {
            key,
            prefix_info: PrefixInfo {
                prefix: ip(0),
                prefix_len: 64,
            },
        }]);

        let updates = a.process(vec![LifecycleEvent::PrefixExpiry {
            key,
            prefix_info: PrefixInfo {
                prefix: ip(0),
                prefix_len: 64,
            },
        }]);

        anyhow::ensure!(updates.len() == 1);

        match &updates[0] {
            Event::RaPrefix { prefixes, .. } => {
                anyhow::ensure!(prefixes.is_empty());
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn prefix_noop_does_not_emit() -> Result<()> {
        let mut a = Aggregator::default();
        let key = Key::new(if0(), 1.into());

        let ev = LifecycleEvent::Prefix {
            key,
            prefix_info: PrefixInfo {
                prefix: ip(0),
                prefix_len: 64,
            },
        };

        a.process(vec![ev.clone()]);
        let updates = a.process(vec![ev]);

        anyhow::ensure!(updates.is_empty());
        Ok(())
    }
}

#[cfg(test)]
mod flatten_sorted_dedup_by_lifetime_tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::time::Duration;

    #[derive(Clone, Debug)]
    struct Group {
        items: Vec<Ipv6Addr>,
        lifetime: Duration,
    }

    impl Lifetime for Group {
        fn lifetime(&self) -> Duration {
            self.lifetime
        }
    }

    fn ip(v: u128) -> Ipv6Addr {
        Ipv6Addr::from(v)
    }

    #[test]
    fn sorts_by_lifetime_descending() {
        let a = Group {
            items: vec![ip(1)],
            lifetime: Duration::from_secs(10),
        };
        let b = Group {
            items: vec![ip(2)],
            lifetime: Duration::from_secs(20),
        };

        let out = flatten_sorted_dedup_by_lifetime(&[a, b], |g| g.items.clone());

        assert_eq!(out, vec![ip(2), ip(1)]);
    }

    #[test]
    fn removes_duplicates_preserving_first_seen() {
        let short = Group {
            items: vec![ip(1), ip(2)],
            lifetime: Duration::from_secs(5),
        };
        let long = Group {
            items: vec![ip(1), ip(3)],
            lifetime: Duration::from_secs(10),
        };

        let out = flatten_sorted_dedup_by_lifetime(&[short, long], |g| g.items.clone());

        // ip(1) comes from `long` (longer lifetime), ip(2) is dropped,
        // ip(3) is appended.
        assert_eq!(out, vec![ip(1), ip(3), ip(2)]);
    }

    #[test]
    fn preserves_order_within_same_lifetime() {
        let a = Group {
            items: vec![ip(1), ip(2)],
            lifetime: Duration::from_secs(10),
        };
        let b = Group {
            items: vec![ip(3), ip(4)],
            lifetime: Duration::from_secs(10),
        };

        let out = flatten_sorted_dedup_by_lifetime(&[a.clone(), b.clone()], |g| g.items.clone());

        // Same lifetime → stable order as provided in input slice.
        assert_eq!(out, vec![ip(1), ip(2), ip(3), ip(4)]);
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let out: Vec<Ipv6Addr> = flatten_sorted_dedup_by_lifetime(&[], |g: &Group| g.items.clone());

        assert!(out.is_empty());
    }
}
