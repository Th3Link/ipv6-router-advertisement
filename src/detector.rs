//! Detector for Router Advertisement (RA) information.
//!
//! This module translates a parsed IPv6 Router Advertisement into
//! semantically meaningful events.
//!
//! The detector is deliberately stateless and performs no aggregation,
//! expiration, or policy decisions.
//!
//! Responsibilities:
//! - Decode RA content into domain-specific events.
//! - Preserve per-router separation of information.
//! - Attach lifetimes as specified by the RA.
//!
//! Higher layers (lifecycle, aggregation, FSM) are responsible for
//! interpreting and combining these events.

use super::router_advertisement::RouterAdvertisement;
use super::Lifetime;
use super::{InterfaceIndex, PrefixInfo, RouterIp};
use std::net::Ipv6Addr;
use tokio::time::Duration;

/// Unique identity of a `(interface, router)` combination.
///
/// A `Key` identifies the *source* of router advertisement information.
/// It is stable across updates and expiries and used throughout detector,
/// lifecycle, and aggregation layers to associate data with its origin.
///
/// Semantics:
/// - `ifindex` identifies the network interface.
/// - `router_ip` identifies the advertising router.
///
/// The key does **not** encode the category of information (router, DNS,
/// prefix, etc.). That distinction is expressed by the event type itself.
///
/// Keys are intentionally lightweight and copyable.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct Key {
    /// Network interface on which the router advertisement was received.
    pub ifindex: InterfaceIndex,
    /// IPv6 address of the advertising router.
    ///
    /// This uniquely identifies the router on the link. It is kept private
    /// to prevent accidental use as an externally visible identifier.
    router_ip: RouterIp,
}

impl Key {
    /// Creates a new router identity key.
    pub fn new(ifindex: InterfaceIndex, router_ip: RouterIp) -> Self {
        Self { ifindex, router_ip }
    }
}

/// DNS server information advertised by a router.
///
/// This structure corresponds to a single RDNSS option as defined in
/// RFC 8106.
///
/// All DNS servers contained in this structure share the same lifetime.
/// If a router wishes to advertise servers with different lifetimes,
/// multiple `DnsServers` entries will be emitted.
#[derive(Debug, Clone)]
pub struct DnsServers {
    /// List of DNS servers provided by this router.
    pub servers: Vec<Ipv6Addr>,
    /// Lifetime of the DNS server information.
    pub lifetime: Duration,
}

impl Lifetime for DnsServers {
    /// Returns the lifetime of this DNS server group.
    ///
    /// All DNS servers contained in this structure share the same lifetime,
    /// as defined by the RDNSS option semantics.
    ///
    /// A lifetime of zero indicates an explicit withdrawal of previously
    /// advertised DNS server information.
    fn lifetime(&self) -> Duration {
        self.lifetime
    }
}

/// DNS search domain information advertised by a router.
///
/// This structure corresponds to a single DNSSL option as defined in
/// RFC 8106.
///
/// All domain names contained in this structure share the same lifetime.
/// Multiple `DnsDomains` entries may be present if different lifetimes
/// are required.
#[derive(Debug, Clone)]
pub struct DnsDomains {
    /// List of DNS servers provided by this router.
    pub domains: Vec<String>,
    /// Lifetime of the DNS domain information.
    pub lifetime: Duration,
}

impl Lifetime for DnsDomains {
    /// Returns the lifetime of this DNS server group.
    ///
    /// All DNS servers contained in this structure share the same lifetime,
    /// as defined by the RDNSS option semantics.
    ///
    /// A lifetime of zero indicates an explicit withdrawal of previously
    /// advertised DNS server information.
    fn lifetime(&self) -> Duration {
        self.lifetime
    }
}

/// Events produced by the Router Advertisement detector.
///
/// Each detector event represents information *observed* in a single
/// Router Advertisement (RA). Detector events describe what the router
/// announced, not whether the information is still valid or expired.
///
/// All events are scoped to a single router and interface, identified
/// by the associated `Key`.
///
/// Detector events are converted into lifecycle events, which then add
/// time semantics and expiration handling.
#[derive(Debug, Clone)]
pub enum Event {
    /// Router configuration update.
    ///
    /// Represents the Managed (M) and Other Configuration (O) flags
    /// as advertised by the router, together with the router lifetime.
    Router {
        /// Identity of the advertising router.
        key: Key,
        /// Indicates whether the Managed (M) flag is set.
        managed: bool,
        /// Indicates whether the Other Configuration (O) flag is set.
        other_config: bool,
        /// Lifetime of the router configuration.
        lifetime: Duration,
    },
    /// DNS server information contributed by a router.
    ///
    /// The vector contains all RDNSS options present in the RA.
    /// An empty vector explicitly withdraws previously advertised DNS
    /// server information for this router.
    DnsServers(Key, Vec<DnsServers>),
    /// DNS search domain information contributed by a router.
    ///
    /// The vector contains all DNSSL options present in the RA.
    /// An empty vector explicitly withdraws previously advertised DNS
    /// search domains for this router.
    DnsDomains(Key, Vec<DnsDomains>),
    /// Prefix information contributed by a router.
    ///
    /// Prefixes are lease-based and handled individually in later
    /// lifecycle processing.
    Prefix {
        /// Identity of the advertising router.
        key: Key,
        /// Prefix information (address and prefix length).
        prefix_info: PrefixInfo,
        /// Valid lifetime of the prefix.
        lifetime: Duration,
        /// Preferred lifetime of the prefix.
        preferred_lifetime: Duration,
    },
}

/// Helper for detecting multi-option RA fields with lifetime semantics.
///
/// This function is used to process RA options that:
/// - may appear multiple times in a single RA,
/// - carry a lifetime,
/// - and represent *state*, not incremental updates.
///
/// Semantics:
/// - If **any option** has a zero lifetime, all previous information of
///   this category is explicitly withdrawn for the router, and an update
///   with an empty vector is emitted.
/// - Otherwise, all options are collected and emitted together.
/// - If no options are present, no event is emitted.
///
/// This matches the replace semantics required for DNS options
/// (RDNSS/DNSSL).
fn detect_multi_option<T, O, G>(
    out: &mut Vec<Event>,
    key: Key,
    options: impl IntoIterator<Item = O>,
    map: G,
    emit_update: impl FnOnce(Key, Vec<T>) -> Event,
) where
    G: Fn(O) -> T,
    O: Lifetime,
{
    let mut items = Vec::new();
    for opt in options {
        if opt.lifetime().is_zero() {
            out.push(emit_update(key, vec![]));
            return;
        }
        items.push(map(opt));
    }
    if !items.is_empty() {
        out.push(emit_update(key, items));
    }
}

/// Detects router-related events from a Router Advertisement.
///
/// This function translates a single RA into zero or more detector events:
///
/// - A router update event is always emitted.
/// - DNS server and domain events are emitted only if present in the RA.
///
/// Semantic behavior:
/// - If a router has lifetime == 0, then all dns servers, domains and prefixes must
///   also be removed.
/// - DNS servers, TNS domains and prefixes are grouped per RA.
/// - If a lifetime == 0 DNS servers or domains comes in, all servers or domains
///   will be removed by sending the Remove event.
/// - Prefixes are a little different.
///
/// The detector performs no aggregation and preserves per-router identity.
pub fn detect(ra: RouterAdvertisement) -> Vec<Event> {
    // We know we have 1-3 events only. Lets avoid unnecessary allocations
    let mut v = Vec::with_capacity(3);
    let key = Key::new(ra.ifindex, ra.router_ip);
    v.push(Event::Router {
        key,
        managed: ra.managed,
        other_config: ra.other_config,
        lifetime: Duration::from_secs(ra.router_lifetime as u64),
    });
    if ra.router_lifetime == 0 {
        return v;
    }
    // Semantic notes:
    // DNS servers and domains are separate updateable.
    // Practical this will happen very rarely, but spec allows it.
    //
    // - lifetime == 0 => remove dns servers / domains.
    // - empty vec => not nice but ok. just
    // - entrys in there => replace the dns for this router

    detect_multi_option(
        &mut v,
        key,
        ra.rdnss,
        |o| DnsServers {
            servers: o.servers,
            lifetime: Duration::from_secs(o.lifetime as u64),
        },
        Event::DnsServers,
    );

    detect_multi_option(
        &mut v,
        key,
        ra.dnssl,
        |o| DnsDomains {
            domains: o.domains,
            lifetime: Duration::from_secs(o.lifetime as u64),
        },
        Event::DnsDomains,
    );

    for prefix in ra.prefixes {
        v.push(Event::Prefix {
            key,
            prefix_info: PrefixInfo {
                prefix: prefix.prefix,
                prefix_len: prefix.prefix_len,
            },
            lifetime: Duration::from_secs(prefix.valid_lifetime as u64),
            preferred_lifetime: Duration::from_secs(prefix.preferred_lifetime as u64),
        });
    }

    v
}

#[cfg(test)]
mod tests {
    use super::super::router_advertisement;
    use super::*;
    use anyhow::{Context, Result};
    use std::net::Ipv6Addr;
    use tokio::time::Duration;
    fn ip(a: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, a)
    }

    fn base_ra() -> RouterAdvertisement {
        RouterAdvertisement {
            ifindex: 1,
            router_ip: ip(1),
            managed: true,
            other_config: false,
            router_lifetime: 30,
            rdnss: vec![],
            dnssl: vec![],
            prefixes: vec![],
        }
    }

    #[test]
    fn detect_emits_router_update() -> Result<()> {
        let ra = base_ra();
        let events = detect(ra);

        anyhow::ensure!(events.len() == 1);

        match &events[0] {
            Event::Router {
                managed,
                other_config,
                lifetime,
                ..
            } => {
                anyhow::ensure!(*managed);
                anyhow::ensure!(!*other_config);
                anyhow::ensure!(*lifetime == Duration::from_secs(30));
            }
            ev => anyhow::bail!("unexpected event: {:?}", ev),
        }

        Ok(())
    }

    #[test]
    fn detect_emits_dns_servers_event() -> Result<()> {
        let mut ra = base_ra();
        ra.rdnss = vec![router_advertisement::Rdnss {
            servers: vec![ip(2), ip(3)],
            lifetime: 60,
        }];

        let events = detect(ra);

        let dns = events
            .iter()
            .find_map(|e| match e {
                Event::DnsServers(_key, servers) => Some(servers),
                _ => None,
            })
            .context("missing RouterDnsServers event")?;

        anyhow::ensure!(dns.len() == 1);
        anyhow::ensure!(dns[0].servers.len() == 2);
        anyhow::ensure!(dns[0].lifetime == Duration::from_secs(60));
        Ok(())
    }

    #[test]
    fn detect_emits_dns_domains_event() -> Result<()> {
        let mut ra = base_ra();
        ra.dnssl = vec![
            router_advertisement::Dnssl {
                domains: vec!["example.com".into()],
                lifetime: 120,
            },
            router_advertisement::Dnssl {
                domains: vec!["example1.com".into(), "example2.com".into()],
                lifetime: 100,
            },
        ];

        let events = detect(ra);

        let domains = events
            .iter()
            .find_map(|e| match e {
                Event::DnsDomains(_key, domains) => Some(domains),
                _ => None,
            })
            .context("missing RouterDnsDomains event")?;

        anyhow::ensure!(domains.len() == 2);
        anyhow::ensure!(domains[0].domains.len() == 1);
        anyhow::ensure!(domains[0].lifetime == Duration::from_secs(120));
        anyhow::ensure!(domains[0].domains == vec!["example.com".to_string()]);
        anyhow::ensure!(domains[1].domains.len() == 2);
        anyhow::ensure!(domains[1].lifetime == Duration::from_secs(100));
        anyhow::ensure!(
            domains[1].domains == vec!["example1.com".to_string(), "example2.com".to_string()]
        );
        Ok(())
    }

    #[test]
    fn detect_allows_empty_dns_lists() -> Result<()> {
        let mut ra = base_ra();
        ra.rdnss = vec![router_advertisement::Rdnss {
            servers: Vec::new(),
            lifetime: 10,
        }];

        let events = detect(ra);

        let dns = events
            .iter()
            .find_map(|e| match e {
                Event::DnsServers(_key, servers) => Some(servers),
                _ => None,
            })
            .context("missing RouterDnsServers event")?;

        anyhow::ensure!(dns.len() == 1);
        anyhow::ensure!(dns[0].servers.is_empty());
        Ok(())
    }

    #[test]
    fn detect_emits_single_prefix() -> Result<()> {
        let mut ra = base_ra();
        ra.prefixes = vec![router_advertisement::PrefixInfo {
            prefix: ip(10),
            prefix_len: 64,
            valid_lifetime: 100,
            preferred_lifetime: 50,
            autonomous: false,
            on_link: false,
        }];

        let events = detect(ra);

        let prefix = events
            .iter()
            .find_map(|e| match e {
                Event::Prefix {
                    prefix_info,
                    lifetime,
                    preferred_lifetime,
                    ..
                } => Some((prefix_info, lifetime, preferred_lifetime)),
                _ => None,
            })
            .context("missing Prefix event")?;

        anyhow::ensure!(prefix.0.prefix == ip(10));
        anyhow::ensure!(*prefix.1 == Duration::from_secs(100));
        anyhow::ensure!(*prefix.2 == Duration::from_secs(50));
        Ok(())
    }

    #[test]
    fn detect_emits_prefix_with_zero_lifetime() -> Result<()> {
        let mut ra = base_ra();
        ra.prefixes = vec![router_advertisement::PrefixInfo {
            prefix: ip(30),
            prefix_len: 64,
            valid_lifetime: 0,
            preferred_lifetime: 0,
            autonomous: false,
            on_link: false,
        }];

        let events = detect(ra);

        let prefix = events
            .iter()
            .find(|e| matches!(e, Event::Prefix { .. }))
            .context("missing Prefix event")?;

        match prefix {
            Event::Prefix { lifetime, .. } => {
                anyhow::ensure!(lifetime.is_zero());
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    #[test]
    fn detect_emits_router_dns_and_prefix() -> Result<()> {
        let mut ra = base_ra();
        ra.rdnss = vec![router_advertisement::Rdnss {
            servers: vec![ip(1)],
            lifetime: 100,
        }];
        ra.prefixes = vec![router_advertisement::PrefixInfo {
            prefix: ip(10),
            prefix_len: 64,
            valid_lifetime: 200,
            preferred_lifetime: 0,
            autonomous: false,
            on_link: false,
        }];

        let events = detect(ra);

        anyhow::ensure!(events.iter().any(|e| matches!(e, Event::Router { .. })));
        anyhow::ensure!(events.iter().any(|e| matches!(e, Event::DnsServers(_, _))));
        anyhow::ensure!(events.iter().any(|e| matches!(e, Event::Prefix { .. })));

        Ok(())
    }
}
#[cfg(test)]
mod detect_multi_option_tests {
    use super::*;
    use std::net::Ipv6Addr;
    use tokio::time::Duration;
    #[derive(Debug)]
    struct TestOpt {
        id: u8,
        lifetime: Duration,
    }

    impl Lifetime for TestOpt {
        fn lifetime(&self) -> Duration {
            self.lifetime
        }
    }

    #[test]
    fn detect_multi_option_collects_all_items() {
        let key = Key::new(1, Ipv6Addr::from(1));
        let mut out = Vec::new();

        let input = vec![
            TestOpt {
                id: 1,
                lifetime: Duration::from_secs(10),
            },
            TestOpt {
                id: 2,
                lifetime: Duration::from_secs(20),
            },
        ];

        detect_multi_option(
            &mut out,
            key,
            input,
            |o| o.id,
            |k, v| {
                Event::DnsServers(
                    k,
                    vec![DnsServers {
                        servers: vec![Ipv6Addr::from(v[0] as u128), Ipv6Addr::from(v[1] as u128)],
                        lifetime: Duration::from_secs(1),
                    }],
                )
            },
        );

        assert_eq!(out.len(), 1);
    }

    #[test]
    fn detect_multi_option_zero_lifetime_short_circuits() -> anyhow::Result<()> {
        let key = Key::new(1, Ipv6Addr::from(1));
        let mut out = Vec::new();

        let input = vec![
            TestOpt {
                id: 1,
                lifetime: Duration::from_secs(10),
            },
            TestOpt {
                id: 2,
                lifetime: Duration::ZERO,
            },
            TestOpt {
                id: 3,
                lifetime: Duration::from_secs(20),
            },
        ];

        detect_multi_option(
            &mut out,
            key,
            input,
            |o| o.id,
            |k, v| {
                Event::DnsDomains(
                    k,
                    vec![DnsDomains {
                        domains: v.iter().map(|i| i.to_string()).collect(),
                        lifetime: Duration::from_secs(1),
                    }],
                )
            },
        );

        assert_eq!(out.len(), 1);

        match &out[0] {
            Event::DnsDomains(_, domains) => {
                // Empty vector = explicit withdraw
                anyhow::ensure!(domains.len() == 1);
                anyhow::ensure!(domains[0].domains.len() == 0);
            }
            _ => panic!("unexpected event"),
        }
        Ok(())
    }

    #[test]
    fn detect_multi_option_empty_input_emits_nothing() {
        let key = Key::new(1, Ipv6Addr::from(1));
        let mut out = Vec::new();

        let input: Vec<TestOpt> = vec![];

        detect_multi_option(
            &mut out,
            key,
            input,
            |o| o.id,
            |k, _| Event::DnsServers(k, vec![]),
        );

        assert!(out.is_empty());
    }
}
