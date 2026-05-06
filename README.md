# IPv6 Router Advertisement Processing for Rust

![CI](https://github.com/Th3Link/ipv6-router-advertisement/actions/workflows/ci.yml/badge.svg)
[![Crates.io](https://img.shields.io/crates/v/ipv6-router-advertisement.svg)](https://crates.io/crates/ipv6-router-advertisement)
[![Documentation](https://docs.rs/ipv6-router-advertisement/badge.svg)](https://docs.rs/ipv6-router-advertisement)
[![Downloads](https://img.shields.io/crates/d/ipv6-router-advertisement.svg)](https://crates.io/crates/ipv6-router-advertisement)

Low-level, policy-free processing of IPv6 Router Advertisements (RA) for Linux.
This crate receives ICMPv6 Router Advertisements, parses their contents (including DNS and Prefix Information), tracks lifetimes, aggregates state per interface, and emits deterministic, full-state events. It is intended as a building block for network managers, FSMs, and embedded systems - not as a configuration tool.


## TL;DR

- Parses RAs (RFC 4861 / RFC 8106)
- Tracks lifetimes and expiries
- Aggregates state per interface
- Emits complete, policy-free events
- Supports Router flags (M and O), DNS (RDNSS/DNSSL) and Prefixes (PIO)
- Listens on all interfaces
- Applies no system configuration

## Minimal Example

The crate exposes a single async event stream that emits aggregated, time-aware RA state changes.

```rust
use ipv6_router_advertisement::{router_events, Event};
use futures::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let (link_tx, link_rx) = tokio::sync::broadcast::channel(16);
    // Convert broadcast receiver into a Stream of interface indices
    let link_up_stream = BroadcastStream::new(link_rx)
        .filter_map(|res| async move { res.ok() });
    let mut events = router_events(link_up_stream);

    while let Some(event) = events.next().await {
        match event {
            // the flags are OR'ed over all valid routers.
            Event::RouterUpdate { ifindex, managed, other_config } => {
                println!("router flag change {ifindex}, M={managed}, O={other_config}");
            }
            // event is only fired of the list changes. sends the whole (snapshot)
            // list of dns servers and domains
            Event::RaDns { ifindex, servers, domains } => {
                println!("DNS update on {ifindex}: servers={servers:?}, domains={domains:?}");
            }
            // event is only fired when a prefix changes (added or expried). will always send
            // the whole list (snapshot).
            Event::RaPrefix { ifindex, prefixes } => {
                println!("prefix update on {ifindex}: {prefixes:?}");
            }
            // prefixes can deprecate: they are still valid but you should not assign new ip addresses
            // with this prefix.
            Event::RaPrefixSoftExpiry { ifindex, prefix } => {
                println!("prefix deprecation on {ifindex}: {prefix:?}");
            }
            // the last router became invalid for an interface.
            Event::RouterDown { ifindex } => {
                println!("router down on {ifindex}");
            }
            _ => {}
        }
    }

    Ok(())
}
```

## Why this exists

Although the Linux kernel receives and validates Router Advertisement packets,
it does not expose most relevant RA information (RDNSS, DNSSL, Prefixes, flags, lifetimes)
in a way that is usable for advanced or custom configuration logic.

As a result, all major network managers parse RA packets themselves using raw
ICMPv6 sockets.

## Scope & Philosophy

This crate focuses on:

- Receiving ICMPv6 Router Advertisements using raw sockets
- Parsing RA headers and options (RDNSS, DNSSL, PIO)
- Explicit lifecycle handling based on advertised lifetimes
- Deterministic aggregation of RA information per interface
- Emitting full-state events when effective RA state changes
- Strict separation between data, time, aggregation, and policy

It intentionally does not:

- configure addresses or routes
- start DHCPv6 clients
- modify kernel networking state
- make policy decisions

Instead, it emits snapshots that higher layers can use to setup dhcp and dns.

## Architecture Overview

ICMPv6 socket
-> RA parsing
-> detector (policy-free events)
-> lifecycle (expiry/lifetime handling)
-> aggregator (state reduction and aggregation per interface)
-> event stream

Each layer is meant to be isolated, testable, and documented. There are no hidden side effects. Higher layer
can acces the next lower layer.

## Safety

Working with raw ICMPv6 sockets requires `unsafe` code.

This crate:
- restricts all `unsafe` blocks to socket and packet parsing code
- documents safety requirements explicitly
- keeps higher layers entirely safe Rust

## Standards Compliance

This crate implements IPv6 Router Advertisement processing according to the
following standards:

- RFC 4861 - Neighbor Discovery for IP version 6 (IPv6)
  Parsing and interpretation of ICMPv6 Router Advertisement (RA) and
  Router Solicitation (RS) messages, including flags, lifetimes and timing
  behavior.

- RFC 8106 - IPv6 Router Advertisement Options for DNS Configuration
  Support for DNS-related RA options:
  - Recursive DNS Server (RDNSS)
  - DNS Search List (DNSSL)

The crate intentionally focuses on control-plane information conveyed
by Router Advertisements and does not currently process address prefix
options used for SLAAC-based address assignment (RFC 4862).

### Prefix InformationOptions  (PIO)
Prefix Information Options (PIO, RFC 4861 / RFC 4862) are fully parsed and tracked as leases.
The crate:

tracks valid and preferred lifetimes
emits prefix updates as complete, authoritative state
emits separate advisory events when preferred lifetimes expire

The crate does not apply prefixes to interfaces or generate addresses. Prefix handling is informational and intended for higher-level policy engines.

### DHCPv6 Interaction

The crate supports the interpretation of RA flags used to coordinate
DHCPv6 behavior:

- Managed (M) flag - indicates stateful DHCPv6 for address configuration
- Other (O) flag - indicates stateless DHCPv6 for configuration data

Mixed configurations (e.g. SLAAC prefix information combined with DHCPv6-based
interface identifiers or DNS information) are recognized at the policy level
but left to higher layers to implement.

## Observability

The crate uses `tracing` for structured, async-aware diagnostics.

- No global subscriber is installed
- All tracing is optional and controlled by the application
- Spans are placed at semantic boundaries (RA reception, lifecycle, FSM)

## Testing Strategy
Testing is a first-class concern and covers multiple layers:

### Unit Tests

- detector semantics (DNS replace vs prefix leases)
- lifecycle expiry rules
- aggregation behavior

### Integration Tests

- end-to-end RA processing via mock ICMPv6 sockets
- multi-router and multi-interface scenarios
- DNS and prefix expiry behavior

### PCAP Replay Tests
The test suite includes helpers to replay real Router Advertisement captures exported from Wireshark.
Only Router Advertisements are injected; Router Solicitations are explicitly excluded to keep tests deterministic.

## Co-Maintainer Wanted

This project is currently maintained by a single author.

Co-maintainers and contributors are very welcome, especially people
interested in:

- Rust networking
- IPv6 internals (RA, DHCPv6)
- Async / IO heavy systems
- Testing and observability

If you'd like to help shape this crate long-term, please open an issue
or start a discussion.

## Contributing

Contributions are welcome, especially around:

IPv6 / RA edge cases
testing and PCAP-based scenarios
documentation and examples

See CONTRIBUTING.md for details.

## License

This project is licensed under **MIT OR Apache-2.0**.
