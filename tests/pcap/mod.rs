#![allow(dead_code)]

pub mod loader;
pub mod replay_flat;

use ipv6_router_advertisement::InterfaceIndex;
use std::net::Ipv6Addr;

/// A single Router Advertisement frame extracted from a PCAP file.
///
/// This is the unified representation used by replay helpers.
#[derive(Debug, Clone)]
pub struct RaFrame {
    pub ifindex: InterfaceIndex,
    pub src: Ipv6Addr,
    pub payload: Vec<u8>, // ICMPv6 RA starting at Type field (134)
}
