#![allow(dead_code)]

use super::RaFrame;
use ipv6_router_advertisement::InterfaceIndex;
use pcap_file::pcapng::{Block, PcapNgReader};
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv6Addr;
use std::path::Path;

/// Load Router Advertisements from a PCAP/PCAPNG file exported by Wireshark.
///
/// Only ICMPv6 Router Advertisement packets (Type 134) are extracted.
/// The parsing is deliberately minimal and only walks through:
///
/// Ethernet -> IPv6 -> ICMPv6
///
/// # Parameters
///
/// - `path`: Path to the PCAP or PCAPNG file
/// - `ifindex`: Interface index to associate with all frames (test scope)
///
/// # Returns
///
/// A vector of `RaFrame` entries in capture order.
pub fn load_ra_frames_from_pcap<P: AsRef<Path>>(
    path: P,
    ifindex: InterfaceIndex,
) -> anyhow::Result<Vec<RaFrame>> {
    let file = File::open(path)?;
    let mut reader = PcapNgReader::new(BufReader::new(file))?;

    let mut frames = Vec::new();

    while let Some(block) = reader.next_block() {
        let block = block?;

        let Block::EnhancedPacket(epb) = block else {
            continue;
        };

        let data = epb.data;

        if let Some((src, icmp_ra)) = extract_icmpv6_ra(&data) {
            let _ts = Some(epb.timestamp);

            frames.push(RaFrame {
                ifindex,
                src,
                payload: icmp_ra.to_vec(),
            });
        }
    }

    Ok(frames)
}

/// Extract an ICMPv6 Router Advertisement from an Ethernet frame.
///
/// Returns the IPv6 source address and a slice pointing to the ICMPv6 payload.
fn extract_icmpv6_ra(frame: &[u8]) -> Option<(Ipv6Addr, &[u8])> {
    // Ethernet header length
    if frame.len() < 14 {
        return None;
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype != 0x86DD {
        return None; // Not IPv6
    }

    // IPv6 header (fixed 40 bytes)
    let ipv6_start = 14;
    if frame.len() < ipv6_start + 40 {
        return None;
    }

    let next_header = frame[ipv6_start + 6];
    if next_header != 58 {
        return None; // Not ICMPv6
    }

    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&frame[ipv6_start + 8..ipv6_start + 24]).ok()?);

    let icmp_start = ipv6_start + 40;
    if frame.len() <= icmp_start {
        return None;
    }

    let icmp_type = frame[icmp_start];
    if icmp_type != 134 {
        return None; // Not Router Advertisement
    }

    Some((src, &frame[icmp_start..]))
}
