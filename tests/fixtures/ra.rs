#![allow(dead_code)]

use ipv6_router_advertisement::router_advertisement::RouterAdvertisementMessage;
use std::mem;
use std::net::Ipv6Addr;

pub fn ra_minimal(lifetime: u16) -> Vec<u8> {
    let ra = RouterAdvertisementMessage {
        icmp_type: 134,
        icmp_code: 0,
        checksum: 0,
        cur_hop_limit: 64,
        flags: 0b1100_0000, // M + O
        router_lifetime: lifetime.to_be(),
        reachable_time: 0,
        retrans_timer: 0,
    };

    let mut buf = vec![0u8; mem::size_of::<RouterAdvertisementMessage>()];
    unsafe {
        std::ptr::copy_nonoverlapping(&ra as *const _ as *const u8, buf.as_mut_ptr(), buf.len());
    }
    buf
}

fn push_rdnss(
    buf: &mut Vec<u8>,
    lifetime: u32,
    servers: &[u8], // letzte Byte der ::x
) {
    let n = servers.len();
    let opt_len = 1 + 2 * n; // 8-byte units

    buf.push(25); // ND_OPT_RDNSS
    buf.push(opt_len as u8);
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(&lifetime.to_be_bytes());

    for s in servers {
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, *s]);
    }
}
fn push_dnssl(buf: &mut Vec<u8>, lifetime: u32, domains: &[&str]) {
    let start = buf.len();

    buf.push(31); // ND_OPT_DNSSL
    buf.push(0); // placeholder length
    buf.extend_from_slice(&[0, 0]);
    buf.extend_from_slice(&lifetime.to_be_bytes());

    for d in domains {
        buf.extend_from_slice(&dns_name(d));
    }

    // Padding auf 8-Byte-Grenze
    let len = buf.len() - start;
    let padded = (len + 7) & !7;
    buf.resize(start + padded, 0);

    buf[start + 1] = (padded / 8) as u8;
}

fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // terminator
    out
}

pub fn ra_with_rdnss_dnssl(
    lifetime: u16,
    rdnss_lifetime: u32,
    servers: &[u8],
    dnssl_lifetime: u32,
    domains: &[&str],
) -> Vec<u8> {
    let mut buf = ra_minimal(lifetime);

    push_rdnss(&mut buf, rdnss_lifetime, servers);
    push_dnssl(&mut buf, dnssl_lifetime, domains);

    buf
}

fn push_prefix(
    buf: &mut Vec<u8>,
    prefix: Ipv6Addr,
    prefix_len: u8,
    valid_lifetime: u32,
    preferred_lifetime: u32,
) {
    buf.push(3); // ND_OPT_PREFIX_INFORMATION
    buf.push(4); // length in units of 8 bytes (always 4 = 32 bytes)

    buf.push(prefix_len);

    // Flags: L (on-link) + A (autonomous)
    buf.push(0b1100_0000);

    buf.extend_from_slice(&valid_lifetime.to_be_bytes());
    buf.extend_from_slice(&preferred_lifetime.to_be_bytes());

    // Reserved (4 bytes)
    buf.extend_from_slice(&[0, 0, 0, 0]);

    // Prefix (128 bits)
    buf.extend_from_slice(&prefix.octets());
}

/// Minimal RA containing exactly one Prefix Information Option (PIO).
///
/// This helper is intended for integration tests and produces a byte-exact
/// Router Advertisement message with:
///
/// - one router lifetime
/// - one prefix with valid and preferred lifetime
///
/// No DNS options are included.
pub fn ra_with_prefix(
    router_lifetime: u16,
    prefix: Ipv6Addr,
    prefix_len: u8,
    valid_lifetime: u32,
    preferred_lifetime: u32,
) -> Vec<u8> {
    let mut buf = ra_minimal(router_lifetime);

    push_prefix(
        &mut buf,
        prefix,
        prefix_len,
        valid_lifetime,
        preferred_lifetime,
    );

    buf
}
