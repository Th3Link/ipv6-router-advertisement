//! # ICMPv6 Router Advertisement Receiver
//!
//! This module receives and parses IPv6 Router Advertisement (RA) packets
//! using raw ICMPv6 sockets.
//!
//! ## Why this module exists
//!
//! Although the Linux kernel already receives and validates Router
//! Advertisements, it does not expose all RA information in a form usable
//! for advanced configuration logic.
//!
//! As a result, this module must re-parse RA packets in user space.
//! Other network managers (e.g. systemd-networkd, NetworkManager) solve
//! this problem in the same way.
//!
//! ## Safety
//!
//! Working with raw IPv6 sockets requires `unsafe` code. Unsafe blocks
//! are strictly limited to:
//!
//! - raw socket creation and configuration
//! - `recvmsg` usage and ancillary data parsing
//!
//! All unsafe operations are encapsulated and validated before producing
//! safe, policy-free data structures.
//!
//! ## Responsibilities
//!
//! - Receive ICMPv6 Router Advertisements
//! - Parse RA headers and options (RDNSS, DNSSL)
//! - Convert raw packets into policy-free `Ipv6Ra` structures
//! - Drive Router Solicitation (RS) bursts on link changes
//!
//! This module performs **no policy decisions**.
//! Policy is handled exclusively by higher layers.

use super::Lifetime;
use crate::{icmpv6_socket::Icmpv6Socket, InterfaceIndex};
use std::{mem, net::Ipv6Addr};
use tokio::time::{self, Duration};
use tracing::{debug, warn};

/// ICMPv6 Router Advertisement type (RFC 4861)
const ICMPV6_RA_TYPE: u8 = 134;

/// ND option types (RFC 6106)
const ND_OPT_RDNSS: u8 = 25;
const ND_OPT_DNSSL: u8 = 31;
const ND_OPT_PREFIX_INFO: u8 = 3;

/// Parsed IPv6 Router Advertisement data.
///
/// This structure represents the information contained in a single
/// ICMPv6 Router Advertisement as received from the network.
///
/// It is intentionally **policy-free**:
/// - no aggregation
/// - no lifetime handling
/// - no configuration decisions
///
/// Higher layers are responsible for interpreting and acting on this data.
#[derive(Debug, Clone)]
pub struct RouterAdvertisement {
    /// Interface index on which the RA was received.
    pub ifindex: u32,
    /// IPv6 address of the advertising router.
    pub router_ip: Ipv6Addr,
    /// Managed address configuration flag (M flag).
    pub managed: bool,
    /// Other configuration flag (O flag).
    pub other_config: bool,
    /// Router lifetime in seconds, as advertised.
    pub router_lifetime: u16,
    /// Recursive DNS server information (RDNSS option), if present.
    pub rdnss: Vec<Rdnss>,
    /// DNS search list information (DNSSL option), if present.
    pub dnssl: Vec<Dnssl>,
    /// Prefix information option (PIO). PIO is different to DNS: prefixes only expire by lifetime
    /// not by not sending it anymore.
    pub prefixes: Vec<PrefixInfo>,
}

/// Recursive DNS Server (RDNSS) option data.
///
/// Defined in RFC 6106.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rdnss {
    /// Validity lifetime of the DNS server list in seconds.
    pub lifetime: u32,
    /// IPv6 addresses of recursive DNS servers.
    pub servers: Vec<Ipv6Addr>,
}

impl Lifetime for Rdnss {
    fn lifetime(&self) -> Duration {
        Duration::from_secs(self.lifetime as u64)
    }
}

/// DNS Search List (DNSSL) option data.
///
/// Defined in RFC 6106.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dnssl {
    /// Validity lifetime of the DNS search list in seconds.
    pub lifetime: u32,
    /// Fully qualified domain names forming the search list.
    ///
    /// Each domain is returned with a trailing dot (`.`).
    pub domains: Vec<String>,
}

impl Lifetime for Dnssl {
    fn lifetime(&self) -> Duration {
        Duration::from_secs(self.lifetime as u64)
    }
}

/// IPv6 Prefix Information as advertised via the Prefix Information Option (PIO)
/// in an ICMPv6 Router Advertisement (RFC 4861).
///
/// A `PrefixInfo` describes a single IPv6 prefix contributed by a router,
/// together with its associated lifetimes and flags. The information is
/// **policy‑free**: it does not decide how the prefix is used (SLAAC,
/// on‑link routing, delegation, etc.).
///
/// Semantics:
/// - Each router may advertise zero or more prefixes.
/// - Prefixes are scoped to an interface and a router.
/// - Lifetimes control validity and preference but are not interpreted here.
/// - Higher layers (lifecycle, aggregation, FSM) decide how prefixes are applied.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Valid lifetime of the prefix, in seconds.
    ///
    /// After this time has elapsed, the prefix is no longer valid and
    /// must not be used for new connections.
    ///
    /// A value of zero indicates immediate invalidation.
    pub valid_lifetime: u32,

    /// Preferred lifetime of the prefix, in seconds.
    ///
    /// While the prefix is preferred, it may be used for new connections.
    /// Once the preferred lifetime expires (but before the valid lifetime),
    /// the prefix is considered deprecated.
    pub preferred_lifetime: u32,

    /// On‑link flag (L flag).
    ///
    /// If set, the prefix is considered on‑link for the interface.
    /// Hosts may treat destinations within this prefix as directly reachable.
    /// Kernel handles this flag, we ignore it.
    pub on_link: bool,

    /// Autonomous address‑configuration flag (A flag).
    ///
    /// If set, the prefix may be used for stateless address
    /// autoconfiguration (SLAAC). Kernel handles it, we ignore it
    pub autonomous: bool,
}

impl Lifetime for PrefixInfo {
    fn lifetime(&self) -> Duration {
        Duration::from_secs(self.valid_lifetime as u64)
    }
}
/// Raw ICMPv6 Router Advertisement message (RFC4861).
/// Section 4.2 - Router Advertisement Message Format
///
/// This structure mirrors the fixed header of an IPv6 Router Advertisement
/// as defined in RFC 4861 and is used only for on-wire parsing.
/// All fields are in network byte order unless stated otherwise.
///
/// Options follow immediately after this header.
#[repr(C)]
pub struct RouterAdvertisementMessage {
    /// ICMPv6 message type (must be 134 for Router Advertisement).
    pub icmp_type: u8,
    /// ICMPv6 code (always 0).
    pub icmp_code: u8,
    /// ICMPv6 checksum (verified by the kernel).
    pub checksum: u16,
    /// Current hop limit to be used by hosts.
    pub cur_hop_limit: u8,
    /// RA flags field containing:
    /// - Managed address configuration flag (M)
    /// - Other configuration flag (O)
    pub flags: u8,
    /// Router lifetime in seconds.
    ///
    /// Indicates how long this router should be considered a default router.
    pub router_lifetime: u16,
    /// Reachable Time in milliseconds.
    ///
    /// Advertises how long a neighbor is considered reachable after
    /// receiving a reachability confirmation.
    pub reachable_time: u32,
    /// Retransmission Timer in milliseconds.
    ///
    /// Used for Neighbor Solicitation retransmissions.
    pub retrans_timer: u32,
}

/// ICMPv6 Router Solicitation message (RFC 4861).
/// Section 4.1 - Router Solicitation Message Format
///
/// This structure represents the minimal Router Solicitation message
/// used to request Router Advertisements.
///
/// The checksum is left as zero and calculated by the kernel.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RouterSolicitationMessage {
    /// ICMPv6 message type (133).
    pub icmp_type: u8,
    /// ICMPv6 code (always 0).
    pub icmp_code: u8,
    /// ICMPv6 checksum (computed by the kernel).
    pub checksum: u16,
    /// Reserved field, must be zero.
    pub reserved: u32,
}

impl Default for RouterSolicitationMessage {
    fn default() -> Self {
        Self {
            icmp_type: 133, // ND_ROUTER_SOLICIT
            icmp_code: 0,
            checksum: 0,
            reserved: 0,
        }
    }
}

impl RouterSolicitationMessage {
    pub fn as_bytes(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];

        buf[0] = self.icmp_type;
        buf[1] = self.icmp_code;
        buf[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        buf[4..8].copy_from_slice(&self.reserved.to_be_bytes());

        buf
    }
}

pub fn decode_router_advertisement(
    ifindex: InterfaceIndex,
    router_ip: Ipv6Addr,
    payload: &[u8],
) -> anyhow::Result<RouterAdvertisement> {
    if payload.len() < mem::size_of::<RouterAdvertisementMessage>() {
        anyhow::bail!("Truncated RA");
    }

    let ra = unsafe { &*(payload.as_ptr() as *const RouterAdvertisementMessage) };

    if ra.icmp_type != ICMPV6_RA_TYPE {
        anyhow::bail!("Not a Router Advertisement");
    }

    let (managed, other) = parse_flags(ra.flags);

    let options = &payload[mem::size_of::<RouterAdvertisementMessage>()..];

    let (rdnss, dnssl, prefixes) = parse_router_advertisement_options(options).unwrap_or_default();

    debug!(
        ifindex,
        %router_ip,
        router_lifetime = u16::from_be(ra.router_lifetime),
        managed,
        other,
        rdnss = rdnss.len(),
        dnssl = dnssl.len(),
        prefixes = prefixes.len(),
        "decoded router advertisement"
    );

    Ok(RouterAdvertisement {
        ifindex,
        router_ip,
        managed,
        other_config: other,
        router_lifetime: u16::from_be(ra.router_lifetime),
        rdnss,
        dnssl,
        prefixes,
    })
}

/// Parses the Managed (M) and Other Configuration (O) flags from an RA header.
///
/// Returns a tuple `(managed, other_config)` corresponding to the
/// respective bits in the RA flags field.
fn parse_flags(flags: u8) -> (bool, bool) {
    let managed = flags & 0b1000_0000 != 0;
    let other = flags & 0b0100_0000 != 0;
    (managed, other)
}

/// Send a burst of Router Solicitation (RS) messages.
///
/// This function implements the RFC 4861 recommended behavior:
///
/// - transmit up to `count` solicitations
/// - wait `interval` between transmissions
/// - stop early if a cancellation token is triggered
///
/// Failure to receive a Router Advertisement is **not considered an error**.
pub async fn send_router_solicitation_burst<I: Icmpv6Socket>(
    socket: &I,
    ifindex: u32,
    count: usize,
    interval: Duration,
) {
    let rs = RouterSolicitationMessage::default();
    for _ in 0..count {
        socket
            .send(
                ifindex,
                Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2),
                &rs.as_bytes(),
            )
            .ok();
        time::sleep(interval).await;
    }
    // rs should be aborted when receiving a ra. this did not happen though.
    warn!("router solicitation burst finished without receiving a router advertisement");
}

/// Extracts a fixed-size slice from a buffer at a given offset.
///
/// Returns an error if the requested range exceeds the buffer bounds
/// or if the conversion fails.
///
/// This helper is primarily used when decoding network byte structures.
fn get_slice<const N: usize>(buf: &[u8], start: usize) -> anyhow::Result<[u8; N]> {
    let end = start + N;
    if end > buf.len() {
        return Err(anyhow::anyhow!("Truncated"));
    }
    buf[start..end]
        .try_into()
        .map_err(|_| anyhow::anyhow!("InvalidLength"))
}

/// Parses relevant Router Advertisement options from an RA payload.
///
/// This function currently supports:
/// - RDNSS (RFC 6106)
/// - DNSSL (RFC 6106)
/// - Prefix Information Options (PIO) (RFC 4861).
///
/// Unknown options are skipped.
/// Malformed options result in an error.
///
/// Returns the parsed RDNSS, DNSSL and PIO information if present.
fn parse_router_advertisement_options(
    buf: &[u8],
) -> anyhow::Result<(Vec<Rdnss>, Vec<Dnssl>, Vec<PrefixInfo>)> {
    let mut offset = 0;
    let mut rdnss = Vec::new();
    let mut dnssl = Vec::new();
    let mut prefixes = Vec::new();

    while offset + 2 <= buf.len() {
        let opt_type = buf[offset];
        let opt_len = (buf[offset + 1] as usize) * 8;

        if opt_len == 0 {
            tracing::trace!(buf=?buf, rdnss=?rdnss, dnssl=?dnssl, prefixes=?prefixes);
            return Err(anyhow::anyhow!(
                "InvalidLength on offset {offset} type: {opt_type}"
            ));
        }

        if offset + opt_len > buf.len() {
            tracing::trace!(buf=?buf, opt_type=opt_type, offset=offset, opt_len=opt_len, rdnss=?rdnss, dnssl=?dnssl, prefixes=?prefixes);
            return Err(anyhow::anyhow!(
                "Truncated: {} must be > {}",
                offset + opt_len,
                buf.len()
            ));
        }

        match opt_type {
            ND_OPT_RDNSS => {
                if let Ok(rdnss_option) = parse_rdnss_servers(&buf[offset + 4..offset + opt_len]) {
                    rdnss.push(rdnss_option);
                }
            }

            ND_OPT_DNSSL => {
                if let Ok(dnssl_option) = parse_dnssl_domains(&buf[offset + 4..offset + opt_len]) {
                    dnssl.push(dnssl_option);
                }
            }

            ND_OPT_PREFIX_INFO => {
                if let Ok(prefix) = parse_prefix_information(&buf[offset + 2..offset + opt_len]) {
                    prefixes.push(prefix);
                }
            }
            _ => {}
        }

        offset += opt_len;
    }

    Ok((rdnss, dnssl, prefixes))
}

/// Parses prefix information options (PIO) from an option payload (RFC 4861).
/// Type and Length are already cut of
///
/// +---------+---------+---------+---------+
/// | Type=3  | Length  | PrefixLen | Flags |
/// +---------+---------+---------+---------+
/// |        Valid Lifetime (32 bits)       |
/// +---------------------------------------+
/// |     Preferred Lifetime (32 bits)      |
/// +---------------------------------------+
/// |            Reserved (32 bits)         |
/// +---------------------------------------+
/// |        IPv6 Prefix (128 bits)         |
/// +---------------------------------------+
///
/// The input buffer contains a signal prefix information:
fn parse_prefix_information(buf: &[u8]) -> anyhow::Result<PrefixInfo> {
    if buf.len() < 30 {
        return Err(anyhow::anyhow!("Invalid PIO length"));
    }

    let prefix_len = buf[0];
    let flags = buf[1];

    let on_link = flags & 0x80 != 0;
    let autonomous = flags & 0x40 != 0;

    let valid_lifetime = u32::from_be_bytes(get_slice::<4>(buf, 2)?);
    let preferred_lifetime = u32::from_be_bytes(get_slice::<4>(buf, 6)?);
    // offset 10 is reserved
    let prefix = Ipv6Addr::from(get_slice::<16>(buf, 14)?);

    Ok(PrefixInfo {
        prefix,
        prefix_len,
        valid_lifetime,
        preferred_lifetime,
        on_link,
        autonomous,
    })
}

/// Parses DNS search domains from a DNSSL option payload (RFC 6106).
/// Type, Length and Reserved are already cut of
///
/// +--------+--------+--------+--------+
/// | Type=25| Length | Reserved        |
/// +--------+--------+--------+--------+
/// |        Lifetime (32 bits)         |
/// +-----------------------------------+
/// |  IPv6 address #1 (16 bytes)       |
/// +-----------------------------------+
/// |  IPv6 address #2 (16 bytes)       |
/// +-----------------------------------+
///
/// The input buffer contains a signal prefix information:
fn parse_rdnss_servers(buf: &[u8]) -> anyhow::Result<Rdnss> {
    let lifetime = u32::from_be_bytes(get_slice::<4>(buf, 0)?);
    let mut servers = Vec::new();
    let mut pos = 4;

    while pos + 16 <= buf.len() {
        let addr = Ipv6Addr::from(get_slice::<16>(buf, pos)?);
        servers.push(addr);
        pos += 16;
    }

    Ok(Rdnss { lifetime, servers })
}

/// Parses DNS search domains from a DNSSL option payload (RFC 6106).
/// Type, Length and Reserved are already cut of.
///
/// The input buffer contains a sequence of DNS labels encoded as:
/// - length-prefixed labels
/// - zero-length terminators between domains
///
/// +--------+--------+--------+--------+
/// | Type=31| Length | Reserved        |
/// +--------+--------+--------+--------+
/// |        Lifetime (32 bits)         |
/// +-----------------------------------+
/// |  DNS label sequence (variable)    |
/// +-----------------------------------+
///
/// The returned domain strings are fully qualified and always end
/// with a trailing dot (`.`).
///
/// Invalid or truncated labels are ignored.
fn parse_dnssl_domains(buf: &[u8]) -> anyhow::Result<Dnssl> {
    let lifetime = u32::from_be_bytes(get_slice::<4>(buf, 0)?);
    let mut domains = Vec::new();
    let mut cur = Vec::new();
    let mut i = 4;

    while i < buf.len() {
        let len = buf[i] as usize;
        i += 1;

        if len == 0 {
            if !cur.is_empty() {
                domains.push(String::from_utf8_lossy(&cur).to_string());
                cur.clear();
            }
            continue;
        }

        if i + len > buf.len() {
            break;
        }

        cur.extend_from_slice(&buf[i..i + len]);
        // Here we will always create domains with . an the end
        cur.push(b'.');
        i += len;
    }

    Ok(Dnssl { lifetime, domains })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use anyhow::ensure;

    use super::*;

    fn ra_header(flags: u8, router_lifetime: u16) -> Vec<u8> {
        let mut buf = vec![0u8; mem::size_of::<RouterAdvertisementMessage>()];

        let ra = RouterAdvertisementMessage {
            icmp_type: ICMPV6_RA_TYPE,
            icmp_code: 0,
            checksum: 0,
            cur_hop_limit: 64,
            flags,
            router_lifetime: router_lifetime.to_be(),
            reachable_time: 0,
            retrans_timer: 0,
        };

        unsafe {
            std::ptr::copy_nonoverlapping(
                &ra as *const _ as *const u8,
                buf.as_mut_ptr(),
                buf.len(),
            );
        }

        buf
    }

    // parse_flags
    #[test]
    fn test_parse_flags_none() {
        let (managed, other) = parse_flags(0b0000_0000);
        assert!(!managed);
        assert!(!other);
    }

    #[test]
    fn test_parse_flags_managed_only() {
        let (managed, other) = parse_flags(0b1000_0000);
        assert!(managed);
        assert!(!other);
    }

    #[test]
    fn test_parse_flags_other_only() {
        let (managed, other) = parse_flags(0b0100_0000);
        assert!(!managed);
        assert!(other);
    }

    #[test]
    fn test_parse_flags_both() {
        let (managed, other) = parse_flags(0b1100_0000);
        assert!(managed);
        assert!(other);
    }

    // get_slice

    #[test]
    fn test_get_slice_ok() {
        let buf = [1, 2, 3, 4, 5, 6];
        let s: [u8; 4] = get_slice(&buf, 1).unwrap();
        assert_eq!(s, [2, 3, 4, 5]);
    }

    #[test]
    fn test_get_slice_truncated() {
        let buf = [1, 2, 3];
        let err = get_slice::<4>(&buf, 0).unwrap_err();
        assert!(err.to_string().contains("Truncated"));
    }

    // parse_dnssl_domains

    #[test]
    fn test_parse_dnssl_single_domain() -> anyhow::Result<()> {
        // "example.com."
        let buf = [
            0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let dnssl = parse_dnssl_domains(&buf)?;
        assert_eq!(dnssl.domains, vec!["example.com."]);
        Ok(())
    }

    #[test]
    fn test_parse_dnssl_multiple_domains() -> anyhow::Result<()> {
        // "example.com." + "test.local."
        let buf = [
            0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 4,
            b't', b'e', b's', b't', 5, b'l', b'o', b'c', b'a', b'l', 0,
        ];

        let dnssl = parse_dnssl_domains(&buf)?;
        assert_eq!(dnssl.domains, vec!["example.com.", "test.local."]);
        Ok(())
    }

    #[test]
    fn test_parse_dnssl_truncated_label() -> anyhow::Result<()> {
        // length says 5, only 3 bytes follow
        let buf = [5, b'a', b'b', b'c'];
        let dnssl = parse_dnssl_domains(&buf)?;
        assert!(dnssl.domains.is_empty());
        Ok(())
    }

    // parse_ra_options - RDNSS

    #[test]
    fn test_parse_rdnss_three_server() -> anyhow::Result<()> {
        let mut buf = Vec::new();

        // Lifetime = 60
        buf.extend_from_slice(&60u32.to_be_bytes());

        // Three IPv6 address
        let addr = Ipv6Addr::LOCALHOST.octets();
        buf.extend_from_slice(&addr);
        buf.extend_from_slice(&addr);
        buf.extend_from_slice(&addr);

        let rdnss = parse_rdnss_servers(&buf)?;

        ensure!(rdnss.lifetime == 60);
        ensure!(
            rdnss.servers
                == vec![
                    Ipv6Addr::LOCALHOST,
                    Ipv6Addr::LOCALHOST,
                    Ipv6Addr::LOCALHOST
                ]
        );
        Ok(())
    }

    #[test]
    fn test_parse_ra_options_rdnss_single_server() -> anyhow::Result<()> {
        let mut buf = Vec::new();

        // Type, Length (= 3 * 8 = 24 bytes)
        buf.push(ND_OPT_RDNSS);
        buf.push(3);

        // Reserved
        buf.extend_from_slice(&[0, 0]);

        // Lifetime = 60
        buf.extend_from_slice(&60u32.to_be_bytes());

        // One IPv6 address
        let addr = Ipv6Addr::LOCALHOST.octets();
        buf.extend_from_slice(&addr);

        let (rdnss, dnssl, _prefixes) = parse_router_advertisement_options(&buf).unwrap();

        assert_eq!(rdnss[0].lifetime, 60);
        assert_eq!(rdnss[0].servers, vec![Ipv6Addr::LOCALHOST]);
        assert!(dnssl.is_empty());
        Ok(())
    }

    // parse_ra_options - DNSSL
    #[test]
    fn test_parse_ra_options_dnssl_single_domain() -> anyhow::Result<()> {
        let mut buf = Vec::new();

        // Domain: example.com.
        let domain = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let padding = (8 - (domain.len() % 8)) % 8;
        let opt_len = 8 + domain.len() + padding;

        buf.push(ND_OPT_DNSSL);
        buf.push((opt_len / 8) as u8);
        buf.extend_from_slice(&[0, 0]);

        buf.extend_from_slice(&120u32.to_be_bytes()); // lifetime
        buf.extend_from_slice(&domain);

        // padding
        buf.extend(vec![0u8; padding]);

        let (rdnss, dnssl, _prefixes) = parse_router_advertisement_options(&buf)?;

        assert!(rdnss.is_empty());
        assert_eq!(dnssl[0].lifetime, 120);
        assert_eq!(dnssl[0].domains, vec!["example.com."]);
        Ok(())
    }

    // parse_ra_options - PIO
    #[test]
    fn test_parse_ra_options_single_prefix() -> anyhow::Result<()> {
        let mut buf = Vec::new();

        buf.push(ND_OPT_PREFIX_INFO);
        buf.push(4u8); //(4x 8 byte units)
        buf.extend_from_slice(&[64, 0]); // prefix_len and flags

        buf.extend_from_slice(&120u32.to_be_bytes()); // valid_lifetime
        buf.extend_from_slice(&100u32.to_be_bytes()); // preferred_lifetime
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.to_bits().to_be_bytes());

        let (rdnss, dnssl, prefixes) = parse_router_advertisement_options(&buf)?;

        ensure!(rdnss.is_empty());
        ensure!(dnssl.is_empty());
        ensure!(prefixes.len() == 1);
        ensure!(prefixes[0].valid_lifetime == 120);
        ensure!(prefixes[0].preferred_lifetime == 100);
        ensure!(prefixes[0].prefix_len == 64);
        ensure!(prefixes[0].prefix == Ipv6Addr::LOCALHOST);
        Ok(())
    }

    #[test]
    fn test_parse_ra_options_multiple_prefix() -> anyhow::Result<()> {
        let mut buf = Vec::new();

        buf.push(ND_OPT_PREFIX_INFO);
        buf.push(4u8); //(4x 8 byte units)
        buf.extend_from_slice(&[64, 0]); // prefix_len and flags

        buf.extend_from_slice(&120u32.to_be_bytes()); // valid_lifetime
        buf.extend_from_slice(&100u32.to_be_bytes()); // preferred_lifetime
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.to_bits().to_be_bytes());

        buf.push(ND_OPT_PREFIX_INFO);
        buf.push(4u8); //(4x 8 byte units)
        buf.extend_from_slice(&[56, 0]); // prefix_len and flags

        buf.extend_from_slice(&80u32.to_be_bytes()); // valid_lifetime
        buf.extend_from_slice(&60u32.to_be_bytes()); // preferred_lifetime
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.to_bits().to_be_bytes());

        buf.push(ND_OPT_PREFIX_INFO);
        buf.push(4u8); //(4x 8 byte units)
        buf.extend_from_slice(&[60, 0]); // prefix_len and flags

        buf.extend_from_slice(&40u32.to_be_bytes()); // valid_lifetime
        buf.extend_from_slice(&20u32.to_be_bytes()); // preferred_lifetime
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.to_bits().to_be_bytes());
        let (rdnss, dnssl, prefixes) = parse_router_advertisement_options(&buf)?;

        ensure!(rdnss.is_empty());
        ensure!(dnssl.is_empty());
        ensure!(prefixes.len() == 3);
        ensure!(prefixes[0].valid_lifetime == 120);
        ensure!(prefixes[0].preferred_lifetime == 100);
        ensure!(prefixes[0].prefix_len == 64);
        ensure!(prefixes[0].prefix == Ipv6Addr::LOCALHOST);
        ensure!(prefixes[1].valid_lifetime == 80);
        ensure!(prefixes[1].preferred_lifetime == 60);
        ensure!(prefixes[1].prefix_len == 56);
        ensure!(prefixes[1].prefix == Ipv6Addr::LOCALHOST);
        ensure!(prefixes[2].valid_lifetime == 40);
        ensure!(prefixes[2].preferred_lifetime == 20);
        ensure!(prefixes[2].prefix_len == 60);
        ensure!(prefixes[2].prefix == Ipv6Addr::LOCALHOST);
        Ok(())
    }

    #[test]
    fn test_parse_ra_options_ultimate() -> anyhow::Result<()> {
        use tracing_subscriber::{fmt, EnvFilter};
        let _ = fmt()
            .with_env_filter(EnvFilter::from_default_env().add_directive("trace".parse().unwrap()))
            .with_test_writer()
            .try_init();

        let mut buf = Vec::new();
        // first prefix
        buf.push(ND_OPT_PREFIX_INFO);
        buf.push(4u8); //(4x 8 byte units)
        buf.extend_from_slice(&[64, 0]); // prefix_len and flags

        buf.extend_from_slice(&120u32.to_be_bytes()); // valid_lifetime
        buf.extend_from_slice(&100u32.to_be_bytes()); // preferred_lifetime
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.to_bits().to_be_bytes());

        // Domain: example.com.
        let domain = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let padding = (8 - (domain.len() % 8)) % 8;
        let opt_len = 8 + domain.len() + padding;

        buf.push(ND_OPT_DNSSL);
        buf.push((opt_len / 8) as u8);
        buf.extend_from_slice(&[0, 0]);

        buf.extend_from_slice(&120u32.to_be_bytes()); // lifetime
        buf.extend_from_slice(&domain);

        // padding
        buf.extend(vec![0u8; padding]);

        // servers
        buf.push(ND_OPT_RDNSS);
        buf.push(((8 + 16 + 16 + 16) / 8) as u8);
        buf.extend_from_slice(&[0, 0]);
        // Lifetime = 60
        buf.extend_from_slice(&60u32.to_be_bytes());

        // Three IPv6 address
        let addr = Ipv6Addr::LOCALHOST.octets();
        buf.extend_from_slice(&addr);
        buf.extend_from_slice(&addr);
        buf.extend_from_slice(&addr);

        // Prefix
        buf.push(ND_OPT_PREFIX_INFO);
        buf.push(4u8); //(4x 8 byte units)
        buf.extend_from_slice(&[56, 0]); // prefix_len and flags

        buf.extend_from_slice(&80u32.to_be_bytes()); // valid_lifetime
        buf.extend_from_slice(&60u32.to_be_bytes()); // preferred_lifetime
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&Ipv6Addr::LOCALHOST.to_bits().to_be_bytes());

        // Domain: example2.com.
        let domain = [
            8, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'2', 3, b'c', b'o', b'm', 0,
        ];

        let padding = (8 - (domain.len() % 8)) % 8;
        let opt_len = 8 + domain.len() + padding;

        buf.push(ND_OPT_DNSSL);
        buf.push((opt_len / 8) as u8);
        buf.extend_from_slice(&[0, 0]);

        buf.extend_from_slice(&120u32.to_be_bytes()); // lifetime
        buf.extend_from_slice(&domain);

        // padding
        buf.extend(vec![0u8; padding]);
        let (rdnss, dnssl, prefixes) = parse_router_advertisement_options(&buf)?;

        ensure!(rdnss.len() == 1);
        ensure!(dnssl.len() == 2);
        ensure!(prefixes.len() == 2);
        ensure!(prefixes[0].valid_lifetime == 120);
        ensure!(prefixes[0].preferred_lifetime == 100);
        ensure!(prefixes[0].prefix_len == 64);
        ensure!(prefixes[0].prefix == Ipv6Addr::LOCALHOST);
        ensure!(prefixes[1].valid_lifetime == 80);
        ensure!(prefixes[1].preferred_lifetime == 60);
        ensure!(prefixes[1].prefix_len == 56);
        ensure!(prefixes[1].prefix == Ipv6Addr::LOCALHOST);
        Ok(())
    }
    // parse_ra_options - error handling

    #[test]
    fn test_parse_ra_options_invalid_length() {
        let buf = [ND_OPT_RDNSS, 0];
        let err = parse_router_advertisement_options(&buf).unwrap_err();
        assert!(err.to_string().contains("InvalidLength"));
    }

    #[test]
    fn test_parse_ra_options_truncated() {
        let buf = [ND_OPT_RDNSS, 2, 0, 0];
        let err = parse_router_advertisement_options(&buf).unwrap_err();
        assert!(err.to_string().contains("Truncated"));
    }

    #[test]
    fn test_dnssl_domains_are_fully_qualified() -> anyhow::Result<()> {
        let buf = [
            0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c',
            b'o', b'm', 0,
        ];

        let dnssl = parse_dnssl_domains(&buf)?;
        assert_eq!(dnssl.domains, vec!["www.example.com."]);
        Ok(())
    }

    #[test]
    fn decode_minimal_ra() {
        let payload = ra_header(0b1100_0000, 1800);

        let ra = decode_router_advertisement(2, "fe80::1".parse().unwrap(), &payload).unwrap();

        assert_eq!(ra.ifindex, 2);
        assert_eq!(
            ra.router_ip,
            Ipv6Addr::from([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert!(ra.managed);
        assert!(ra.other_config);
        assert_eq!(ra.router_lifetime, 1800);
        assert!(ra.rdnss.is_empty());
        assert!(ra.dnssl.is_empty());
        assert!(ra.prefixes.is_empty());
    }

    #[test]
    fn reject_non_ra_packet() {
        let mut payload = ra_header(0, 0);
        payload[0] = 128; // ICMPv6 Echo Request

        let err = decode_router_advertisement(0, Ipv6Addr::UNSPECIFIED, &payload).unwrap_err();

        assert!(err.to_string().contains("Not a Router Advertisement"));
    }

    #[test]
    fn reject_truncated_ra() {
        let payload = vec![0u8; mem::size_of::<RouterAdvertisementMessage>() - 1];

        let err = decode_router_advertisement(0, Ipv6Addr::UNSPECIFIED, &payload).unwrap_err();

        assert!(err.to_string().contains("Truncated"));
    }

    #[test]
    fn parse_rdnss_option() -> anyhow::Result<()> {
        let mut payload = ra_header(0, 0);

        // RDNSS option:
        // type = 25
        // length = 3 (24 bytes)
        payload.extend_from_slice(&[
            ND_OPT_RDNSS,
            3,
            0,
            0,
            0,
            0,
            0,
            30, // lifetime = 30
        ]);

        payload.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let ra = decode_router_advertisement(1, Ipv6Addr::UNSPECIFIED, &payload)?;
        let rdnss = ra.rdnss;
        anyhow::ensure!(rdnss.len() == 1);
        anyhow::ensure!(rdnss[0].lifetime == 30);
        anyhow::ensure!(rdnss[0].servers.len() == 1);
        anyhow::ensure!(rdnss[0].servers[0] == "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        Ok(())
    }

    #[test]
    fn parse_dnssl_option() -> anyhow::Result<()> {
        let mut payload = ra_header(0, 0);

        let domain = [
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let opt_len = 8 + domain.len();
        let padded_len = (opt_len + 7) & !7;

        payload.push(ND_OPT_DNSSL);
        payload.push((padded_len / 8) as u8);
        payload.extend_from_slice(&[0, 0]); // reserved
        payload.extend_from_slice(&60u32.to_be_bytes());
        payload.extend_from_slice(&domain);
        payload.resize(payload.len() + (padded_len - opt_len), 0);

        let ra = decode_router_advertisement(1, Ipv6Addr::UNSPECIFIED, &payload)?;
        let dnssl = ra.dnssl;
        anyhow::ensure!(dnssl.len() == 1);
        anyhow::ensure!(dnssl[0].lifetime == 60);
        anyhow::ensure!(dnssl[0].domains == vec!["example.com.".to_string()]);
        Ok(())
    }
}
