//! Working out which address a request actually came from.
//!
//! # Why this is a security decision and not a convenience
//!
//! Three subsystems read the caller's address, and each of them treats it as
//! authority:
//!
//! - **Cedar** sees it as `context.source_ip`, so a policy can say "nothing in
//!   production is readable from outside the VPC".
//! - **Rate limiting** buckets by it, so one abusive client cannot be spread
//!   across the whole table by rotating a header.
//! - **The audit trail** records it, so a decision can be attributed.
//!
//! Behind a reverse proxy the TCP peer is the proxy, so the real address has to
//! come from a header — and a header is written by whoever is upstream, which
//! includes the client. `X-Forwarded-For` is *appended* to at each hop, so a
//! client that sends `X-Forwarded-For: 10.0.0.1` arrives at Rustberg as
//! `10.0.0.1, <real client>`. Reading the **leftmost** entry therefore reads
//! the one value the attacker chose: it would let any caller claim to be inside
//! the VPC, and give every request a distinct rate-limit bucket.
//!
//! # The rule
//!
//! The forwarding chain is `X-Forwarded-For` left to right, with the TCP peer
//! appended as the final, unforgeable hop. Walk it from the **right**, skipping
//! addresses that belong to a proxy this deployment trusts. The first address
//! that is not a trusted proxy is the client: everything to its left it could
//! have written itself, and everything to its right is infrastructure that
//! appended honestly.
//!
//! With no trusted proxies configured — the default — the chain is one entry
//! long and the answer is always the TCP peer. Headers are not read at all,
//! which is the only correct behaviour for a server exposed directly.
//!
//! # Why a CIDR list rather than a boolean
//!
//! A boolean has no way to express *which* hop to believe, so it can only mean
//! "read the leftmost", which is the spoofable answer above. Naming the proxies
//! is what makes the trust decision checkable, and it is information the
//! operator already has: it is the same subnet the load balancer runs in.
//!
//! A hop count would also work and is one number shorter, but it is wrong the
//! moment a request arrives by a second path — a health checker, a service-mesh
//! sidecar, an internal caller bypassing the load balancer — and it fails
//! *open*, attributing the request to whatever the chain happens to hold at
//! that offset.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{AppError, Result};

/// Request header carrying the forwarding chain.
pub const X_FORWARDED_FOR: &str = "x-forwarded-for";

/// Request header some proxies use to name the client directly.
pub const X_REAL_IP: &str = "x-real-ip";

/// An address range, in `addr/prefix` form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Parses `addr/prefix`, or a bare address meaning a single host.
    ///
    /// # Errors
    ///
    /// [`AppError::Internal`] naming the value, because this is read from
    /// configuration at startup and a range nobody can parse must not silently
    /// become a range that matches nothing.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        let (addr, prefix) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };

        let network: IpAddr = addr.parse().map_err(|_| {
            AppError::Internal(format!(
                "'{value}' is not a trusted-proxy range: expected an address, optionally \
                 followed by '/' and a prefix length (for example '10.0.0.0/8')."
            ))
        })?;

        let width = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => width,
            Some(text) => text
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= width)
                .ok_or_else(|| {
                    AppError::Internal(format!(
                        "'{value}' is not a trusted-proxy range: the prefix length must be a \
                         number between 0 and {width}."
                    ))
                })?,
        };

        Ok(Self { network, prefix })
    }

    /// Whether `candidate` falls inside this range.
    ///
    /// An IPv4-mapped IPv6 address is compared as the IPv4 address it carries.
    /// A proxy that connects over a dual-stack socket arrives as
    /// `::ffff:10.0.0.1`, and an operator who wrote `10.0.0.0/8` means that
    /// host — treating the two as unrelated would silently stop trusting the
    /// proxy the moment the listener bound to `[::]`.
    pub fn contains(&self, candidate: IpAddr) -> bool {
        match (self.network, normalize(candidate)) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                matches_prefix(&network.octets(), &candidate.octets(), self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                matches_prefix(&network.octets(), &candidate.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

/// Unwraps an IPv4-mapped IPv6 address to the IPv4 address it carries.
fn normalize(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Whether two addresses agree on their first `prefix` bits.
fn matches_prefix(network: &[u8], candidate: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    if network[..whole] != candidate[..whole] {
        return false;
    }
    let remainder = prefix % 8;
    if remainder == 0 {
        return true;
    }
    // `remainder` is 1..=7 here, so the shift is in range and the mask keeps the
    // high bits that the prefix covers.
    let mask = 0xFFu8 << (8 - remainder);
    network[whole] & mask == candidate[whole] & mask
}

/// How this deployment decides which address a request came from.
#[derive(Debug, Clone, Default)]
pub struct RemoteIp {
    /// Ranges whose addresses are infrastructure rather than callers. Empty
    /// means headers are not consulted at all.
    trusted: Vec<Cidr>,
}

impl RemoteIp {
    /// The default: no proxy is trusted, so only the TCP peer is ever reported.
    pub fn direct() -> Self {
        Self::default()
    }

    /// Trusts the given ranges as forwarding infrastructure.
    ///
    /// # Errors
    ///
    /// [`AppError::Internal`] for a range that does not parse. A trusted-proxy
    /// list that silently dropped an entry would make Rustberg attribute every
    /// request to that proxy's own address, which looks like working software.
    pub fn behind<I, S>(ranges: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Ok(Self {
            trusted: ranges
                .into_iter()
                .map(|range| Cidr::parse(range.as_ref()))
                .collect::<Result<Vec<_>>>()?,
        })
    }

    /// Whether any proxy is trusted, and therefore whether headers are read.
    pub fn trusts_any_proxy(&self) -> bool {
        !self.trusted.is_empty()
    }

    /// The caller's address.
    ///
    /// `forwarded` is every `X-Forwarded-For` value on the request, in the order
    /// they arrived; each may itself be a comma-separated list. `real_ip` is the
    /// `X-Real-IP` header, used only when the peer is a trusted proxy and no
    /// forwarding chain was sent. `peer` is the TCP source address, which is the
    /// only entry nobody can forge.
    ///
    /// Returns `None` when there is no peer — an in-process call through the
    /// library, where there is no connection to describe — and when the hop that
    /// *is* the client cannot be read: a proxy is free to obfuscate one, and
    /// inventing an address for it would put a fiction in the audit trail and
    /// hand an attacker a way to be attributed to somebody else.
    pub fn resolve(
        &self,
        peer: Option<IpAddr>,
        forwarded: &[&str],
        real_ip: Option<&str>,
    ) -> Option<IpAddr> {
        // Without a trusted proxy the peer is the whole story, and a header is
        // just something a stranger wrote.
        if self.trusted.is_empty() {
            return peer;
        }

        let peer = peer?;

        // An entry that does not parse stays in the chain as `None` rather than
        // being dropped. Dropping it looks harmless and is not: the walk below
        // stops at the first hop that is not a trusted proxy, and a hop it
        // cannot read is exactly such a hop. Removing it lets the walk continue
        // *past* the position of the real client and settle on whatever the
        // client itself wrote further left.
        //
        // RFC 7239 lets a proxy write `unknown` or an obfuscated identifier for
        // a hop it does not wish to disclose, so this is a shape a correctly
        // configured deployment produces — and the honest answer for it is "the
        // client's address is not knowable", never "the client is whoever
        // claimed to be".
        let mut chain: Vec<Option<IpAddr>> = forwarded
            .iter()
            .flat_map(|value| value.split(','))
            .map(|entry| parse_forwarded_entry(entry.trim()))
            .collect();

        if chain.is_empty()
            && let Some(claimed) = real_ip.and_then(|value| parse_forwarded_entry(value.trim()))
            && self.is_trusted(peer)
        {
            // Nginx-style: one hop, one header, no chain to walk. Believed only
            // because the peer that wrote it is trusted.
            return Some(claimed);
        }

        // The unforgeable hop goes on the end, so a chain of nothing but trusted
        // proxies still resolves to something real.
        chain.push(Some(peer));

        chain
            .iter()
            .rposition(|address| !address.is_some_and(|address| self.is_trusted(address)))
            .map_or_else(
                // Every hop is a trusted proxy, including the peer. The client
                // is then whatever the outermost proxy recorded.
                || chain.first().copied().flatten(),
                // The first non-infrastructure hop from the right. `None` there
                // is a hop this cannot read, and the answer is that the address
                // is unknown — a policy guarded with `context has source_ip`
                // then does not apply, which is the deny-by-default direction.
                |index| chain[index],
            )
    }

    fn is_trusted(&self, address: IpAddr) -> bool {
        self.trusted.iter().any(|range| range.contains(address))
    }
}

/// Reads one forwarding-chain entry.
///
/// Handles the bracketed-with-port form (`[2001:db8::1]:443`) and the
/// address-with-port form (`10.0.0.1:443`) that some proxies emit, and refuses
/// the obfuscated identifiers RFC 7239 permits (`_hidden`, `unknown`) rather
/// than inventing an address for them.
fn parse_forwarded_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(address) = entry.parse::<IpAddr>() {
        return Some(normalize(address));
    }

    // `[v6]:port`
    if let Some(rest) = entry.strip_prefix('[')
        && let Some((inner, _)) = rest.split_once(']')
    {
        return inner
            .parse::<Ipv6Addr>()
            .ok()
            .map(IpAddr::V6)
            .map(normalize);
    }

    // `v4:port` — only when there is exactly one colon, so a bare IPv6 address
    // is never mistaken for one.
    if entry.matches(':').count() == 1
        && let Some((address, _)) = entry.split_once(':')
    {
        return address.parse::<Ipv4Addr>().ok().map(IpAddr::V4);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("test address")
    }

    fn behind(ranges: &[&str]) -> RemoteIp {
        RemoteIp::behind(ranges).expect("test ranges")
    }

    // ── CIDR ────────────────────────────────────────────────────────────

    #[test]
    fn a_range_contains_its_own_members() {
        let range = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(range.contains(ip("10.1.2.3")));
        assert!(range.contains(ip("10.0.0.0")));
        assert!(!range.contains(ip("11.0.0.1")));
        assert!(!range.contains(ip("9.255.255.255")));
    }

    #[test]
    fn a_prefix_that_is_not_a_whole_byte_is_respected() {
        let range = Cidr::parse("192.168.16.0/20").unwrap();
        assert!(range.contains(ip("192.168.16.1")));
        assert!(range.contains(ip("192.168.31.255")));
        assert!(!range.contains(ip("192.168.32.0")));
        assert!(!range.contains(ip("192.168.15.255")));
    }

    #[test]
    fn a_bare_address_is_a_single_host() {
        let range = Cidr::parse("203.0.113.7").unwrap();
        assert!(range.contains(ip("203.0.113.7")));
        assert!(!range.contains(ip("203.0.113.8")));
    }

    #[test]
    fn ipv6_ranges_work_too() {
        let range = Cidr::parse("2001:db8::/32").unwrap();
        assert!(range.contains(ip("2001:db8:1234::1")));
        assert!(!range.contains(ip("2001:db9::1")));
    }

    /// A dual-stack listener reports an IPv4 peer as `::ffff:a.b.c.d`. An
    /// operator who wrote `10.0.0.0/8` means that host either way.
    #[test]
    fn a_mapped_address_matches_its_ipv4_range() {
        let range = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(range.contains(ip("::ffff:10.1.2.3")));
    }

    #[test]
    fn a_zero_prefix_matches_its_whole_family() {
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(
            !Cidr::parse("0.0.0.0/0")
                .unwrap()
                .contains(ip("2001:db8::1"))
        );
    }

    #[test]
    fn an_unparseable_range_is_a_startup_error() {
        assert!(Cidr::parse("not-an-address").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("10.0.0.0/x").is_err());
        assert!(RemoteIp::behind(["10.0.0.0/8", "nonsense"]).is_err());
    }

    // ── Resolution ──────────────────────────────────────────────────────

    /// The default. A header from a stranger decides nothing.
    #[test]
    fn without_trusted_proxies_only_the_peer_counts() {
        let resolver = RemoteIp::direct();
        assert_eq!(
            resolver.resolve(Some(ip("203.0.113.9")), &["10.0.0.1"], Some("10.0.0.2")),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn one_trusted_proxy_reveals_the_client_behind_it() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("10.0.0.7")), &["203.0.113.9"], None),
            Some(ip("203.0.113.9"))
        );
    }

    /// The attack this module exists to stop: the client writes the header, the
    /// proxy appends the truth, and reading left to right believes the client.
    #[test]
    fn a_client_cannot_prepend_an_address_it_chose() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(
                Some(ip("10.0.0.7")),
                &["10.9.9.9, 203.0.113.9"],
                Some("10.9.9.9"),
            ),
            Some(ip("203.0.113.9")),
            "the spoofed hop is to the left of the real one and must be ignored"
        );
    }

    #[test]
    fn several_trusted_hops_are_walked_through() {
        let resolver = behind(&["10.0.0.0/8", "192.168.0.0/16"]);
        assert_eq!(
            resolver.resolve(
                Some(ip("192.168.1.1")),
                &["203.0.113.9, 10.0.0.4, 10.0.0.5"],
                None,
            ),
            Some(ip("203.0.113.9"))
        );
    }

    /// A list header may arrive split across repeated lines.
    #[test]
    fn repeated_headers_form_one_chain() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("10.0.0.7")), &["203.0.113.9", "10.0.0.6"], None),
            Some(ip("203.0.113.9"))
        );
    }

    /// Nothing but infrastructure in the chain: the outermost recorded hop is
    /// the best answer available, and it is a real address rather than `None`.
    #[test]
    fn an_all_trusted_chain_falls_back_to_the_outermost_hop() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("10.0.0.7")), &["10.0.0.3, 10.0.0.4"], None),
            Some(ip("10.0.0.3"))
        );
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_it_sent() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("203.0.113.9")), &["198.51.100.1"], None),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn x_real_ip_is_believed_only_from_a_trusted_peer() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("10.0.0.7")), &[], Some("203.0.113.9")),
            Some(ip("203.0.113.9"))
        );
        assert_eq!(
            resolver.resolve(Some(ip("198.51.100.4")), &[], Some("203.0.113.9")),
            Some(ip("198.51.100.4")),
            "an untrusted peer does not get to rename itself"
        );
    }

    #[test]
    fn a_forwarding_chain_wins_over_x_real_ip() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("10.0.0.7")), &["203.0.113.9"], Some("198.51.100.1")),
            Some(ip("203.0.113.9"))
        );
    }

    #[test]
    fn an_in_process_call_has_no_address() {
        assert_eq!(RemoteIp::direct().resolve(None, &[], None), None);
        assert_eq!(
            behind(&["10.0.0.0/8"]).resolve(None, &["203.0.113.9"], None),
            None
        );
    }

    // ── Entry parsing ───────────────────────────────────────────────────

    #[test]
    fn entries_may_carry_a_port() {
        assert_eq!(parse_forwarded_entry("10.0.0.1:4711"), Some(ip("10.0.0.1")));
        assert_eq!(
            parse_forwarded_entry("[2001:db8::1]:4711"),
            Some(ip("2001:db8::1"))
        );
        assert_eq!(
            parse_forwarded_entry("2001:db8::1"),
            Some(ip("2001:db8::1"))
        );
    }

    /// RFC 7239 lets a proxy hide a hop. Inventing an address for one would put
    /// a fiction in the audit trail.
    #[test]
    fn obfuscated_entries_are_dropped() {
        assert_eq!(parse_forwarded_entry("unknown"), None);
        assert_eq!(parse_forwarded_entry("_hidden"), None);
        assert_eq!(parse_forwarded_entry(""), None);
    }

    /// An entry to the *left* of the client is irrelevant, readable or not: the
    /// walk stops before reaching it.
    #[test]
    fn an_unreadable_entry_left_of_the_client_changes_nothing() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("10.0.0.7")), &["unknown, 203.0.113.9"], None),
            Some(ip("203.0.113.9"))
        );
    }

    /// `unknown` is the client's own hop — RFC 7239 lets a proxy obfuscate one —
    /// and the leftmost entry is whatever the client itself sent. Dropping the
    /// unreadable entry would let the walk continue past the real position and
    /// land on the forged one.
    #[test]
    fn an_unreadable_client_hop_is_not_skipped_over() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(
                Some(ip("10.0.0.7")),
                &["203.0.113.1, unknown, 10.0.0.4"],
                None,
            ),
            None,
            "the client's own hop is unreadable, so the address is unknown — never \
             the address the client picked"
        );
    }

    /// An unknown address is not a permitted one. A policy conditioned on
    /// `context.source_ip` guards with `context has source_ip`, so `None` fails
    /// that guard rather than satisfying it.
    #[test]
    fn a_trailing_unreadable_entry_is_the_client_and_is_unknown() {
        let resolver = behind(&["10.0.0.0/8"]);
        assert_eq!(
            resolver.resolve(Some(ip("10.0.0.7")), &["203.0.113.9, unknown"], None),
            None
        );
    }
}
