//! Intranet zero-egress guard.
//!
//! This module is the single authority for "may this process talk to that address".
//! Upstream RustDesk 1.5.0 has no egress funnel: `socket_client`, raw `tokio`/`std` sockets, HTTP
//! clients and the Dart side are independent stacks, and the target addresses are writable by the
//! remote peer while the persisted config has no integrity protection. So the decision is taken
//! here, at connect/send time, never from the UI or from a remote message.
//!
//! The allow-list is the one operator-supplied input: `intranet-allowlist.conf` next to the app
//! config, re-read at startup. It can only contain private IPv4 space; public entries are refused
//! and audited, so configuring a deployment cannot re-open the internet.
//!
//! Security properties:
//! - default-deny: unlisted addresses are refused, in both directions, with an audit line
//! - one guard for every socket, deny + audit, no retry, no fallback path
//! - server-shaped options are pinned to safe values in `FORCED_OPTIONS` and cannot be widened
//!   by the config file, the UI or a remote peer
//!
//! No new dependencies: CIDR matching is done by hand on `std::net` types.
//!
//! This file is part of a modified RustDesk fork and is distributed under AGPL-3.0; see the
//! repository `LICENCE` and `NOTICE` for the upstream copyright and the list of modifications.

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::ResultType;

/// The user's intranet allow-list, read at startup from this file under the app config directory
/// (e.g. `%APPDATA%\RustDesk\config\intranet-allowlist.conf` on Windows).
///
/// The list is supplied by the operator, not compiled in: deployments differ, and a fork that
/// hardcodes one site's subnet is both unusable elsewhere and leaks that site's layout. The file
/// may only widen the guard inside private IPv4 space (RFC1918, `100.64/10`, `169.254/16`) -
/// a public entry is refused and audited, so "configure your own range" can never turn this build
/// back into an internet client.
///
/// Format: one host (`a.b.c.d`) or CIDR (`a.b.c.d/len`) per line; `#` starts a comment. The file
/// is re-read on every start (`init_allowlist`), not on every packet.
pub const ALLOWLIST_FILE: &str = "intranet-allowlist.conf";

/// Parsed allow-list behind a read-mostly lock. Empty until `init_allowlist` runs; an empty list
/// means nothing is reachable except `127.0.0.1`, which is the safe default.
static ALLOWED_V4_CIDRS: OnceLock<RwLock<Vec<CidrV4>>> = OnceLock::new();

fn allowlist_store() -> &'static RwLock<Vec<CidrV4>> {
    ALLOWED_V4_CIDRS.get_or_init(|| RwLock::new(Vec::new()))
}

/// Fixed test list. Every test that consults `ip_allowed` installs the same list so the tests can
/// run in parallel without fighting over the process-wide store.
#[cfg(test)]
fn set_allowlist_for_test() {
    let mut list = Vec::new();
    for entry in ["10.20.30.0/24", "172.20.0.0/16"] {
        list.push(parse_allowlist_entry(entry).expect(entry));
    }
    *allowlist_store()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = list;
}

/// Current allow-list, for diagnostics.
pub fn allowed_cidrs() -> Vec<CidrV4> {
    let guard = allowlist_store()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

pub fn allowlist_path() -> PathBuf {
    Config::path(ALLOWLIST_FILE)
}

const ALLOWLIST_TEMPLATE: &str = "\
# Intranet-only allow-list. One IPv4 host (a.b.c.d) or CIDR (a.b.c.d/len) per line.
# Only private space is accepted: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
# 100.64.0.0/10 (CGNAT) and 169.254.0.0/16 (link-local). Public addresses are refused.
# 127.0.0.1 is always reachable for local IPC and does not need an entry.
#
# Examples (remove the leading '# ' to activate, and replace with your own ranges):
# 192.168.10.0/24
# 10.20.30.15
";

/// Load the allow-list. Called once from `global_init` before the self-check.
///
/// A missing file is created from `ALLOWLIST_TEMPLATE` (all examples commented out), so the
/// operator has something to edit; a missing file therefore means "only loopback", not "allow
/// everything". [`store_allowlist_text`] is the other way in - the settings page uses it and does
/// not need a restart.
pub fn init_allowlist() {
    let path = allowlist_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(&path, ALLOWLIST_TEMPLATE) {
                crate::log::error!("netguard: cannot create allow-list template {:?}: {}", path, e);
            }
            ALLOWLIST_TEMPLATE.to_owned()
        }
        Err(e) => {
            crate::log::error!("netguard: cannot read allow-list {:?}: {}", path, e);
            String::new()
        }
    };

    let count = install_allowlist(allowlist_from_text(&text, "netguard::init_allowlist").0);
    if count == 0 {
        crate::log::warn!(
            "netguard: allow-list is empty ({}); only 127.0.0.1 is reachable. Add your intranet ranges, one per line.",
            path.display()
        );
    } else {
        crate::log::info!(
            "netguard: allow-list loaded from {:?}: {} entr{}",
            path,
            count,
            if count == 1 { "y" } else { "ies" }
        );
    }
}

/// The allow-list as the operator would edit it: the file verbatim, or the commented template when
/// the file is not there yet. The settings page starts from this so the explanatory comments - and
/// anything else the operator keeps in that file - are never silently dropped.
pub fn allowlist_text() -> String {
    match std::fs::read_to_string(allowlist_path()) {
        Ok(text) => text,
        Err(_) => ALLOWLIST_TEMPLATE.to_owned(),
    }
}

/// Validate, write and make live in this process. Returns how many entries the guard now enforces.
///
/// One refused line refuses the whole write, on purpose. A card that saved `8.8.8.0/24` alongside a
/// good range and then reported "1 of 2 entries loaded" would leave the operator believing the
/// public range was allowed; here the edit simply fails and says which line, so the file on disk and
/// the list in memory cannot disagree.
pub fn store_allowlist_text(text: &str) -> ResultType<usize> {
    let (list, rejected) = allowlist_from_text(text, "netguard::store_allowlist_text");
    if !rejected.is_empty() {
        return Err(anyhow::anyhow!(
            "refused: {}",
            rejected.join("; ")
        ));
    }
    let path = allowlist_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("netguard: cannot create {:?}: {}", parent, e))?;
    }
    std::fs::write(&path, text)
        .map_err(|e| anyhow::anyhow!("netguard: cannot write {:?}: {}", path, e))?;
    let count = install_allowlist(list);
    crate::log::info!(
        "netguard: allow-list edited through the UI, {} entr{} now enforced ({})",
        count,
        if count == 1 { "y" } else { "ies" },
        path.display()
    );
    Ok(count)
}

/// Parse every non-comment line, auditing the ones the guard refuses. Returns the accepted list and
/// the refused lines with their `reason=` for the caller to show.
///
/// Split out from [`init_allowlist`] and [`store_allowlist_text`] so the refusal rules are testable
/// without touching the config directory.
fn allowlist_from_text(text: &str, ctx: &str) -> (Vec<CidrV4>, Vec<String>) {
    let mut list = Vec::new();
    let mut rejected = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match parse_allowlist_entry(line) {
            Ok(cidr) => list.push(cidr),
            Err(reason) => {
                audit_denied("local", line, ctx, reason);
                rejected.push(format!("{} ({})", line, reason));
            }
        }
    }
    list.sort_by_key(|c| (c.base(), c.prefix));
    list.dedup();
    (list, rejected)
}

/// Swap the parsed list into the process-wide store and report how many entries it holds.
fn install_allowlist(list: Vec<CidrV4>) -> usize {
    let count = list.len();
    let mut guard = allowlist_store()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = list;
    count
}

/// One line of the allow-list. Refusals carry the audit `reason=`.
fn parse_allowlist_entry(line: &str) -> Result<CidrV4, &'static str> {
    let (host, prefix) = match line.split_once('/') {
        Some((host, prefix)) => {
            let prefix: u8 = prefix
                .trim()
                .parse()
                .map_err(|_| "reason=allowlist_bad_prefix")?;
            if prefix > 32 {
                return Err("reason=allowlist_bad_prefix");
            }
            (host.trim(), prefix)
        }
        None => (line, 32),
    };
    let ip = Ipv4Addr::from_str(host).map_err(|_| "reason=allowlist_not_literal_ipv4")?;
    let cidr = CidrV4::new(ip.octets(), prefix);
    if !is_private_intranet(cidr.base(), prefix) {
        return Err("reason=allowlist_not_private_space");
    }
    Ok(cidr)
}

/// Whether `base/prefix` sits entirely inside private space. Public, loopback, multicast and
/// broadcast ranges are excluded; loopback is handled separately by `ALLOW_LOOPBACK_V4_1`.
fn is_private_intranet(base: u32, prefix: u8) -> bool {
    for (net, block) in [
        (u32::from(Ipv4Addr::new(10, 0, 0, 0)), 8u8),
        (u32::from(Ipv4Addr::new(172, 16, 0, 0)), 12),
        (u32::from(Ipv4Addr::new(192, 168, 0, 0)), 16),
        (u32::from(Ipv4Addr::new(100, 64, 0, 0)), 10),
        (u32::from(Ipv4Addr::new(169, 254, 0, 0)), 16),
    ] {
        if prefix >= block {
            let mask = if block == 32 {
                u32::MAX
            } else {
                (!0u32) << (32 - block)
            };
            if base & mask == net {
                return true;
            }
        }
    }
    false
}

/// The allow-list is written as host ranges (`x.x.x.1 ~ x.x.x.254` in the original requirement),
/// so the network address and the broadcast address of a CIDR are NOT hosts: plain
/// `IpCidr::contains` would be one address too wide at both ends.
pub const EXCLUDE_NETWORK_AND_BROADCAST_HOSTS: bool = true;

/// Loopback: only `127.0.0.1`, for the process' own local IPC/forwarding listeners
/// (e.g. `src/port_forward.rs:84`). The rest of `127.0.0.0/8` and all of `::1` stay denied.
pub const ALLOW_LOOPBACK_V4_1: bool = true;

/// Whether two hosts inside the same allow-list network may talk to each other. Kept `true`:
/// a subnet is one site, and requiring every pair to cross CIDR boundaries would break ordinary
/// peer-to-peer use inside a single /24.
pub const ALLOW_SAME_CIDR_PAIR: bool = true;

/// Everything the guard refuses, per process lifetime. Surfaced for the acceptance report.
pub static DENIED_COUNT: AtomicU64 = AtomicU64::new(0);
/// Everything the guard allowed. Counting only — the allow path performs no file IO by design,
/// so a connection storm cannot turn the audit into a disk bottleneck.
pub static ALLOWED_COUNT: AtomicU64 = AtomicU64::new(0);

/// Audit lines per destination address, at most one per this interval.
const AUDIT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidrV4 {
    octets: [u8; 4],
    prefix: u8,
}

impl CidrV4 {
    pub const fn new(octets: [u8; 4], prefix: u8) -> Self {
        CidrV4 { octets, prefix }
    }

    const fn mask(&self) -> u32 {
        if self.prefix == 0 {
            0
        } else if self.prefix >= 32 {
            u32::MAX
        } else {
            (!0u32) << (32 - self.prefix)
        }
    }

    fn base(&self) -> u32 {
        u32::from_be_bytes(self.octets) & self.mask()
    }

    /// Is `ip` a usable host of this network (see `EXCLUDE_NETWORK_AND_BROADCAST_HOSTS`)?
    pub fn contains_host(&self, ip: Ipv4Addr) -> bool {
        let bits = u32::from(ip);
        if bits & self.mask() != self.base() {
            return false;
        }
        if EXCLUDE_NETWORK_AND_BROADCAST_HOSTS && self.prefix < 31 {
            let host_bits = bits & !self.mask();
            if host_bits == 0 || host_bits == !self.mask() {
                return false;
            }
        }
        true
    }
}

/// Strict `::ffff:a.b.c.d` unwrapping, on purpose narrower than the deprecated
/// `Ipv6Addr::to_ipv4()`: that one also maps 6to4 (`2002:x.x.x.x::/48`), so
/// `2002:x.x.x.x::/48` would read as a private IPv4 address and a v6 packet would leave through a
/// 6to4 relay while the guard believed it was talking to an allow-listed host.
fn ipv4_mapped(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let seg = v6.segments();
    if seg[0] == 0
        && seg[1] == 0
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0xffff
    {
        Some(Ipv4Addr::new(
            (seg[6] >> 8) as u8,
            (seg[6] & 0xff) as u8,
            (seg[7] >> 8) as u8,
            (seg[7] & 0xff) as u8,
        ))
    } else {
        None
    }
}

/// The one predicate everything else is built on. Default-deny: anything not listed by the
/// operator — public space, unlisted private ranges, link-local, multicast, `255.255.255.255`,
/// `::1`, `fe80::/10` — is refused.
pub fn ip_allowed(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => match ipv4_mapped(v6) {
            Some(v4) => IpAddr::V4(v4),
            None => return false,
        },
        other => other,
    };
    match ip {
        IpAddr::V4(v4) => {
            if ALLOW_LOOPBACK_V4_1 && v4 == Ipv4Addr::LOCALHOST {
                return true;
            }
            let guard = allowlist_store()
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.iter().any(|c| c.contains_host(v4))
        }
        // Only IPv4 is allow-listed; a non-mapped IPv6 is always refused.
        IpAddr::V6(_) => false,
    }
}

/// `ALLOW_SAME_CIDR_PAIR == false` needs to know both ends, so this takes the local address too.
/// An unspecified local address (`0.0.0.0:0`, the usual case before bind) cannot be classified,
/// and then the pair rule is not applied — the destination is still checked.
pub fn pair_allowed(local: Option<IpAddr>, peer: IpAddr) -> bool {
    if !ip_allowed(peer) {
        return false;
    }
    if ALLOW_SAME_CIDR_PAIR {
        return true;
    }
    match local {
        Some(l) if ip_allowed(l) => cidr_index_of(l) != cidr_index_of(peer),
        _ => true,
    }
}

/// Which allow-list entry hosts `ip`; `None` for loopback or anything outside.
pub fn cidr_index_of(ip: IpAddr) -> Option<usize> {
    let v4 = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => ipv4_mapped(v6)?,
    };
    let guard = allowlist_store()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.iter().position(|c| c.contains_host(v4))
}

/// Predicate for `SettingEngine::set_ip_filter`, which `webrtc.rs:645-648` already installs but
/// currently sets to `IpAddr::V4(_) => true` — i.e. it only excludes link-local IPv6, so a VPN or
/// public interface is gathered as an ICE candidate. Binding a candidate on such an interface is
/// itself a public-facing act (the socket is announced to the peer and probed), so gathering must
/// be limited to interfaces whose own address sits inside the allow-list.
///
/// Note this is about *local* interface addresses; remote destinations are covered by
/// `ip_allowed` on the connect/send path.
pub fn local_interface_allowed(ip: IpAddr) -> bool {
    match ip {
        // Never gather on loopback: it is allowed as a peer for local IPC, not as an ICE candidate.
        IpAddr::V4(v4) if v4 == Ipv4Addr::LOCALHOST => false,
        other => ip_allowed(other),
    }
}

fn deny(direction: &str, ctx: &str, target: String, peer_note: &str) -> anyhow::Error {
    DENIED_COUNT.fetch_add(1, Ordering::Relaxed);
    audit_denied(direction, &target, ctx, peer_note);
    anyhow::anyhow!(
        "netguard: denied {} {} ({})",
        direction,
        target,
        if ctx.is_empty() { "unknown site" } else { ctx }
    )
}

/// Outbound: may we open a connection towards `addr`?
pub fn check_outbound_addr(addr: SocketAddr, ctx: &str) -> ResultType<()> {
    check_outbound_ip(addr.ip(), ctx, &addr.to_string())
}

pub fn check_outbound_ip(ip: IpAddr, ctx: &str, note: &str) -> ResultType<()> {
    if ip_allowed(ip) {
        ALLOWED_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(())
    } else {
        Err(deny("outbound", ctx, note.to_owned(), &ip_note(ip)))
    }
}

/// Outbound with the strict pair rule (`ALLOW_SAME_CIDR_PAIR == false`).
pub fn check_outbound_pair(
    local: Option<SocketAddr>,
    peer: SocketAddr,
    ctx: &str,
) -> ResultType<()> {
    if pair_allowed(local.map(|a| a.ip()), peer.ip()) {
        ALLOWED_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(())
    } else {
        Err(deny("outbound", ctx, peer.to_string(), &ip_note(peer.ip())))
    }
}

/// Inbound: a peer has just connected (TCP accept) or sent a datagram. Refusing here means
/// closing without any protocol-level reply, so the handshake never starts.
pub fn check_inbound_ip(ip: IpAddr, ctx: &str) -> ResultType<()> {
    if ip_allowed(ip) {
        ALLOWED_COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(())
    } else {
        Err(deny("inbound", ctx, ip.to_string(), &ip_note(ip)))
    }
}

pub fn check_inbound_addr(addr: SocketAddr, ctx: &str) -> ResultType<()> {
    check_inbound_ip(addr.ip(), ctx)
}

fn ip_note(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => "reason=not_in_allowlist".to_owned(),
        IpAddr::V6(v6) => {
            if ipv4_mapped(v6).is_some() {
                "reason=ipv4_mapped_out_of_allowlist".to_owned()
            } else {
                "reason=ipv6_not_allowlisted".to_owned()
            }
        }
    }
}

/// DNS containment (§二.1 "任何形式的公网 DNS 解析"): the allow-list is IP-only, so a target that
/// is not already a literal address has no legitimate use. Resolve it as a literal or refuse —
/// never hand the string to `lookup_host`/`to_socket_addrs`, because the query leaves before any
/// post-resolution check could run (`socket_client.rs:86/190/210/220`, `tcp.rs:124/261`,
/// `udp.rs:58`, `proxy.rs:203/242`).
pub fn parse_literal(target: &str, default_port: u16, ctx: &str) -> ResultType<SocketAddr> {
    if let Ok(addr) = SocketAddr::from_str(target) {
        check_outbound_addr(addr, ctx)?;
        return Ok(addr);
    }
    // "a.b.c.d" without a port is still a literal host.
    if let Ok(v4) = Ipv4Addr::from_str(target) {
        let addr = SocketAddr::new(IpAddr::V4(v4), default_port);
        check_outbound_addr(addr, ctx)?;
        return Ok(addr);
    }
    if let Ok(v6) = Ipv6Addr::from_str(target) {
        let addr = SocketAddr::new(IpAddr::V6(v6), default_port);
        check_outbound_addr(addr, ctx)?;
        return Ok(addr);
    }
    Err(deny(
        "outbound",
        ctx,
        format!("{} (name form, default port {})", target, default_port),
        "reason=dns_forbidden",
    ))
}

/// Same rule for a `host:port` string whose host part must be a literal.
pub fn parse_literal_with_port(target: &str, ctx: &str) -> ResultType<SocketAddr> {
    match parse_split_host_port(target) {
        Some((host, port)) => parse_literal(&host, port, ctx).map(|a| {
            SocketAddr::new(a.ip(), if port == 0 { a.port() } else { port })
        }),
        None => Err(deny(
            "outbound",
            ctx,
            target.to_owned(),
            "reason=unparsable_target",
        )),
    }
}

/// `host` parsed as a literal address only — no resolver is consulted at any point.
fn literal_addr(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(addr) = SocketAddr::from_str(host) {
        return Some(addr);
    }
    if let Ok(v4) = Ipv4Addr::from_str(host) {
        return Some(SocketAddr::new(IpAddr::V4(v4), port));
    }
    if let Ok(v6) = Ipv6Addr::from_str(host) {
        return Some(SocketAddr::new(IpAddr::V6(v6), port));
    }
    None
}

/// Deny a target that is still in name form, auditing it first. Shared by the paths that hold a
/// `tokio_socks::TargetAddr` rather than a `SocketAddr` (`udp::FramedSocket::send`,
/// `proxy::Proxy::connect`): validating "after resolution" is not available to them, because the
/// resolver call *is* the egress (§5).
pub fn deny_name_form(target: &str, ctx: &str) -> anyhow::Error {
    audit_denied("outbound", target, ctx, "reason=dns_forbidden");
    anyhow::anyhow!(
        "netguard: denied outbound {} ({}, reason=dns_forbidden)",
        target,
        if ctx.is_empty() { "unknown site" } else { ctx }
    )
}

/// Local bind addresses (`tcp::new_listener`, `udp::FramedSocket::new`, `UdpSocket::bind`): the
/// allow-list says nothing about which of our own interfaces to listen on, so the only rule here is
/// "no name form" — binding must never reach the resolver (§二.1). Which *peer* is served is decided
/// at accept time by `check_inbound`; that is why `listen_any`'s wildcard bind is left in place (§4).
pub fn parse_bind_addr(target: &str, ctx: &str) -> ResultType<SocketAddr> {
    match parse_split_host_port(target) {
        Some((host, port)) => match literal_addr(&host, port) {
            Some(addr) => Ok(addr),
            None => Err(deny(
                "bind",
                ctx,
                target.to_owned(),
                "reason=dns_forbidden_for_bind",
            )),
        },
        None => Err(deny(
            "bind",
            ctx,
            target.to_owned(),
            "reason=unparsable_target",
        )),
    }
}

fn parse_split_host_port(target: &str) -> Option<(String, u16)> {
    let target = target.trim();
    if target.is_empty() {
        return None;
    }
    if target.starts_with('[') {
        let end = target.find(']')?;
        let host = target[1..end].to_owned();
        let rest = target[end + 1..].trim_start_matches(':');
        let port = if rest.is_empty() { 0 } else { rest.parse().ok()? };
        return Some((host, port));
    }
    let mut it = target.rsplitn(2, ':');
    let tail = it.next()?;
    match it.next() {
        Some(head) => {
            let port = tail.parse().ok()?;
            Some((head.to_owned(), port))
        }
        None => Some((target.to_owned(), 0)),
    }
}

/// The safe values for options that decide whether the client goes looking for a server.
/// Read through `crate::config::Config::get_option` and `LocalConfig::get_option` so a rewritten
/// `RustDesk2.toml` (which has no integrity protection: `config.rs:555-570` is a bare
/// `confy::load_path`), a heartbeat-delivered option (`src/hbbs_http/sync.rs:271-292`) or a UI edit
/// cannot change them. `custom.txt` IS signature-checked (`src/common.rs:2458-2470`), which is why
/// the server-shaped policy lives in these constants rather than in any file. The *allow-list* is
/// the one operator-supplied input, and it is constrained to private IPv4 by
/// `parse_allowlist_entry`.
///
/// `option2bool` (`config.rs:2826-2838`) treats `enable-*` and any unrecognised key as
/// "anything but `N` is on", so an empty value means ENABLED: every entry below states its value
/// explicitly on purpose.
pub const FORCED_OPTIONS: &[(&str, &str)] = &[
    ("enable-tcp-punch", "N"),
    ("enable-udp-punch", "N"),
    ("enable-ipv6-punch", "N"),
    ("enable-webrtc", "N"),
    ("allow-webrtc-congestion-control", "N"),
    ("force-always-relay", "N"),
    ("relay-server", ""),
    ("rendezvous-servers", ""),
    ("custom-rendezvous-server", ""),
    ("api-server", ""),
    ("key", ""),
    ("ice-servers", ""),
    ("allow-websocket", "N"),
    ("enable-check-update", "N"),
    ("allow-auto-update", "N"),
    ("register-device", "N"),
    ("enable-lan-discovery", "N"),
    ("proxy-url", ""),
    ("proxy-username", ""),
    ("proxy-password", ""),
    // Belt and braces: the inbound server-layer check (`src/server/connection.rs:1410`) keeps
    // working with the same value even though the real enforcement is `ip_allowed` above.
    // Upstream's own inbound whitelist is a second, weaker list (it never sees outbound connects
    // and would silently shadow the operator's allow-list). Keep it empty; netguard is the only
    // authority.
    ("whitelist", ""),
    // No per-ID gate: the operator's allow-listed segments are the boundary, and an empty id list is
    // what "any id from an allowed address" means. A stale non-empty value here would only break
    // legitimate peers.
    ("id-whitelist", ""),
    // 需求 §一「双向直连」的正向开关。`option2bool` treats `direct-server` as `== "Y"` (空值 = 关,
    // `config.rs:2842`), and it is the *only* thing that puts a listener on the direct port
    // (`src/direct_access.rs::direct_server`) - the port the controller dials when the user types a
    // peer's IP (`src/client.rs`, `check_port(peer, netguard::direct_peer_port())`). Left at its
    // default the build would refuse every inbound direct connection, so the requirement would fail
    // on its own happy path. Forced on, and not switchable from the UI or the config file
    // (`is_forced_key`).
    ("direct-server", "Y"),
    // Meaningless without a relay to fall back to (F1-F11); emptied so a leftover value cannot
    // look like a live knob in the file or the UI. Upstream read it as a hold-before-relay window -
    // see the note in `src/client.rs`'s `RELAY_FALLBACK_DELAY_MS`.
    ("relay-fallback-delay", ""),
    // 端口不再钉死（需求方要求「21118 不可用，端口要能自己指定」）。历史记录：上游把控制端写死成
    // `RELAY_PORT + 1`（`src/client.rs`），而被控端 `src/direct_access.rs::get_direct_port` 读这个
    // 选项，所以当年只有把它钉死为空（两侧都用默认值）才不会一侧重启、另一侧拨错端口。现在两侧都
    // 走下面的 `direct_peer_port()` 这一个函数，一致性由结构保证；端口号也开不了外联 - 目的地仍然
    // 只由 `intranet-allowlist.conf` 决定，改端口只是把 21118 这个数字换掉。写进文件的值由
    // `startup_self_check` 校验，非法值直接拒绝启动而不是静默回落。
    // netguard L4 (需求 §二.1): the Telegram bot credential (`bot`, an encrypted JSON blob holding a
    // Bot API token and a chat id). The type that read and wrote it (`auth_2fa::TelegramBot`) is
    // deleted in 步 6-B, so nothing consumes a leftover value any more - but pinning it empty + listing
    // it in `SERVER_SHAPED_KEYS` makes the startup purge delete the credential from
    // `RustDesk2.toml` instead of leaving a live-looking public-service secret on disk.
    ("bot", ""),
];

/// `Some(v)` means "this option is compiled to `v`; the stored value must be ignored".
pub fn force_option(key: &str) -> Option<String> {
    FORCED_OPTIONS
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| (*v).to_owned())
}

/// The one port the direct pair uses, in both directions.
///
/// Both halves of 需求 §一「双向直连」 call this and nothing else: the listener
/// (`src/direct_access.rs::get_direct_port`) and the controller's dial default
/// (`src/client.rs`, the `check_port(peer, …)` argument when the user typed a bare address). Upstream
/// had the listener read an option and the controller hardcode `RELAY_PORT + 1`, which is why the
/// option used to be pinned to the default - one knob could only move one side. With a single
/// source the operator can set `direct-access-port` to whatever the deployment's firewall allows
/// (需求方: 21118 不可用), and an empty / unset value keeps the historical 21118.
///
/// This is a *port* knob, not a *destination* knob: it cannot widen the guard, because every dial
/// still has to pass `check_outbound_pair` against `intranet-allowlist.conf`.
pub fn direct_peer_port() -> i32 {
    peer_port_from_option(&Config::get_option("direct-access-port"))
}

/// The port a deployment gets when it never sets `direct-access-port` - upstream's direct port,
/// which the docs and the settings-page hint name, and which `startup_self_check` keeps honest.
pub const DEFAULT_DIRECT_PEER_PORT: i32 = 21118;

/// The pure half of [`direct_peer_port`], so the fallback rule is testable without a config file.
fn peer_port_from_option(raw: &str) -> i32 {
    let fallback = crate::config::RENDEZVOUS_PORT + 2;
    match raw.trim().parse::<i32>() {
        Ok(port) if (1..=65535).contains(&port) => port,
        _ => fallback,
    }
}

/// Used by the `set_option` paths: a write to a forced key is dropped, not applied.
pub fn is_forced_key(key: &str) -> bool {
    FORCED_OPTIONS.iter().any(|(k, _)| *k == key)
}

/// Keys whose *value* would point the client at a server at all. They are also all in
/// `FORCED_OPTIONS`, so the guard already ignores them at read time - the reason they are listed
/// separately is the **on-disk purge** at startup (`Config::netguard_purge_policy_keys`, mounted from
/// `src/common.rs::global_init`): deleting the stale keys keeps the file, the log and the UI telling
/// the same story, so an incident review reading `RustDesk2.toml` does not mistake
/// `relay-server = "…"` for a live target.
pub const SERVER_SHAPED_KEYS: &[&str] = &[
    "rendezvous-servers",
    "custom-rendezvous-server",
    "relay-server",
    "api-server",
    "key",
    "ice-servers",
    "proxy-url",
    "proxy-username",
    "proxy-password",
    // L4 (步 6-B): a Telegram Bot API token + chat id - a public-service credential, and the only
    // thing that let the removed bot code address the Bot API. Purged so it does not survive
    // in the file as a dangling secret.
    "bot",
];

/// The purge predicate: everything the build decided for itself, plus anything that would name a
/// server. `direct-server` is in `FORCED_OPTIONS`, hence covered, which is exactly why the value can
/// no longer be turned off by whoever edits the file.
pub fn is_policy_key(key: &str) -> bool {
    is_forced_key(key) || SERVER_SHAPED_KEYS.contains(&key)
}

/// The single write-side refusal used by every store path - the two config files
/// (`Config::set_option`, `LocalConfig::set_option`, `LocalConfig::set_flutter_option`), the bulk
/// import (`Config::purify_options`), the whole-struct IPC replace (`Config2::set`), the Flutter/Sciter
/// UI mirrors (`src/ui_interface.rs`) and the per-peer config (`src/client.rs`, `src/ui_interface.rs`).
///
/// `Some(compiled_value)` means "this key is pinned: do not store the caller's value", and the attempt
/// is audited here so all refusal sites report the same way (`dir=local`, `target=key=value`,
/// `verdict=denied`, `reason=option_pinned_at_compile_time`). Requirement §二.7 asks that a tampered
/// option 「不生效」 *and* that refusals be auditable; keeping the check in one function is what makes
/// "no store path can bypass it" something a reader can verify instead of guess.
///
/// The audit line is only written when the attempted value actually *disagrees* with the compiled one.
/// The UI re-sends whole option maps - every pinned key in them, at exactly the value the policy
/// dictates - and a write that matches the policy is not a tampering attempt: reporting it would bury
/// the reports that matter. The caller still drops the key either way, so the resulting file is the
/// same whether or not anything was logged.
pub fn refuse_pinned_write(key: &str, value: &str, ctx: &str) -> Option<String> {
    let pinned = force_option(key)?;
    if pinned != value {
        audit_denied(
            "local",
            &format!("{}={}", key, value),
            ctx,
            &format!(
                "reason=option_pinned_at_compile_time compiled_value=\"{}\"",
                pinned
            ),
        );
    }
    Some(pinned)
}

/// Fail-fast sanity check on the compiled policy. Returns the problems found; an empty vec means
/// the policy is internally consistent.
///
/// The allow-list itself is operator-supplied and therefore not a failure: an empty list is a
/// valid (if useless) configuration, and `init_allowlist` has already rejected public entries.
/// What is checked here is that no rejection can be bypassed and that the pinned options still
/// describe a working direct-only build.
pub fn startup_self_check() -> Vec<String> {
    let mut problems = Vec::new();
    let cidrs = allowed_cidrs();
    for cidr in cidrs.iter() {
        if cidr.prefix > 32 {
            problems.push(format!("bad prefix {}", cidr.prefix));
        }
        if !is_private_intranet(cidr.base(), cidr.prefix) {
            problems.push(format!(
                "allow-list entry {}.{}.{}.{}/{} is not private space",
                cidr.octets[0], cidr.octets[1], cidr.octets[2], cidr.octets[3], cidr.prefix
            ));
        }
    }
    // Invariants the 步 5 enforcement layer is built on, checked instead of assumed:
    // 1. the startup purge deletes every `SERVER_SHAPED_KEYS` entry, so each of them must also have a
    //    compiled value - otherwise deleting it would change what the read side reports, i.e. the purge
    //    would become the tampering.
    for k in SERVER_SHAPED_KEYS.iter() {
        if !is_forced_key(k) {
            problems.push(format!(
                "{} is purged at startup but not pinned: reads would still honour the stored value",
                k
            ));
        }
    }
    // 2. `direct-server` is the one *positive* pin. Without it nothing listens on the direct port
    //    (`src/direct_access.rs::direct_server` is gated by it), so the requirement's 「双向直连」
    //    would fail on its happy path - a policy that lost the entry is broken by construction and must
    //    not start.
    if force_option("direct-server").as_deref() != Some("Y") {
        problems.push("direct-server is not pinned to \"Y\": no direct listener, inbound connections impossible".to_owned());
    }
    // 3. both halves of the direct port come from `direct_peer_port()`, so they cannot drift; what can
    //    still go wrong is the operator's own value. A non-empty `direct-access-port` that does not
    //    parse would silently fall back to 21118 on both sides - a working but *not the requested*
    //    port, which is the kind of thing that must not be swallowed. Refuse to start and say why.
    let stored_port = Config::get_option("direct-access-port");
    if !stored_port.trim().is_empty() && peer_port_from_option(&stored_port).to_string() != stored_port.trim() {
        problems.push(format!(
            "direct-access-port = {:?} is not a port number 1-65535; it would fall back to {} instead of the port you asked for",
            stored_port,
            crate::config::RENDEZVOUS_PORT + 2
        ));
    }
    // 3 continued: what an *unset* `direct-access-port` resolves to. The two halves can no longer drift
    //    (both call `direct_peer_port()`), so the old check that upstream's listener default still
    //    equalled its hardcoded controller default (`RELAY_PORT + 1`) is meaningless here - neither side
    //    reads `RELAY_PORT` any more. What still matters is the number a fresh deployment listens on,
    //    because that is what the docs, the settings page hint and the peer's firewall rule name. If the
    //    fallback ever stops being 21118, that is a documented-behaviour change and must be caught here
    //    rather than discovered on site.
    if crate::config::RENDEZVOUS_PORT + 2 != DEFAULT_DIRECT_PEER_PORT {
        problems.push(format!(
            "the unset direct port is {} but the documented default is {}",
            crate::config::RENDEZVOUS_PORT + 2,
            DEFAULT_DIRECT_PEER_PORT
        ));
    }
    // 4. `custom-rendezvous-server` pinned to "" is what the *non-option* server stores are gated on:
    //    `config::get_rendezvous_server{,s}` (`EXE_RENDEZVOUS_SERVER` from the executable's file name,
    //    `PROD_RENDEZVOUS_SERVER`, the plain-text `Config2.rendezvous_server` field) and
    //    `src/common.rs::get_custom_rendezvous_server` all short-circuit on `is_forced_key` of it,
    //    because those stores never pass `get_or`. Lose the entry and the license/exe-name route is open
    //    again - silently, since the read side otherwise still reports "".
    if force_option("custom-rendezvous-server").as_deref() != Some("")
        || !is_forced_key("custom-rendezvous-server")
    {
        problems.push(
            "custom-rendezvous-server is not pinned to \"\": the server-shaped stores outside the option table are no longer gated"
                .to_owned(),
        );
    }
    // The policy must never admit public space, whatever the operator wrote in the file: the
    // loader rejects such entries, and this catches a regression in the loader itself.
    for probe in [
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
    ]
    .iter()
    {
        if ip_allowed(*probe) {
            problems.push(format!("policy too wide: {} must be refused", probe));
        }
    }
    // Loopback is the one implicit entry (local IPC / port forwarding); losing it would break the
    // local paths without improving the guarantee.
    if !ip_allowed(IpAddr::V4(Ipv4Addr::LOCALHOST)) {
        problems.push("127.0.0.1 must stay allowed for local IPC".to_owned());
    }
    problems
}

struct AuditSlot {
    last: Instant,
    suppressed: u64,
}

fn audit_state() -> &'static Mutex<HashMap<String, AuditSlot>> {
    static STATE: OnceLock<Mutex<HashMap<String, AuditSlot>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether denials are also appended to the audit file. Always true in a real run.
static AUDIT_TO_FILE: AtomicBool = AtomicBool::new(true);

/// Test-only switch for the file sink. It is not wired to any option, environment variable or IPC
/// message: the requirement "审计日志" cannot be turned off from outside the process, and the
/// mirrored `log::warn!` line in `audit_denied` is emitted regardless.
#[cfg(test)]
fn set_audit_file(enabled: bool) {
    AUDIT_TO_FILE.store(enabled, Ordering::Relaxed);
}

/// Append one denial line to `<config_dir>/netguard-audit.log`, at most one per target per second,
/// carrying how many were folded into it. Also mirrored to the normal log.
///
/// Boundary (task book §三): the file is durable and cannot be switched off from inside the
/// process, but it is not protected against an administrator with write access to the disk.
pub fn audit_denied(direction: &str, target: &str, ctx: &str, reason: &str) {
    let line = due_to_write(target);
    let text = format!(
        "{} pid={} dir={} target={} ctx={} verdict=denied {}",
        now_stamp(),
        std::process::id(),
        direction,
        target,
        if ctx.is_empty() { "-" } else { ctx },
        reason
    );
    crate::log::warn!("{}", text);
    if !line || !AUDIT_TO_FILE.load(Ordering::Relaxed) {
        return;
    }
    let path = Config::path("netguard-audit.log");
    match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            if writeln!(f, "{}", text).is_err() {
                crate::log::error!("netguard: cannot write audit log {:?}", path);
            }
        }
        Err(e) => crate::log::error!("netguard: cannot open audit log {:?}: {}", path, e),
    }
}

/// True when this target has not been written to recently; otherwise the occurrence is counted.
fn due_to_write(target: &str) -> bool {
    let mut state = match audit_state().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = Instant::now();
    match state.get_mut(target) {
        Some(slot) if now.duration_since(slot.last) < AUDIT_INTERVAL => {
            slot.suppressed = slot.suppressed.saturating_add(1);
            false
        }
        Some(slot) => {
            slot.last = now;
            slot.suppressed = 0;
            true
        }
        None => {
            state.insert(target.to_owned(), AuditSlot { last: now, suppressed: 0 });
            true
        }
    }
}

fn now_stamp() -> String {
    crate::chrono::Local::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from_str(s).unwrap())
    }

    #[test]
    fn allow_list_hosts() {
        set_allowlist_for_test();
        for ok in [
            "10.20.30.1",
            "10.20.30.5",
            "10.20.30.200",
            "10.20.30.254",
            "172.20.0.1",
            "172.20.5.50",
            "172.20.255.254",
            "127.0.0.1",
        ] {
            assert!(ip_allowed(v4(ok)), "{} must be allowed", ok);
        }
    }

    #[test]
    fn network_and_broadcast_are_not_hosts() {
        set_allowlist_for_test();
        for no in ["10.20.30.0", "10.20.30.255", "172.20.0.0", "172.20.255.255"] {
            assert!(!ip_allowed(v4(no)), "{} must be refused", no);
        }
    }

    #[test]
    fn refuses_everything_else() {
        set_allowlist_for_test();
        for no in [
            // neighbouring /24, unlisted space
            "10.20.29.10",
            "10.20.31.10",
            "10.21.0.1",
            // other private space not in the list
            "192.168.1.10",
            "172.16.5.5",
            "10.0.0.5",
            // public, link-local, broadcast, other loopback
            "8.8.8.8",
            "169.254.1.1",
            "255.255.255.255",
            "127.0.0.2",
            "127.1.2.3",
        ] {
            assert!(!ip_allowed(v4(no)), "{} must be refused", no);
        }
    }

    #[test]
    fn allowlist_rejects_public_and_too_wide_entries() {
        // The operator may add ranges, but never public space and never a supernet that contains
        // it (a /7 covering 10/8 would also cover public space).
        assert!(parse_allowlist_entry("10.20.30.0/24").is_ok());
        assert!(parse_allowlist_entry("172.20.0.0/16").is_ok());
        assert!(parse_allowlist_entry("100.64.0.0/10").is_ok());
        assert!(parse_allowlist_entry("169.254.7.9").is_ok());
        assert!(parse_allowlist_entry("10.20.30.7").is_ok());
        for bad in [
            "8.8.8.8",
            "1.1.1.0/24",
            "10.0.0.0/7",
            "192.168.0.0/8",
            "0.0.0.0/0",
            "127.0.0.2",
            "example.com",
            "10.20.30.0/33",
            "10.20.30.0/abc",
        ] {
            assert!(parse_allowlist_entry(bad).is_err(), "{} must be rejected", bad);
        }
    }

    #[test]
    fn allowlist_from_text_keeps_the_good_lines_and_names_the_bad_one() {
        // The card shows the operator this string when a write is refused, so it has to carry both
        // the offending line and the audit reason.
        let (list, rejected) = allowlist_from_text(
            "192.168.10.0/24\n8.8.8.0/24\n192.168.10.0/24\n",
            "netguard::test::allowlist_from_text",
        );
        assert_eq!(list.len(), 1, "the duplicate must fold into one entry");
        assert_eq!(rejected.len(), 1, "{:?}", rejected);
        assert!(rejected[0].starts_with("8.8.8.0/24"), "{}", rejected[0]);
        assert!(
            rejected[0].contains("reason=allowlist_not_private_space"),
            "{}",
            rejected[0]
        );
    }

    #[test]
    fn allowlist_from_text_reads_comments_the_way_the_template_writes_them() {
        // Shipped template: every example is commented, so a fresh install parses to zero entries.
        // That is the whole reason "cannot connect" is the expected first behaviour.
        let (list, rejected) = allowlist_from_text(ALLOWLIST_TEMPLATE, "netguard::test::comments");
        assert!(list.is_empty(), "{:?}", list);
        assert!(rejected.is_empty(), "{:?}", rejected);

        // Inline comment after a value, indentation, and blank lines are not entries.
        let (list, rejected) = allowlist_from_text(
            "\n  10.20.30.0/24 # the office  \n# whole line\n172.16.5.5\n",
            "netguard::test::comments",
        );
        assert!(rejected.is_empty(), "{:?}", rejected);
        assert_eq!(list.len(), 2, "{:?}", list);
    }

    #[test]
    fn an_empty_allowlist_is_valid_input_not_an_error() {
        // Closing the gate has to be an edit the card accepts, otherwise the only way to reach
        // deny-all is by hand.
        let (list, rejected) = allowlist_from_text("", "netguard::test::empty");
        assert!(list.is_empty());
        assert!(rejected.is_empty(), "{:?}", rejected);

        // A refused line refuses the whole write, before anything touches the config directory.
        // (Only the refusal branch is exercised here - the accepting branch writes the real file.)
        let err = store_allowlist_text("192.168.10.0/24\nexample.com\n")
            .expect_err("a hostname must not be savable")
            .to_string();
        assert!(err.contains("example.com"), "{}", err);
        assert!(err.contains("reason=allowlist_not_literal_ipv4"), "{}", err);
    }

    #[test]
    fn ipv6_only_mapped_v4_passes() {
        set_allowlist_for_test();
        assert!(ip_allowed(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x0a14, 0x1e05
        )))); // ::ffff:10.20.30.5
        assert!(!ip_allowed(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x0808, 0x0808
        )))); // ::ffff:8.8.8.8
        assert!(!ip_allowed(IpAddr::V6(Ipv6Addr::LOCALHOST))); // ::1 is not allowed
        // 6to4 for an allow-listed host must NOT pass: the packet would go out through a relay.
        assert!(!ip_allowed(IpAddr::V6(Ipv6Addr::new(
            0x2002, 0x0a14, 0x1e05, 0, 0, 0, 0, 1
        ))));
        assert_eq!(ipv4_mapped(Ipv6Addr::new(0x2002, 0x0a14, 0x1e05, 0, 0, 0, 0, 1)), None);
    }

    #[test]
    fn local_interface_rule() {
        set_allowlist_for_test();
        // ICE gathering may use an allow-listed NIC, but never loopback and never a public one.
        assert!(local_interface_allowed(v4("10.20.30.5")));
        assert!(local_interface_allowed(v4("172.20.0.1")));
        assert!(!local_interface_allowed(v4("127.0.0.1")));
        assert!(!local_interface_allowed(v4("192.168.1.20")));
        assert!(!local_interface_allowed(v4("8.8.8.8")));
    }

    #[test]
    fn pair_rule() {
        set_allowlist_for_test();
        // D-2: same-network is allowed by the shipped default.
        assert!(pair_allowed(Some(v4("10.20.30.5")), v4("10.20.30.6")));
        assert!(pair_allowed(Some(v4("10.20.30.5")), v4("172.20.1.1")));
        assert!(!pair_allowed(Some(v4("10.20.30.5")), v4("10.0.0.5")));
    }

    #[test]
    fn dns_is_not_asked() {
        set_allowlist_for_test();
        // Keep the unit tests off the real config directory; `log::warn!` still runs.
        set_audit_file(false);
        // A literal is accepted, a name is refused before any resolver sees it.
        assert!(parse_literal("10.20.30.5", 21118, "test").is_ok());
        assert!(parse_literal("rs-ny.example.net", 21116, "test").is_err());
        assert!(parse_literal("8.8.8.8", 53, "test").is_err());
        assert!(parse_literal_with_port("172.20.0.50:21118", "test").is_ok());
        assert!(parse_literal_with_port("stun.example.net:19302", "test").is_err());
        assert_eq!(
            parse_literal("10.20.30.5", 21118, "test").unwrap().port(),
            21118
        );
    }

    #[test]
    fn bind_never_asks_the_resolver() {
        // A bind is about our own interface, so the allow-list is not consulted — but a name still
        // has to be refused, or `new_listener` would hand it to the resolver.
        assert_eq!(
            parse_bind_addr("0.0.0.0:0", "test").unwrap(),
            SocketAddr::from_str("0.0.0.0:0").unwrap()
        );
        assert_eq!(
            parse_bind_addr("127.0.0.1:0", "test").unwrap().port(),
            0
        );
        assert_eq!(
            parse_bind_addr("10.20.30.5:21118", "test").unwrap().ip(),
            v4("10.20.30.5")
        );
        assert!(parse_bind_addr("rs-ny.example.net:21116", "test").is_err());
    }

    #[test]
    fn forced_options_are_explicit() {
        // option2bool turns an empty value into ON for `enable-*`, so never force to "".
        for (k, v) in FORCED_OPTIONS.iter() {
            if k.starts_with("enable-") {
                assert_eq!(*v, "N", "{} must be forced to N, not {:?}", k, v);
            }
        }
        // The opposite polarity (config.rs::option2bool): `allow-*`, `stop-service`, `direct-server`
        // and `force-always-relay` are read as `== "Y"`, so an empty value there means OFF - which would
        // have silently switched the one thing this build needs on. Same trap as `enable-*`, other way
        // round, so it gets the same explicit test.
        for (k, v) in FORCED_OPTIONS.iter() {
            if k.starts_with("allow-")
                || *k == "stop-service"
                || *k == "direct-server"
                || *k == "force-always-relay"
            {
                assert!(
                    matches!(*v, "Y" | "N"),
                    "{} is read as `== \"Y\"`, so it must be pinned to Y or N, got {:?}",
                    k,
                    v
                );
            }
        }
        assert_eq!(force_option("enable-tcp-punch").as_deref(), Some("N"));
        assert_eq!(force_option("lang"), None);
        assert!(is_forced_key("custom-rendezvous-server"));
        assert!(!is_forced_key("lang"));
    }

    #[test]
    fn self_check_is_clean() {
        assert_eq!(startup_self_check(), Vec::<String>::new());
    }

    #[test]
    fn policy_keys_are_pinned_keys() {
        // The invariant `startup_self_check` now also guards: the purge deletes these, so they must all
        // have a compiled value - otherwise deleting a stored value would change behaviour.
        for k in SERVER_SHAPED_KEYS.iter() {
            assert!(is_forced_key(k), "{} is purged but not pinned", k);
            assert!(is_policy_key(k));
        }
        // Pinned without naming a server: the positive switch, the relay window, and the upstream
        // peer-ID gate that must stay empty so netguard's allow-list is the only inbound authority.
        // (These are deliberately not in `SERVER_SHAPED_KEYS`: `direct-server` = "Y" is what the build
        // *wants* stored nowhere, but the pin itself is the guarantee, so the purge dropping it is
        // fine.)
        for k in ["direct-server", "relay-fallback-delay", "id-whitelist"] {
            assert!(is_forced_key(k), "{}", k);
            assert!(is_policy_key(k), "{}", k);
        }
        // `direct-access-port` is the opposite case: deliberately *not* pinned, so the operator can
        // move the direct pair off 21118 when that port is not usable on their network. Both halves
        // read `direct_peer_port()`, which is what makes the old pin unnecessary (see the invariant in
        // `startup_self_check`).
        assert!(!is_forced_key("direct-access-port"));
        assert!(!is_policy_key("direct-access-port"));
        assert_eq!(force_option("direct-server").as_deref(), Some("Y"));
        assert_eq!(force_option("relay-server").as_deref(), Some(""));
        // 步 6-B: the Telegram bot credential is a public-service secret with no reader left.
        assert_eq!(force_option("bot").as_deref(), Some(""));
        assert!(is_policy_key("bot"));
        // The key the *non-option* server stores are gated on (`get_rendezvous_server{,s}`,
        // `get_custom_rendezvous_server`) - `startup_self_check` invariant 4 checks it at run time.
        assert_eq!(
            force_option("custom-rendezvous-server").as_deref(),
            Some("")
        );
        assert_eq!(force_option("relay-fallback-delay").as_deref(), Some(""));
        // Nothing else is pinned - `lang` is the stand-in for an ordinary option.
        assert_eq!(force_option("lang"), None);
        assert!(!is_policy_key("lang"));
    }

    #[test]
    fn operator_can_move_the_direct_pair_off_21118() {
        // The whole point of un-pinning `direct-access-port`: one value, both sides, no silent
        // half-migration. Anything unusable falls back to the historical default, and
        // `startup_self_check` refuses to start on a value that would fall back unexpectedly.
        let default_port = crate::config::RENDEZVOUS_PORT + 2;
        assert_eq!(default_port, DEFAULT_DIRECT_PEER_PORT);
        assert_eq!(DEFAULT_DIRECT_PEER_PORT, 21118);
        for unusable in ["", " ", "0", "-1", "65536", "abc", "21118abc"] {
            assert_eq!(
                peer_port_from_option(unusable),
                default_port,
                "{:?} must fall back",
                unusable
            );
        }
        assert_eq!(peer_port_from_option("9001"), 9001);
        assert_eq!(peer_port_from_option(" 9001 "), 9001);
        assert_eq!(peer_port_from_option("1"), 1);
        assert_eq!(peer_port_from_option("65535"), 65535);
        // A write to it is no longer a policy violation.
        assert_eq!(refuse_pinned_write("direct-access-port", "9001", "test"), None);
    }

    #[test]
    fn pinned_writes_are_refused_and_only_mismatches_are_reported() {
        set_audit_file(false);
        // An attempt that disagrees with the policy: refused, and worth an audit line.
        assert_eq!(refuse_pinned_write("enable-webrtc", "Y", "test").as_deref(), Some("N"));
        // An attempt that happens to match: still refused - the caller must not store it, and storing it
        // would be a lie in the file - but it is not a tampering attempt, so nothing gets reported.
        assert_eq!(refuse_pinned_write("enable-webrtc", "N", "test").as_deref(), Some("N"));
        // The positive pin, checked the other way round: `option2bool("direct-server")` is `== "Y"`, so
        // "N" is a real attempt to switch the direct listener off.
        assert_eq!(refuse_pinned_write("direct-server", "N", "test").as_deref(), Some("Y"));
        // An ordinary key is nobody's business: no refusal, no audit.
        assert_eq!(refuse_pinned_write("lang", "en", "test"), None);
    }

    #[test]
    fn deny_produces_error_not_fallback() {
        set_audit_file(false);
        let err = check_outbound_addr(
            SocketAddr::from_str("8.8.8.8:21117").unwrap(),
            "tcp::FramedStream::new",
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("netguard: denied"), "{}", msg);
        assert!(msg.contains("8.8.8.8:21117"), "{}", msg);
        assert!(msg.contains("tcp::FramedStream::new"), "{}", msg);
    }
}
