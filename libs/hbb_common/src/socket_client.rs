#[cfg(feature = "webrtc")]
use crate::webrtc::{self, is_webrtc_endpoint};
use crate::{
    config::{Config, NetworkType},
    netguard,
    tcp::FramedStream,
    udp::FramedSocket,
    ResultType, Stream,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio_socks::{IntoTargetAddr, TargetAddr};

#[inline]
pub fn check_port<T: std::string::ToString>(host: T, port: i32) -> String {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            return host;
        }
        return format!("[{host}]:{port}");
    }
    if !host.contains(':') {
        return format!("{host}:{port}");
    }
    host
}

#[inline]
pub fn increase_port<T: std::string::ToString>(host: T, offset: i32) -> String {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            let tmp: Vec<&str> = host.split("]:").collect();
            if tmp.len() == 2 {
                let port: i32 = tmp[1].parse().unwrap_or(0);
                if port > 0 {
                    return format!("{}]:{}", tmp[0], port + offset);
                }
            }
        }
    } else if host.contains(':') {
        let tmp: Vec<&str> = host.split(':').collect();
        if tmp.len() == 2 {
            let port: i32 = tmp[1].parse().unwrap_or(0);
            if port > 0 {
                return format!("{}:{}", tmp[0], port + offset);
            }
        }
    }
    host
}

pub fn split_host_port<T: std::string::ToString>(host: T) -> Option<(String, i32)> {
    let host = host.to_string();
    if crate::is_ipv6_str(&host) {
        if host.starts_with('[') {
            let tmp: Vec<&str> = host.split("]:").collect();
            if tmp.len() == 2 {
                let port: i32 = tmp[1].parse().unwrap_or(0);
                if port > 0 {
                    return Some((format!("{}]", tmp[0]), port));
                }
            }
        }
    } else if host.contains(':') {
        let tmp: Vec<&str> = host.split(':').collect();
        if tmp.len() == 2 {
            let port: i32 = tmp[1].parse().unwrap_or(0);
            if port > 0 {
                return Some((tmp[0].to_string(), port));
            }
        }
    }
    None
}

pub fn test_if_valid_server(host: &str, test_with_proxy: bool) -> String {
    // netguard §二.1/§二.6: "valid server" in this build means "an address the allow-list will
    // actually let us dial". The old form called `to_socket_addrs`, so merely typing a value in the
    // server dialog put a DNS query on the wire, and it accepted any public name.
    let _ = test_with_proxy;
    let with_port = check_port(host, 0);
    match netguard::parse_literal_with_port(&with_port, "socket_client::test_if_valid_server") {
        Ok(addr) => {
            if netguard::check_outbound_addr(addr, "socket_client::test_if_valid_server").is_ok() {
                String::new()
            } else {
                format!("'{host}' is outside the intranet allow-list")
            }
        }
        Err(err) => format!("{err}"),
    }
}

#[inline]
pub fn test_if_valid_server_for_proxy_(host: &str) -> String {
    // `&host.into_target_addr()` is defined in `tokio-socs`, but is a common pattern for testing,
    // it can be used for both `socks` and `http` proxy.
    match &host.into_target_addr() {
        Err(err) => err.to_string(),
        Ok(_) => "".to_owned(),
    }
}

pub trait IsResolvedSocketAddr {
    fn resolve(&self) -> Option<&SocketAddr>;
}

impl IsResolvedSocketAddr for SocketAddr {
    fn resolve(&self) -> Option<&SocketAddr> {
        Some(self)
    }
}

impl IsResolvedSocketAddr for String {
    fn resolve(&self) -> Option<&SocketAddr> {
        None
    }
}

impl IsResolvedSocketAddr for &str {
    fn resolve(&self) -> Option<&SocketAddr> {
        None
    }
}

// netguard L11 (步 6-E): this used to check for a websocket endpoint first (and `check_ws` could
// rewrite the port); the WebSocket transport is deleted, so every target goes to plain TCP.
#[inline]
pub async fn connect_tcp<
    't,
    T: IntoTargetAddr<'t> + ToSocketAddrs + IsResolvedSocketAddr + std::fmt::Display,
>(
    target: T,
    ms_timeout: u64,
) -> ResultType<crate::Stream> {
    #[cfg(feature = "webrtc")]
    if is_webrtc_endpoint(&target.to_string()) {
        // netguard §3.6 可达层: webrtc-rs opens its sockets inside the crate (the gatherer dials
        // STUN itself, and `SettingEngine` has no destination-address hook), so an in-call guard
        // cannot cover it. Making the transport entry unreachable is what actually keeps ICE/STUN
        // traffic off the wire; `ice-servers` is forced empty (§8.4) and `set_ip_filter` is narrowed
        // in `webrtc.rs` as the layers underneath.
        netguard::audit_denied(
            "outbound",
            &target.to_string(),
            "socket_client::connect_tcp",
            "reason=webrtc_transport_disabled",
        );
        return Err(anyhow::anyhow!(
            "netguard: WebRTC transport is disabled in this build ({})",
            target
        ));
    }
    connect_tcp_local(target, None, ms_timeout).await
}

// This function connects directly to the target (the target is always plain TCP in this build).
pub async fn connect_tcp_local<
    't,
    T: IntoTargetAddr<'t> + ToSocketAddrs + IsResolvedSocketAddr + std::fmt::Display,
>(
    target: T,
    local: Option<SocketAddr>,
    ms_timeout: u64,
) -> ResultType<Stream> {
    // netguard §3.4/§5 (was `query_nip_io`, L7): the NAT64 branch rewrote a v4 peer into
    // `{ip}.nip.io` and looked it up, i.e. a deliberate public DNS query, to reach a v4 peer over a
    // v6-only link. Both allow-listed networks are IPv4, and a v6 destination can never pass the
    // allow-list, so the branch has no legitimate use left; `FramedStream::new` is now the single
    // egress point and it refuses name-form targets before resolving.
    Ok(Stream::Tcp(
        FramedStream::new(target, local, ms_timeout).await?,
    ))
}

#[inline]
pub fn is_ipv4(target: &TargetAddr<'_>) -> bool {
    match target {
        TargetAddr::Ip(addr) => addr.is_ipv4(),
        _ => true,
    }
}

#[inline]
pub async fn query_nip_io(addr: &SocketAddr) -> ResultType<SocketAddr> {
    // netguard L7/§5: the `{ip}.nip.io` rewrite is a deliberate public DNS query (NAT64), so it is
    // refused here — and the name is not even constructed, because building it would put the
    // `nip.io` label back into the binary that §五 asks to be clean of it. The only branch that
    // used it is already gone from `connect_tcp_local`.
    netguard::audit_denied(
        "outbound",
        &addr.to_string(),
        "socket_client::query_nip_io",
        "reason=nat64_helper_removed",
    );
    Err(anyhow::anyhow!(
        "netguard: the NAT64 address helper is disabled in this build"
    ))
}

#[inline]
pub fn ipv4_to_ipv6(addr: String, ipv4: bool) -> String {
    // netguard L7: rewriting an IPv4 literal into a `.nip.io` name is the name form that the egress
    // guards refuse, so the helper is a no-op in this build.
    if !ipv4 && crate::is_ipv4_str(&addr) {
        return addr;
    }
    addr
}

/// The address of `target` for a direct session.
///
/// netguard §3.4/§5: this used to call `lookup_host`, i.e. it put a DNS query on the wire before
/// anything checked where the answer pointed. The allow-list is IP-only, so a literal is the only
/// acceptable input and a name has no legitimate use — refuse it instead of resolving it.
async fn resolve_target(target: &str) -> ResultType<SocketAddr> {
    netguard::parse_literal_with_port(target, "socket_client::resolve_target")
}

/// netguard §3.4 (was L8): the old form opened a throwaway TCP connection to `target`
/// (`tokio::net::TcpStream::connect`, an independent egress that no guard saw) purely to learn which
/// address answered. There is nothing to prove: the direct path now dials literal allow-listed
/// addresses only, so the resolver's job is the literal parse in `resolve_target`.
async fn test_target(target: &str) -> ResultType<SocketAddr> {
    resolve_target(target).await
}

#[inline]
pub async fn new_direct_udp_for(target: &str) -> ResultType<(Arc<UdpSocket>, SocketAddr)> {
    let peer_addr = test_target(target).await?;
    // netguard §3.9: this is a raw `tokio::net::UdpSocket`, invisible to `udp::FramedSocket::send`,
    // so the verdict has to be taken at the construction point, before anything is bound or sent.
    netguard::check_outbound_ip(peer_addr.ip(), "socket_client::new_direct_udp_for", &target.to_owned())?;
    let local_addr = Config::get_any_listen_addr(peer_addr.is_ipv4());
    let socket = UdpSocket::bind(local_addr).await?;
    Ok((Arc::new(socket), peer_addr))
}

/// `new_direct_udp_for` on the resolver's preferred address, with no handshake to prove it and a
/// second at most for the lookup: for the controller's NAT test, once per connection, where the
/// proof cost a round trip right before the connection it then opens to the same host.
#[inline]
pub async fn new_direct_udp_for_unverified(
    target: &str,
) -> ResultType<(Arc<UdpSocket>, SocketAddr)> {
    let peer_addr = super::timeout(1000, resolve_target(target)).await??;
    netguard::check_outbound_ip(
        peer_addr.ip(),
        "socket_client::new_direct_udp_for_unverified",
        &target.to_owned(),
    )?;
    let local_addr = Config::get_any_listen_addr(peer_addr.is_ipv4());
    let socket = UdpSocket::bind(local_addr).await?;
    Ok((Arc::new(socket), peer_addr))
}

#[inline]
pub async fn new_udp_for(
    target: &str,
    ms_timeout: u64,
) -> ResultType<(FramedSocket, TargetAddr<'static>)> {
    if NetworkType::Direct != Config::get_network_type() {
        // netguard §二.1/§二.3: the old non-direct branch handed a public hostname straight to a
        // relay socket. With the relay path removed (F1–F11 / L5) there is nothing left for it to
        // reach, so refuse before a socket exists rather than dial and filter afterwards.
        netguard::audit_denied(
            "outbound",
            target,
            "socket_client::new_udp_for",
            "reason=relay_path_removed",
        );
        return Err(anyhow::anyhow!(
            "netguard: non-direct network type has no server to reach ({target})"
        ));
    }
    let addr = test_target(target).await?;
    netguard::check_outbound_ip(
        addr.ip(),
        "socket_client::new_udp_for",
        &target.to_owned(),
    )?;
    Ok((
        new_udp(Config::get_any_listen_addr(addr.is_ipv4()), ms_timeout).await?,
        addr.into_target_addr()?.to_owned(),
    ))
}

async fn new_udp<T: ToSocketAddrs + std::fmt::Display>(local: T, ms_timeout: u64) -> ResultType<FramedSocket> {
    match Config::get_socks() {
        None => Ok(FramedSocket::new(local).await?),
        Some(conf) => {
            let socket = FramedSocket::new_proxy(
                conf.proxy.as_str(),
                local,
                conf.username.as_str(),
                conf.password.as_str(),
                ms_timeout,
            )
            .await?;
            Ok(socket)
        }
    }
}

pub async fn rebind_udp_for(
    target: &str,
) -> ResultType<Option<(FramedSocket, TargetAddr<'static>)>> {
    if Config::get_network_type() != NetworkType::Direct {
        return Ok(None);
    }
    let addr = test_target(target).await?;
    // netguard §3.9: same reason as `new_direct_udp_for*` — the socket this returns is a
    // `FramedSocket`, but the peer address is chosen here, so this is where the verdict belongs.
    netguard::check_outbound_ip(
        addr.ip(),
        "socket_client::rebind_udp_for",
        &target.to_owned(),
    )?;
    let v4 = addr.is_ipv4();
    Ok(Some((
        FramedSocket::new(Config::get_any_listen_addr(v4)).await?,
        addr.into_target_addr()?.to_owned(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat64_helpers_never_build_names() {
        test_nat64_helpers_never_build_names_async();
    }

    /// netguard L7/§5: upstream asserted the `{ip}.nip.io` rewrite and then did a real DNS query to
    /// prove it. In this build the rewrite is a no-op, the lookup is refused, and `resolve_target`
    /// only accepts literals — so nothing here can put a query on the wire.
    #[tokio::main(flavor = "current_thread")]
    async fn test_nat64_helpers_never_build_names_async() {
        assert_eq!(ipv4_to_ipv6("1.1.1.1".to_owned(), true), "1.1.1.1");
        assert_eq!(ipv4_to_ipv6("1.1.1.1".to_owned(), false), "1.1.1.1");
        assert_eq!(
            ipv4_to_ipv6("1.1.1.1:8080".to_owned(), false),
            "1.1.1.1:8080"
        );
        assert_eq!(ipv4_to_ipv6("host.example.net".to_owned(), false), "host.example.net");
        assert!(query_nip_io(&"1.1.1.1:80".parse().unwrap()).await.is_err());
        assert_eq!(
            resolve_target("127.0.0.1:21116").await.unwrap(),
            "127.0.0.1:21116".parse().unwrap()
        );
        assert!(resolve_target("rs-ny.example.net:21116").await.is_err());
        assert!(resolve_target("8.8.8.8:53").await.is_err());
    }

    /// netguard: "valid server" now means "on the operator allow-list" (loopback is implicit),
    /// not "resolvable".
    #[test]
    fn test_valid_server_means_allow_listed() {
        assert!(test_if_valid_server("127.0.0.1", false).is_empty());
        assert!(test_if_valid_server("127.0.0.1:21116", false).is_empty());
        assert!(!test_if_valid_server("192.168.1.10", false).is_empty());
        assert!(!test_if_valid_server("8.8.8.8", false).is_empty());
        assert!(!test_if_valid_server("rs-ny.example.net", false).is_empty());
        assert!(!test_if_valid_server("a", false).is_empty());
        assert!(!test_if_valid_server("", false).is_empty());
    }

    #[test]
    fn test_check_port() {
        assert_eq!(check_port("[1:2]:12", 32), "[1:2]:12");
        assert_eq!(check_port("1:2", 32), "[1:2]:32");
        assert_eq!(check_port("z1:2", 32), "z1:2");
        assert_eq!(check_port("1.1.1.1", 32), "1.1.1.1:32");
        assert_eq!(check_port("1.1.1.1:32", 32), "1.1.1.1:32");
        assert_eq!(check_port("test.com:32", 0), "test.com:32");
        assert_eq!(increase_port("[1:2]:12", 1), "[1:2]:13");
        assert_eq!(increase_port("1.2.2.4:12", 1), "1.2.2.4:13");
        assert_eq!(increase_port("1.2.2.4", 1), "1.2.2.4");
        assert_eq!(increase_port("test.com", 1), "test.com");
        assert_eq!(increase_port("test.com:13", 4), "test.com:17");
        assert_eq!(increase_port("1:13", 4), "1:13");
        assert_eq!(increase_port("22:1:13", 4), "22:1:13");
        assert_eq!(increase_port("z1:2", 1), "z1:3");
    }
}
