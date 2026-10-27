use crate::{netguard, ResultType};
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use futures::{SinkExt, StreamExt};
use protobuf::Message;
use socket2::{Domain, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio_socks::{udp::Socks5UdpFramed, IntoTargetAddr, TargetAddr, ToProxyAddrs};
use tokio_util::{codec::BytesCodec, udp::UdpFramed};

/// Outbound check for a `send`/`send_raw` target, with the fake success removed (§二.4/§五):
/// upstream silently skipped name-form targets on a `Direct` socket and still returned `Ok(())`,
/// which an acceptance run would read as "nothing was sent". A name-form target is now an error,
/// so no resolver is ever asked and the caller sees a failure instead of a lie.
fn check_outbound_target(addr: &TargetAddr<'_>, ctx: &str) -> ResultType<()> {
    match addr {
        TargetAddr::Ip(peer) => netguard::check_outbound_ip(peer.ip(), ctx, &peer.to_string()),
        TargetAddr::Domain(host, port) => Err(netguard::deny_name_form(&format!("{host}:{port}"), ctx)),
    }
}

pub enum FramedSocket {
    Direct(UdpFramed<BytesCodec>),
    ProxySocks(Socks5UdpFramed),
}

fn new_socket(addr: SocketAddr, reuse: bool, buf_size: usize) -> Result<Socket, std::io::Error> {
    let socket = match addr {
        SocketAddr::V4(..) => Socket::new(Domain::ipv4(), Type::dgram(), None),
        SocketAddr::V6(..) => Socket::new(Domain::ipv6(), Type::dgram(), None),
    }?;
    if reuse {
        // windows has no reuse_port, but its reuse_address
        // almost equals to unix's reuse_port + reuse_address,
        // though may introduce nondeterministic behavior
        // illumos has no support for SO_REUSEPORT
        #[cfg(all(unix, not(target_os = "illumos")))]
        socket.set_reuse_port(true).ok();
        socket.set_reuse_address(true).ok();
    }
    // only nonblocking work with tokio, https://stackoverflow.com/questions/64649405/receiver-on-tokiompscchannel-only-receives-messages-when-buffer-is-full
    socket.set_nonblocking(true)?;
    if buf_size > 0 {
        socket.set_recv_buffer_size(buf_size).ok();
    }
    log::debug!(
        "Receive buf size of udp {}: {:?}",
        addr,
        socket.recv_buffer_size()
    );
    if addr.is_ipv6() && addr.ip().is_unspecified() && addr.port() > 0 {
        socket.set_only_v6(false).ok();
    }
    socket.bind(&addr.into())?;
    Ok(socket)
}

impl FramedSocket {
    pub async fn new<T: ToSocketAddrs + std::fmt::Display>(addr: T) -> ResultType<Self> {
        Self::new_reuse(addr, false, 0).await
    }

    pub async fn new_reuse<T: ToSocketAddrs + std::fmt::Display>(
        addr: T,
        reuse: bool,
        buf_size: usize,
    ) -> ResultType<Self> {
        // netguard §二.1/§5: bind on a literal only, so creating the socket cannot put a DNS query
        // on the wire the way `lookup_host` did.
        let addr = netguard::parse_bind_addr(&addr.to_string(), "udp::FramedSocket::new")?;
        Ok(Self::Direct(UdpFramed::new(
            UdpSocket::from_std(new_socket(addr, reuse, buf_size)?.into_udp_socket())?,
            BytesCodec::new(),
        )))
    }

    pub async fn new_proxy<'a, 't, P: ToProxyAddrs, T: ToSocketAddrs>(
        proxy: P,
        local: T,
        username: &'a str,
        password: &'a str,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        // netguard §二.1/§三: the SOCKS UDP Associate path is disabled in this build. Its only
        // caller (`socket_client.rs:270`) is unreachable because `Config::get_socks()` is forced to
        // `None` (§8.4/L10); refusing here is the second lock, and a proxy would forward to
        // wherever the proxy itself can reach, which no in-app guard could account for.
        let _ = (proxy, local, username, password, ms_timeout);
        netguard::audit_denied(
            "outbound",
            "socks5-udp-associate",
            "udp::FramedSocket::new_proxy",
            "reason=socks_proxy_disabled",
        );
        Err(anyhow!(
            "netguard: socks proxy is disabled in this build (udp::FramedSocket::new_proxy)"
        ))
    }

    #[inline]
    pub async fn send(
        &mut self,
        msg: &impl Message,
        addr: impl IntoTargetAddr<'_>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();
        let send_data = Bytes::from(msg.write_to_bytes()?);
        check_outbound_target(&addr, "udp::FramedSocket::send")?;
        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = &addr {
                    f.send((send_data, *addr)).await?
                }
            }
            Self::ProxySocks(f) => f.send((send_data, addr)).await?,
        };
        Ok(())
    }

    // https://stackoverflow.com/a/68733302/1926020
    #[inline]
    pub async fn send_raw(
        &mut self,
        msg: &'static [u8],
        addr: impl IntoTargetAddr<'static>,
    ) -> ResultType<()> {
        let addr = addr.into_target_addr()?.to_owned();
        check_outbound_target(&addr, "udp::FramedSocket::send_raw")?;
        match self {
            Self::Direct(f) => {
                if let TargetAddr::Ip(addr) = &addr {
                    f.send((Bytes::from(msg), *addr)).await?
                }
            }
            Self::ProxySocks(f) => f.send((Bytes::from(msg), addr)).await?,
        };
        Ok(())
    }

    #[inline]
    pub async fn next(&mut self) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        // netguard §二.2 ("双向") / §4: a datagram whose source is outside the allow-list is dropped
        // here, before the session layer ever sees it, and the drop is audited. Looping rather than
        // returning `None` keeps a single stray packet from ending the read stream.
        loop {
            match self {
                Self::Direct(f) => match f.next().await {
                    Some(Ok((data, addr))) => match addr.into_target_addr() {
                        Ok(TargetAddr::Ip(peer)) => {
                            if let Err(err) =
                                netguard::check_inbound_addr(peer, "udp::FramedSocket::next")
                            {
                                log::debug!("Dropped UDP datagram: {err}");
                                continue;
                            }
                            return Some(Ok((data, TargetAddr::Ip(peer))));
                        }
                        Ok(other) => {
                            netguard::audit_denied(
                                "inbound",
                                &format!("{:?}", other),
                                "udp::FramedSocket::next",
                                "reason=name_form_source",
                            );
                            continue;
                        }
                        Err(e) => return Some(Err(anyhow!(e))),
                    },
                    Some(Err(e)) => return Some(Err(anyhow!(e))),
                    None => return None,
                },
                // The SOCKS variant can no longer be constructed (see `new_proxy`), so no framed
                // source is expected to be a relay's; returning None keeps the signature honest.
                Self::ProxySocks(_) => return None,
            }
        }
    }

    #[inline]
    pub async fn next_timeout(
        &mut self,
        ms: u64,
    ) -> Option<ResultType<(BytesMut, TargetAddr<'static>)>> {
        if let Ok(res) =
            tokio::time::timeout(std::time::Duration::from_millis(ms), self.next()).await
        {
            res
        } else {
            None
        }
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        if let FramedSocket::Direct(x) = self {
            if let Ok(v) = x.get_ref().local_addr() {
                return Some(v);
            }
        }
        None
    }
}
