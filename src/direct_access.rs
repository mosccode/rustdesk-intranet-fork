// netguard L5 (需求 §二.1/§二.3): this module used to be the rendezvous mediator. It kept a
// registration connection to `hbbs`, answered PunchHole / RequestRelay / FetchLocalAddr, ran UDP
// and TCP hole punching with its IPv6 half, spawned WebRTC answerers and could fall back to a
// relay. All of that is deleted:
//
//   * registration and heartbeat (`start_udp`, `register_peer`, `handle_resp`, `deploy_register_*`)
//     - there is no server to register with;
//   * relay (`handle_request_relay`, `create_relay`) - removed in 步 4 (F1-F11);
//   * punching (`handle_punch_hole`, `punch_udp_hole`, `punch_tcp_until_connected`, `punch_until`,
//     `serve_punched`, `accept_punched_connection`) and its IPv6 half (`start_ipv6`,
//     `udp_nat_listen`) - the controller dials port 21118 directly, so no hole needs punching;
//   * LAN discovery - removed in 步 6-D.
//
// What is left is the one inbound listener this build has: `direct_server`, plus `start_all` (its
// launcher) and `restart` (a no-op kept for the UI/IPC call sites). The file was renamed from
// `rendezvous_mediator.rs` so that no source file claims to be a rendezvous client any more;
// `lib.rs` re-exports it the same way, which keeps `crate::*` paths in other modules valid.

use hbb_common::{
    allow_err,
    config::{self, option2bool, Config, RENDEZVOUS_PORT},
    log, sleep, tokio, Stream,
};

use base::config::keys::*;

use crate::server::{check_zombie, new as new_server, ConnectionMeta, ServerPtr};

/// Registration used to tell this process whether `hbbs` had deployed the device, and the UI showed
/// a banner from it. Registration is deleted, so nothing can set it any more: the value is a stub
/// that stays `false`. Kept (rather than deleting its three readers) so the UI/IPC keep compiling.
pub static NEEDS_DEPLOY: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Clears the stub above; the caller's intent ("the user saw the notice") is preserved, the state
/// can never be `true` in the first place.
pub fn reset_needs_deploy_notification() {
    NEEDS_DEPLOY.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Kept for the UI/IPC call sites (`flutter_ffi`, `ipc`): they used to force the mediator to drop
/// its registration socket and reconnect. There is no such socket now - `direct_server` re-reads
/// its options on every pass (once a second), so a settings change takes effect on its own.
pub fn restart() {
    log::info!("direct-access listener restart requested; it re-reads its options every second");
}

/// Starts the only listener this build has. Called by `server::start_server` when this process is
/// the host. `check_zombie` and `new_server` are unrelated to rendezvous and stay as they were.
pub async fn start_all() {
    // Preserved from the mediator: an outgoing-only process (`--connect` and friends) never serves.
    if config::is_outgoing_only() {
        loop {
            sleep(1.).await;
        }
    }
    check_zombie();
    // Not networking: the AV1 codec self-test that used to run here before the listener started.
    scrap::codec::test_av1();
    let server = new_server();
    tokio::spawn(async move {
        direct_server(server).await;
    });
    // The mediator's registration loop used to keep this future alive, and `server::start_server`
    // (a `#[tokio::main]` body, or the Android entry) returns into `main` - returning here would
    // drop the runtime and kill the listener we just spawned. Park instead: same lifetime as before,
    // with no registration traffic behind it.
    std::future::pending::<()>().await;
}

fn get_direct_port() -> i32 {
    let mut port = Config::get_option("direct-access-port")
        .parse::<i32>()
        .unwrap_or(0);
    if port <= 0 {
        port = RENDEZVOUS_PORT + 2;
    }
    port
}

async fn direct_server(server: ServerPtr) {
    let mut listener = None;
    let mut port = 0;
    loop {
        let disabled = !option2bool(
            OPTION_DIRECT_SERVER,
            &Config::get_option(OPTION_DIRECT_SERVER),
        ) || option2bool("stop-service", &Config::get_option("stop-service"));
        if !disabled && listener.is_none() {
            port = get_direct_port();
            match hbb_common::tcp::listen_any(port as _).await {
                Ok(l) => {
                    listener = Some(l);
                    log::info!(
                        "Direct server listening on: {:?}",
                        listener.as_ref().map(|l| l.local_addr())
                    );
                }
                Err(err) => {
                    log::error!(
                        "Failed to start direct server on port: {}, error: {}",
                        port,
                        err
                    );
                    loop {
                        if port != get_direct_port() {
                            break;
                        }
                        sleep(1.).await;
                    }
                }
            }
        }
        if let Some(l) = listener.as_mut() {
            if disabled || port != get_direct_port() {
                log::info!("Exit direct access listen");
                listener = None;
                continue;
            }
            if let Ok(Ok((stream, addr))) = hbb_common::timeout(1000, l.accept()).await {
                // netguard §二.2/§4: the direct-access listener is bound to the wildcard address
                // (`tcp::listen_any`), so the allow-list is enforced on the peer the moment it is
                // accepted - before `create_tcp_connection` and before any handshake.
                if let Err(err) =
                    hbb_common::netguard::check_inbound_addr(addr, "direct_server::accept")
                {
                    log::warn!("{err}");
                    drop(stream);
                    continue;
                }
                stream.set_nodelay(true).ok();
                log::info!("direct access from {}", addr);
                let local_addr = stream
                    .local_addr()
                    .unwrap_or(Config::get_any_listen_addr(true));
                let server = server.clone();
                tokio::spawn(async move {
                    allow_err!(
                        crate::server::create_tcp_connection(
                            server,
                            Stream::from(stream, local_addr),
                            addr,
                            false,
                            ConnectionMeta::default(), // Direct connections don't have server-side user context.
                        )
                        .await
                    );
                });
            } else {
                sleep(0.1).await;
            }
        } else {
            sleep(1.).await;
        }
    }
}
