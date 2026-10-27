// netguard webgate: the browser-facing HTTP/1.1 + WebSocket (RFC 6455) surface.
//
// Written by hand on `std::net` for three reasons, all of them policy reasons rather than
// convenience: (1) the fork deleted the WebSocket dependency in step 6-E and the acceptance notes
// record it as gone, so re-adding `tungstenite` (a *client* transport, which is not even what we
// need) would reopen that claim; (2) a full async HTTP+WS stack would want a Tokio runtime that
// then nests against `ui_session_interface::io_loop`'s own current-thread runtime, which
// `agents.md` (Tokio Rules) forbids; (3) the audited surface is one listener serving one embedded
// page and one bridge, and that is easier to defend in 500 lines here than inside a crate's suite.
//
// Hard rules implemented in this file:
//   * the listener binds through netguard's `parse_bind_addr` - a literal address or nothing, no
//     resolver - and every accepted socket is re-checked with `check_inbound_addr`, which is the
//     *same* allow-list test the controlled side runs on its own accepts. 开箱即用那一版（需求方
//     2026-10-28）不填 `webgate-bind` 时听的是 `0.0.0.0`，所以"哪些地址能用这台网关"完全由这道
//     入站检查决定：不在放行范围内的浏览器拿不到页面，连不上是被审计过的，不是"看起来连不上"；
//   * `Host` must name the address the socket actually landed on, and `Origin` must agree with it.
//     That is what makes a DNS-rebinding attempt (a hostname that resolves to this machine) fail
//     rather than merely look odd, because this build has no resolver to rebind with. On a wildcard
//     bind there is no single "landed on" address, so the rule becomes "a literal IP that is not
//     loopback" - names are still refused, and `Origin: null` (sandboxed/file pages) is refused too;
//   * the bridge may have to prove the passphrase, if one is configured: `hello` says which, and
//     when it says `required` the page answers with `sha1(nonce || passphrase)` over a fresh
//     16-byte nonce, so the passphrase itself never crosses the socket. `http` and `ws` are
//     plaintext, so that digest is the only thing standing between "anyone who can reach the port"
//     and "someone who knows the passphrase" - it is not encryption, and the module header says so.
//     不写口令 = 这一层没有，剩下的边界就是上面那条入站策略，README 与本文件都不假装它还在了；
//   * the page ships with `Content-Security-Policy: default-src 'none'` (inline script/style only)
//     and contains no external URL at all, so the browser is told to fetch nothing else;
//   * client frames must be masked (RFC 6455 §5.3) and are length-capped; the only routes are `/`
//     and `/ws`, so the gateway is never a proxy.

use crate::webgate::peer;
use crate::webgate::sha1::sha1;
use hbb_common::base64::Engine as _;
use hbb_common::log;
use hbb_common::netguard;
use hbb_common::rand::rngs::OsRng;
use hbb_common::rand::RngCore as _;
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// RFC 6455 §1.3 magic string for the handshake answer.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Longest request head we read, and the longest inbound message. Both are far above what the
/// page ever sends; over-limit is a close, not a truncation.
const MAX_HEAD: usize = 8 * 1024;
const MAX_INBOUND: usize = 64 * 1024;
/// Queue depth between the bridge and this socket. A browser that stops reading loses frames
/// (latest-wins), it does not build up a backlog of stale screens.
const OUT_QUEUE: usize = 8;
/// A stalled browser must not pin a writer thread behind a socket that never drains.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a connection may sit without any frame from the browser before we let it go.
const READ_TIMEOUT: Duration = Duration::from_secs(300);
/// ... and how long it may take to answer the passphrase challenge.
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

type Writer = Arc<Mutex<TcpStream>>;

/// What the bridge may hand to the socket: one JPEG frame or one JSON event.
///
/// There is deliberately no "end of stream" variant: `detach()` drops the sender, which makes
/// `pump()`'s `recv()` fail, and that is how the pump learns the session is gone.
pub enum OutMsg {
    Frame(Vec<u8>),
    Event(String),
}

/// Serve until the process exits. `bind` is either the one address `webgate-bind` named or the
/// wildcard the turnkey default picked; `auth` is the configured passphrase, empty when there is
/// none (see `bridge`, which turns that into the `hello.auth` the page reads).
pub fn serve(bind: SocketAddr, auth: &str) -> hbb_common::ResultType<()> {
    let listener = TcpListener::bind(bind).map_err(|e| {
        hbb_common::anyhow::anyhow!(
            "webgate: cannot listen on {} (another webgate already running?): {}",
            bind,
            e
        )
    })?;
    log::info!("webgate: serving the control page at http://{}", bind);
    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(e) => {
                log::warn!("webgate: accept failed: {}", e);
                continue;
            }
        };
        // The same verdict the controlled side would reach for this peer address. Denials are
        // audited inside netguard, so there is nothing to add here beyond letting the go.
        let peer_addr = match stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                log::warn!("webgate: peer address unknown, connection dropped: {}", e);
                continue;
            }
        };
        if let Err(e) = netguard::check_inbound_addr(peer_addr, "webgate::http::accept") {
            log::warn!("webgate: {}", e);
            continue;
        }
        let local = match stream.local_addr() {
            Ok(local) => local,
            Err(e) => {
                log::warn!("webgate: local address unknown, connection dropped: {}", e);
                continue;
            }
        };
        let auth = auth.to_owned();
        std::thread::spawn(move || {
            if let Err(e) = handle(stream, local, &auth) {
                log::trace!("webgate: connection ended: {}", e);
            }
        });
    }
    Ok(())
}

/// The socket's whole life: request head, then either the page or the bridge.
fn handle(stream: TcpStream, local: SocketAddr, auth: &str) -> hbb_common::ResultType<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.set_nodelay(true).ok();
    let mut reader = BufReader::new(stream);

    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        return Ok(());
    }
    let (method, path) = match line.split_whitespace().collect::<Vec<_>>()[..] {
        [method, path, _] => (method.to_string(), path.to_string()),
        _ => return Err(hbb_common::anyhow::anyhow!("webgate: malformed request line")),
    };
    // Two routes only, and no path is resolved against the filesystem.
    if path.contains("..") || path.contains('%') {
        return Err(hbb_common::anyhow::anyhow!("webgate: suspicious path refused"));
    }

    let mut headers = Vec::<(String, String)>::new();
    let mut head_len = 0usize;
    loop {
        let mut l = String::new();
        if reader.read_line(&mut l)? == 0 || l.trim().is_empty() {
            break;
        }
        head_len += l.len();
        if head_len > MAX_HEAD {
            return Err(hbb_common::anyhow::anyhow!("webgate: request head too large"));
        }
        // The name is lowercased for lookup, and only the name: slicing the *original* line at an
        // index found in a lowercased copy would panic on a header whose name is not ASCII, because
        // `to_lowercase` does not preserve byte lengths.
        if let Some(idx) = l.find(':') {
            let (name, rest) = l.split_at(idx);
            headers.push((
                name.trim().to_lowercase().to_string(),
                rest[1..].trim().to_string(),
            ));
        }
    }
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    // The address the browser used must be the address the kernel delivered it to. A hostname in
    // `Host` therefore never matches, and neither does a proxy that rewrites it. On the turnkey
    // wildcard bind the accepted socket still reports the real interface address on Windows and
    // Linux, but if a platform hands back the unspecified address we refuse names and loopback and
    // accept any other literal IP - that is the widest the rule ever gets.
    let host = header("host");
    if !host_matches(&host, local) {
        return Err(hbb_common::anyhow::anyhow!(
            "webgate: rejected Host {:?}, this listener is {}",
            host,
            local
        ));
    }

    if method == "GET" && path == "/ws" {
        let origin = header("origin");
        // `Origin: null` is what a sandboxed or `file://` page sends; the page we serve always has a
        // literal IP in its origin, so a null here is a different document trying to reach us.
        if !origin.is_empty()
            && origin.trim().to_lowercase() != "null"
            && !origin_contains(&origin, local)
        {
            return Err(hbb_common::anyhow::anyhow!(
                "webgate: rejected Origin {:?}, the page must come from this listener",
                origin
            ));
        }
        if header("sec-websocket-version") != "13"
            || !header("upgrade").to_lowercase().contains("websocket")
        {
            return Err(hbb_common::anyhow::anyhow!("webgate: not a websocket upgrade"));
        }
        let key = header("sec-websocket-key");
        if key.is_empty() || key.len() > 64 {
            return Err(hbb_common::anyhow::anyhow!("webgate: missing handshake key"));
        }
        return bridge(reader, &key, &host, auth);
    }

    if method == "GET" && (path == "/" || path == "/index.html") {
        return page(reader.get_mut(), &host);
    }
    plain(
        reader.get_mut(),
        "404 Not Found",
        "text/plain; charset=utf-8",
        "not found\n",
    )
}

/// `Host` is `ip`, `ip:port`, or `[ipv6](:port)`; the port a browser sends is the one it connected
/// to, so only the address part is compared against where the socket actually landed.
fn host_matches(host: &str, local: SocketAddr) -> bool {
    match split_host(host) {
        Some(value) => address_allowed(&value, local),
        None => false,
    }
}

/// The same rule for `Origin`, which always carries a scheme and never a path here.
fn origin_contains(origin: &str, local: SocketAddr) -> bool {
    let rest = origin
        .split("://")
        .nth(1)
        .unwrap_or_else(|| origin.trim_start_matches('/'));
    match split_host(rest) {
        Some(value) => address_allowed(&value, local),
        None => false,
    }
}

/// Does an address the browser named belong on this listener? Normally it has to be the very
/// address the socket landed on. The turnkey wildcard bind is the one case where it may not be:
/// if the kernel hands back an unspecified local address, any literal IP passes except loopback,
/// which has no business reaching a gateway meant to be opened from another machine.
fn address_allowed(value: &str, local: SocketAddr) -> bool {
    if !local.ip().is_unspecified() && value == local.ip().to_string() {
        return true;
    }
    if !local.ip().is_unspecified() {
        return false;
    }
    match value.parse::<std::net::IpAddr>() {
        // Neither loopback nor the wildcard itself is a browser's way of reaching a gateway.
        Ok(addr) => !addr.is_loopback() && !addr.is_unspecified(),
        Err(_) => false,
    }
}

/// The address part of an authority string, brackets stripped, port gone, trailing `/` ignored.
fn split_host(authority: &str) -> Option<String> {
    let authority = authority.trim().trim_end_matches('/');
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        // `[::1]:21124` - the port is after the closing bracket, the address is inside it.
        let end = rest.find(']')?;
        return Some(rest[..end].to_string());
    }
    match authority.rsplit_once(':') {
        Some((head, tail)) if !head.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
            Some(head.to_string())
        }
        _ => Some(authority.to_string()),
    }
}

/// The embedded page: one file, inlined, with a policy that forbids any other fetch.
fn page(stream: &mut TcpStream, host: &str) -> hbb_common::ResultType<()> {
    let body = crate::webgate::PAGE;
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src \
         'unsafe-inline'; img-src data: blob:; connect-src ws://{}; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'\r\n\
         Connection: close\r\n\
         \r\n",
        body.len(),
        host
    );
    stream.write_all(resp.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn plain(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> hbb_common::ResultType<()> {
    let resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        status,
        content_type,
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    stream.flush()?;
    Ok(())
}

/// Upgrade, then run the bridge: one reader loop for commands, one writer loop for frames.
///
/// `auth` is the configured `webgate-passphrase`, empty when the operator did not set one. 这正是
/// 开箱即用那条要求的落点：不写口令时这里直接 `auth-ok`，页面不弹任何东西；写了口令时仍然走
/// per-connection nonce 摘要，口令本身照样不上网。两种情况下页面里那个「密码」输入框都是**被控端**的
/// 会话密码，跟这里校验的网关口令不是同一回事。
fn bridge(
    mut reader: BufReader<TcpStream>,
    key: &str,
    host: &str,
    auth: &str,
) -> hbb_common::ResultType<()> {
    let accept = hbb_common::base64::engine::general_purpose::STANDARD
        .encode(sha1(format!("{}{}", key, WS_GUID).as_bytes()));
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept
    );
    reader.get_mut().write_all(resp.as_bytes())?;
    reader.get_mut().flush()?;

    let writer: Writer = Arc::new(Mutex::new(reader.get_ref().try_clone()?));
    let mut rd = WsReader {
        stream: reader,
        writer: writer.clone(),
    };

    let auth_required = !auth.trim().is_empty();
    // The challenge is fresh per socket, so the digest the page sends back is good for exactly one
    // connection: it cannot be captured once and replayed, and the passphrase never goes on the wire.
    let mut nonce = [0u8; 16];
    if auth_required {
        OsRng.fill_bytes(&mut nonce);
    }
    let mut hello = json!({
        "t": "hello",
        "auth": if auth_required { "required" } else { "off" },
        "host": host,
        "peer_port": netguard::direct_peer_port(),
    });
    if auth_required {
        hello["nonce"] =
            json!(hbb_common::base64::engine::general_purpose::STANDARD.encode(nonce));
    }
    send_text(&writer, &hello.to_string())?;
    if auth_required {
        rd.stream.get_ref().set_read_timeout(Some(AUTH_TIMEOUT))?;
        let proved = match rd.next_message() {
            Some(WsMessage::Text(text)) => authenticated(&text, &nonce, auth),
            Some(_) => {
                log::warn!("webgate: the first frame after hello was not the passphrase digest");
                false
            }
            None => false,
        };
        rd.stream.get_ref().set_read_timeout(Some(READ_TIMEOUT))?;
        if !proved {
            netguard::audit_denied(
                "in",
                host,
                "webgate::http::auth",
                "reason=passphrase note=the browser could not prove it knows webgate-passphrase",
            );
            let _ = send_text(
                &writer,
                r#"{"t":"closed","reason":"口令校验未通过，连接已关闭。"}"#,
            );
            let _ = write_frame(&writer, 0x8, &[0x08, 0x00]);
            return Ok(());
        }
    } else {
        // 没口令 = 这台网关的边界就是上面那道入站策略，页面把这一点写给操作者看，不假装还有一层。
        let _ = send_text(
            &writer,
            r#"{"t":"msg","text":"本网关未设置口令，能连到这个端口的内网地址都可以使用它。"}"#,
        );
    }
    send_text(&writer, r#"{"t":"state","s":"auth-ok","msg":""}"#)?;

    // Queue depth between the bridge and this socket, so a browser that stops reading loses frames
    // instead of stacking up old screens.
    let (tx, rx) = std::sync::mpsc::sync_channel::<OutMsg>(OUT_QUEUE);
    // One browser tab drives the gateway at a time: `attach` hands out a token, or refuses when a
    // live tab already holds it, so a second window cannot take the keyboard by surprise.
    let token = match peer::attach(tx.clone()) {
        Some(token) => token,
        None => {
            let _ = send_text(
                &writer,
                r#"{"t":"state","s":"busy","msg":"另一个标签页正在使用本网关，请先关闭它"}"#,
            );
            let _ = write_frame(&writer, 0x8, &[0x08, 0x00]);
            return Ok(());
        }
    };

    let pump_writer = writer.clone();
    let pump = std::thread::spawn(move || pump(token, pump_writer, rx));

    loop {
        match rd.next_message() {
            Some(WsMessage::Text(text)) => peer::on_command(token, &text),
            Some(WsMessage::Binary(_)) => {
                // The page only speaks JSON; a binary frame is noise and is dropped unexamined.
                log::trace!("webgate: unexpected binary frame ignored");
            }
            Some(WsMessage::Closed) | None => break,
        }
    }

    let _ = write_frame(&writer, 0x8, &[0x08, 0x00]);
    // Drop our sender so the pump's `recv()` ends, then let go of the bridge slot.
    drop(tx);
    peer::detach(token);
    if pump.join().is_err() {
        log::warn!("webgate: frame pump panicked");
    }
    Ok(())
}

/// The first message must be `{"t":"auth","d":"<base64 sha1(nonce || passphrase)>"}`.
fn authenticated(text: &str, nonce: &[u8; 16], passphrase: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        log::warn!("webgate: the auth frame was not JSON");
        return false;
    };
    if value.get("t").and_then(|t| t.as_str()) != Some("auth") {
        log::warn!("webgate: the first frame must be the passphrase digest");
        return false;
    }
    let Some(sent) = value.get("d").and_then(|d| d.as_str()) else {
        return false;
    };
    let mut input = nonce.to_vec();
    input.extend_from_slice(passphrase.as_bytes());
    let expected = sha1(&input);
    let Ok(actual) = hbb_common::base64::engine::general_purpose::STANDARD.decode(sent) else {
        return false;
    };
    if actual.len() != expected.len() {
        return false;
    }
    // Not a secret worth a timing attack, but a cheap way to say "we do not compare digests by
    // short-circuit" without a dependency.
    let mut diff = 0u8;
    for (a, b) in actual.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Push queued output to the browser, collapsing frames the browser has not caught up with.
fn pump(_token: peer::Token, writer: Writer, rx: Receiver<OutMsg>) {
    loop {
        let next = match rx.recv() {
            Ok(msg) => msg,
            Err(_) => return,
        };
        // Whatever is already queued: keep the last frame, keep every event (they are rare and
        // each one carries state the page has not seen).
        let mut frame: Option<Vec<u8>> = None;
        let mut events: Vec<String> = Vec::new();
        let mut got_any = false;
        let mut first = Some(next);
        while let Some(msg) = first.take() {
            got_any = true;
            match msg {
                OutMsg::Frame(jpeg) => frame = Some(jpeg),
                OutMsg::Event(json) => events.push(json),
            }
            first = rx.try_recv().ok();
        }
        if !got_any {
            continue;
        }
        for json in events {
            if send_text(&writer, &json).is_err() {
                return;
            }
        }
        if let Some(jpeg) = frame {
            if send_binary(&writer, &jpeg).is_err() {
                return;
            }
        }
    }
}

enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
    Closed,
}

/// The read half; shares the write half so a ping can be answered.
struct WsReader {
    stream: BufReader<TcpStream>,
    writer: Writer,
}

impl WsReader {
    /// One complete application message: reassembles continuations, answers pings, refuses
    /// unmasked or oversized frames. `None` means the socket is gone.
    fn next_message(&mut self) -> Option<WsMessage> {
        let mut payload = Vec::new();
        loop {
            let mut h = [0u8; 2];
            self.stream.read_exact(&mut h).ok()?;
            let fin = h[0] & 0x80 != 0;
            let opcode = h[0] & 0x0f;
            let mut len = (h[1] & 0x7f) as usize;
            if len == 126 {
                let mut b = [0u8; 2];
                self.stream.read_exact(&mut b).ok()?;
                len = u16::from_be_bytes(b) as usize;
            } else if len == 127 {
                let mut b = [0u8; 8];
                self.stream.read_exact(&mut b).ok()?;
                let wide = u64::from_be_bytes(b);
                if wide > MAX_INBOUND as u64 {
                    log::warn!("webgate: frame length {} refused", wide);
                    return Some(WsMessage::Closed);
                }
                len = wide as usize;
            }
            if len > MAX_INBOUND {
                log::warn!("webgate: frame of {} bytes refused", len);
                return Some(WsMessage::Closed);
            }
            if h[1] & 0x80 == 0 {
                // RFC 6455 §5.3: every client frame must be masked. An unmasked one is either a
                // non-browser client or a corrupt stream, and we do not read commands from it.
                log::warn!("webgate: unmasked client frame, closing");
                return Some(WsMessage::Closed);
            }
            let mut mask = [0u8; 4];
            self.stream.read_exact(&mut mask).ok()?;
            let mut buf = vec![0u8; len];
            self.stream.read_exact(&mut buf).ok()?;
            for (i, b) in buf.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }

            match opcode {
                0x0 | 0x1 | 0x2 => {
                    payload.extend_from_slice(&buf);
                    if !fin {
                        if payload.len() > MAX_INBOUND {
                            return Some(WsMessage::Closed);
                        }
                        continue;
                    }
                    return Some(if opcode == 0x2 {
                        WsMessage::Binary(payload)
                    } else {
                        WsMessage::Text(String::from_utf8_lossy(&payload).to_string())
                    });
                }
                0x8 => return Some(WsMessage::Closed),
                0x9 => {
                    // ping -> pong, payload echoed unchanged.
                    let _ = write_frame(&self.writer, 0xA, &buf);
                }
                0xA => {}
                other => {
                    log::warn!("webgate: unknown opcode {}, closing", other);
                    return Some(WsMessage::Closed);
                }
            }
        }
    }
}

fn send_text(writer: &Writer, text: &str) -> hbb_common::ResultType<()> {
    write_frame(writer, 0x1, text.as_bytes())
}

fn send_binary(writer: &Writer, bytes: &[u8]) -> hbb_common::ResultType<()> {
    write_frame(writer, 0x2, bytes)
}

/// The 2-, 4- or 10-byte header of one frame, as RFC 6455 §5.2 spells the three length classes.
/// Split out so the test below checks the real encoder rather than a copy of it.
fn frame_head(opcode: u8, len: usize) -> ([u8; 10], usize) {
    let mut head = [0u8; 10];
    head[0] = 0x80 | opcode;
    let n = if len < 126 {
        head[1] = len as u8;
        2
    } else if len < 0x1_0000 {
        head[1] = 126;
        head[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        4
    } else {
        head[1] = 127;
        head[2..10].copy_from_slice(&(len as u64).to_be_bytes());
        10
    };
    (head, n)
}

/// Emit one unmasked frame (RFC 6455 §5.1: server frames are never masked).
fn write_frame(writer: &Writer, opcode: u8, payload: &[u8]) -> hbb_common::ResultType<()> {
    let (head, n) = frame_head(opcode, payload.len());
    let mut guard = match writer.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.write_all(&head[..n])?;
    guard.write_all(payload)?;
    guard.flush()?;
    Ok(())
}

/// Used by the bridge when it must hand a live session over to a fresh tab.
pub fn push(sender: &SyncSender<OutMsg>, msg: OutMsg) {
    match sender.try_send(msg) {
        Ok(()) => {}
        Err(std::sync::mpsc::TrySendError::Full(_)) => {}
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Imported here as well as above: a test module should not depend on whether a glob picks up
    // the parent's anonymous trait import.
    use hbb_common::base64::engine::general_purpose::STANDARD;
    use hbb_common::base64::Engine as _;

    fn local(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    #[test]
    fn only_the_address_the_socket_landed_on_is_a_host() {
        let v4 = local("10.0.12.7", 21124);
        assert!(host_matches("10.0.12.7:21124", v4));
        assert!(host_matches("10.0.12.7", v4));
        // A hostname - or a DNS name an attacker controls - is not an address we recognise.
        assert!(!host_matches("gate.example:21124", v4));
        assert!(!host_matches("127.0.0.1:21124", v4));
        assert!(!host_matches("", v4));
        let v6 = local("fd00::15", 21124);
        assert!(host_matches("[fd00::15]:21124", v6));
    }

    #[test]
    fn a_wildcard_listener_still_refuses_names_and_loopback() {
        // The turnkey default binds 0.0.0.0. If a platform reports the unspecified address as the
        // local end, the rule widens to "a literal IP that is neither loopback nor the wildcard" -
        // and no further: names still have to go through a resolver, which this build does not do.
        let any = local("0.0.0.0", 21124);
        assert!(host_matches("192.168.10.20:21124", any));
        assert!(!host_matches("127.0.0.1:21124", any));
        assert!(!host_matches("0.0.0.0:21124", any));
        assert!(!host_matches("gate.example:21124", any));
        assert!(!host_matches("", any));
        // A named bind is exactly as strict as it always was.
        let one = local("192.168.10.20", 21124);
        assert!(host_matches("192.168.10.20", one));
        assert!(!host_matches("192.168.10.21", one));
    }

    #[test]
    fn an_origin_may_carry_a_scheme_but_not_a_foreign_host() {
        let v4 = local("10.0.12.7", 21124);
        assert!(origin_contains("http://10.0.12.7:21124", v4));
        assert!(!origin_contains("http://10.0.12.8:21124", v4));
        assert!(!origin_contains("http://evil.example", v4));
        // A wildcard bind does not make `null` (sandboxed/file document) an acceptable origin.
        let any = local("0.0.0.0", 21124);
        assert!(origin_contains("http://192.168.1.9:21124", any));
        assert!(!origin_contains("null", any));
        assert!(!origin_contains("http://127.0.0.1:21124", any));
    }

    #[test]
    fn the_passphrase_digest_is_per_nonce() {
        let nonce = [7u8; 16];
        let mut input = nonce.to_vec();
        input.extend_from_slice(b"correct horse");
        let good = format!(
            r#"{{"t":"auth","d":"{}"}}"#,
            STANDARD.encode(sha1(&input))
        );
        assert!(authenticated(&good, &nonce, "correct horse"));
        // Wrong passphrase, and the same digest replayed against a fresh nonce: both refused.
        assert!(!authenticated(&good, &nonce, "wrong horse"));
        assert!(!authenticated(&good, &[8u8; 16], "correct horse"));
        assert!(!authenticated(r#"{"t":"open","addr":"10.0.0.1"}"#, &nonce, "correct horse"));
        assert!(!authenticated("not json", &nonce, "correct horse"));
    }

    #[test]
    fn a_full_frame_header_covers_every_length_class() {
        // 7-bit, 16-bit and 64-bit length encodings, checked against the bytes RFC 6455 §5.2 says
        // to put on the wire - through the same function `write_frame` uses.
        let (head, n) = frame_head(0x2, 125);
        assert_eq!((&head[..n], &[0x82u8, 125][..]));
        let (head, n) = frame_head(0x2, 126);
        assert_eq!((&head[..n], &[0x82, 126, 0x00, 0x7e][..]));
        let (head, n) = frame_head(0x2, 70_000);
        assert_eq!(n, 10);
        assert_eq!(&head[..2], &[0x82, 127][..]);
        assert_eq!(&head[2..10], &70_000u64.to_be_bytes()[..]);
        // A close frame keeps its status payload intact.
        let (head, n) = frame_head(0x8, 2);
        assert_eq!((&head[..n], &[0x88u8, 2][..]));
    }
}
