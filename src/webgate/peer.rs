// netguard webgate: the peer half of the bridge, an `InvokeUiSession` whose window is a browser tab.
//
// Everything the peer sends that a remote-control page needs becomes either a JSON event or one JPEG
// frame, and everything the page sends becomes a call to the *same* `Session` methods the Flutter UI
// calls. That is the whole design: there is no second implementation of RustDesk's protocol here, no
// second codec path, no re-derived input semantics. The handshake, crypto, decoding and the peer's
// own permission checks all stay in `crate::client`, so a page cannot do anything the desktop client
// could not do from the same machine.
//
// Shape of the state, and why it is split this way:
//
//   * one gateway serves one tab (`GATE`), because two tabs driving one keyboard is a support ticket;
//   * `GATE` owns the strong `Arc<Session<WebUi>>`; `WebUi` holds only a `Weak`, because `Session`
//     already owns its `WebUi` - an `Arc` back would pin the pair forever once the tab closes;
//   * `WebUi` never takes the `GATE` lock while calling into the session, and `peer` never calls a
//     session method while holding it, so the two locks cannot form a cycle.

use super::http::{self, OutMsg};
use crate::client::{Data, Interface, QualityStatus};
use crate::ui_session_interface::{io_loop, InvokeUiSession, Session};
use base::message_proto::*;
use hbb_common::base64::Engine as _;
use hbb_common::config::Config;
use hbb_common::log;
use hbb_common::netguard;
use hbb_common::rendezvous_proto::ConnType;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, RwLock, Weak};

/// Identifies the one tab that currently owns the gateway. Handed out by [`attach`], checked by
/// every command, and retired by [`detach`].
pub type Token = u64;

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

lazy_static::lazy_static! {
    static ref GATE: RwLock<Option<Gate>> = RwLock::new(None);
}

struct Gate {
    token: Token,
    ui: WebUi,
    session: Option<Arc<Session<WebUi>>>,
}

/// Poisoning is not a failure mode worth killing a remote-control page over: a panicked frame is
/// already gone, and the data behind these locks is either an `Option` or a socket sender.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn rlock<T>(r: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    r.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wlock<T>(r: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    r.write().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What the page is allowed to be told about the gateway itself. Kept in one place so a
/// future reader can see the whole disclosure surface of the unauthenticated half.
#[derive(Default)]
struct UiState {
    /// The browser's queue; `None` once the socket is gone.
    out: Option<SyncSender<OutMsg>>,
    /// Back-reference for the handlers that must drive the session (login, options).
    session: Weak<Session<WebUi>>,
    /// Re-encode level for the browser frame, separate from the peer's own image quality.
    jpeg_quality: u8,
    /// The passphrase-side password the operator typed in the page, kept for the password prompt.
    password: String,
    /// Guards the prompt loop: a wrong password must not be replayed forever.
    password_attempts: u32,
    /// Which display the page is looking at, for `refresh` and coordinate sanity.
    display: i32,
    /// The peer's frame size, so the page can be told when it changes.
    width: i32,
    height: i32,
    /// True once the peer has embedded its cursor in the video; the page must then not draw one.
    cursor_embedded: bool,
    /// The peer's version string, which decides whether it understands multi-clipboard messages.
    peer_version: String,
}

/// The UI of one [`Session`]: every callback turns into a WebSocket message.
#[derive(Clone, Default)]
pub struct WebUi {
    state: Arc<Mutex<UiState>>,
}

impl WebUi {
    fn emit(&self, msg: OutMsg) {
        let sender = lock(&self.state).out.clone();
        if let Some(sender) = sender {
            http::push(&sender, msg);
        }
    }

    fn event(&self, value: Value) {
        self.emit(OutMsg::Event(value.to_string()))
    }

    fn emit_state(&self, s: &str, msg: &str) {
        self.event(json!({"t": "state", "s": s, "msg": msg}));
    }

    /// Plain prose for the status line; the page never has to parse it.
    fn note(&self, msg: &str) {
        self.event(json!({"t": "msg", "text": msg}));
    }

    fn session(&self) -> Option<Arc<Session<WebUi>>> {
        lock(&self.state).session.upgrade()
    }

    fn with_session<R, F: FnOnce(&Session<WebUi>) -> R>(&self, f: F) -> Option<R> {
        // The upgrade happens under the lock, the call happens after it is dropped.
        let session = self.session();
        session.as_ref().map(|s| f(s.as_ref()))
    }

    fn jpeg_quality(&self) -> u8 {
        lock(&self.state).jpeg_quality
    }

    fn set_geometry(&self, w: i32, h: i32, display: i32, embedded: bool) {
        let mut state = lock(&self.state);
        state.width = w;
        state.height = h;
        state.display = display;
        state.cursor_embedded = embedded;
    }

    /// Push a stored password through the ordinary UI login path. Called from the password prompt,
    /// which by construction happens after `io_loop` owns a sender, so the data is never dropped.
    fn try_login(&self) {
        let password = lock(&self.state).password.clone();
        if password.is_empty() {
            self.note("没有可用的口令，请在连接表单里填写被控端密码。");
            return;
        }
        let attempts = {
            let mut state = lock(&self.state);
            state.password_attempts += 1;
            state.password_attempts
        };
        if attempts > 3 {
            self.note("口令连续 3 次被拒绝，已停止自动重试。请核对后重新连接。");
            self.close_session();
            return;
        }
        self.with_session(|s| {
            s.login(String::new(), String::new(), password, false);
        });
    }

    fn close_session(&self) {
        if let Some(session) = self.session() {
            session.close();
        }
    }

    fn toggle_if_needed(&self, name: &str, want: bool) {
        let current = self.with_session(|s| s.get_toggle_option(name.to_string()));
        if current == Some(want) {
            return;
        }
        self.with_session(|s| s.toggle_option(name.to_owned()));
    }
}

impl InvokeUiSession for WebUi {
    // ---------------------------------------------------------------- video
    fn on_rgba(&self, _display: usize, rgba: &mut scrap::ImageRgb) {
        // The peer's decoder wrote a 32-bit buffer here. `VideoHandler` picks the layout itself
        // (`ABGR` on the flutter Windows/Linux build, `ARGB` elsewhere), and `align` is only > 1 on
        // macOS, so the two facts below are the whole conversion; anything else is refused rather
        // than guessed at, because a wrong byte order looks like a plausible blue-orange picture.
        let (w, h) = (rgba.w, rgba.h);
        let (swap_red_blue, bytes_per_pixel) = match rgba.fmt {
            // Four bytes per pixel, already in R,G,B,A order.
            scrap::ImageFormat::ABGR => (false, 4),
            // The same buffer with the channels reversed, which is the macOS/non-flutter layout.
            scrap::ImageFormat::ARGB => (true, 4),
            other => {
                log::warn!("webgate: unsupported rgb format {:?}, frame dropped", other);
                return;
            }
        };
        if w == 0 || h == 0 || rgba.align > 1 {
            return;
        }
        let expected = w * h * bytes_per_pixel;
        if rgba.raw.len() < expected {
            log::warn!(
                "webgate: rgb buffer {} shorter than {}x{} needs {}",
                rgba.raw.len(),
                w,
                h,
                expected
            );
            return;
        }
        let quality = self.jpeg_quality();
        // Encode on this thread. A stalled browser drops frames in [`crate::webgate::http::push`]
        // instead of queueing old screens, so the page always shows the newest frame it can carry.
        //
        // The alpha byte is dropped by hand rather than through `image::RgbaImage`: jpeg takes
        // `ColorType::Rgb8`, and building the packed buffer ourselves is one copy instead of two.
        let mut rgb = Vec::with_capacity(w * h * 3);
        for px in rgba.raw[..expected].chunks_exact(4) {
            if swap_red_blue {
                rgb.extend_from_slice(&[px[2], px[1], px[0]]);
            } else {
                rgb.extend_from_slice(&px[..3]);
            }
        }
        let mut encoded = Vec::new();
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut encoded, quality);
        if encoder
            .encode(&rgb, w as u32, h as u32, image::ColorType::Rgb8)
            .is_err()
        {
            log::warn!("webgate: jpeg encode failed");
            return;
        }
        self.emit(OutMsg::Frame(encoded));
    }

    // ---------------------------------------------------------------- geometry
    fn set_display(&self, _x: i32, _y: i32, w: i32, h: i32, cursor_embedded: bool, scale: f64) {
        let display = lock(&self.state).display;
        self.set_geometry(w, h, display, cursor_embedded);
        self.event(json!({
            "t": "geom",
            "w": w,
            "h": h,
            "disp": display,
            "embedded": cursor_embedded,
            "scale": scale,
        }));
    }

    fn switch_display(&self, display: &SwitchDisplay) {
        self.set_geometry(
            display.width,
            display.height,
            display.display,
            display.cursor_embedded,
        );
        // No `scale` here: `SwitchDisplay` does not carry one, only `set_display` does.
        self.event(json!({
            "t": "geom",
            "w": display.width,
            "h": display.height,
            "disp": display.display,
            "embedded": display.cursor_embedded,
        }));
    }

    fn set_current_display(&self, disp_idx: i32) {
        lock(&self.state).display = disp_idx;
    }

    fn set_displays(&self, displays: &Vec<DisplayInfo>) {
        let list: Vec<Value> = displays
            .iter()
            .enumerate()
            .map(|(i, d)| {
                json!({
                    "i": i,
                    "name": d.name,
                    "w": d.width,
                    "h": d.height,
                    "online": d.online,
                })
            })
            .collect();
        self.event(json!({"t": "displays", "list": list}));
    }

    fn adapt_size(&self) {}

    // ---------------------------------------------------------------- cursor
    fn set_cursor_data(&self, cd: CursorData) {
        // Same helper the desktop UI uses for cursor shapes: the peer sends RGBA bottom-up, and
        // `repng` is what turns that into a PNG the browser can show.
        if cd.width <= 0 || cd.height <= 0 {
            return;
        }
        let mut colors: Vec<u8> = cd.colors.into();
        if colors.iter().all(|b| *b == 0) {
            // Upstream's workaround for an all-transparent shape drawing as a black rectangle.
            if colors.is_empty() {
                colors.resize(4, 0);
            }
            colors[3] = 1;
        }
        let mut png = Vec::new();
        if repng::encode(&mut png, cd.width as _, cd.height as _, &colors).is_err() {
            log::warn!("webgate: cursor png encode failed");
            return;
        }
        self.event(json!({
            "t": "cursor",
            "id": cd.id.to_string(),
            "w": cd.width,
            "h": cd.height,
            "hotx": cd.hotx,
            "hoty": cd.hoty,
            "png": hbb_common::base64::engine::general_purpose::STANDARD.encode(&png),
        }));
    }

    /// The peer caches shapes by id and switches between them without resending pixels; a browser
    /// that ignored this would keep drawing the last shape it was given.
    fn set_cursor_id(&self, id: String) {
        self.event(json!({ "t": "cursor-id", "id": id }));
    }

    fn set_cursor_position(&self, cp: CursorPosition) {
        let embedded = lock(&self.state).cursor_embedded;
        self.event(json!({
            "t": "cursor-pos",
            "x": cp.x,
            "y": cp.y,
            "embedded": embedded,
        }));
    }

    // ---------------------------------------------------------------- identity
    fn set_peer_info(&self, pi: &PeerInfo) {
        lock(&self.state).peer_version = pi.version.clone();
        self.event(json!({
            "t": "info",
            "platform": pi.platform,
            "username": pi.username,
            "hostname": pi.hostname,
            "version": pi.version,
            "displays": pi.displays.len(),
        }));
    }

    fn set_platform_additions(&self, _data: &str) {}

    fn set_fingerprint(&self, fingerprint: String) {
        self.event(json!({"t": "fingerprint", "value": fingerprint}));
    }

    fn set_connection_type(&self, is_secured: bool, direct: bool, stream_type: &str) {
        self.event(json!({
            "t": "transport",
            "secured": is_secured,
            "direct": direct,
            "stream": stream_type,
        }));
    }

    fn on_connected(&self, _conn_type: ConnType) {
        lock(&self.state).password_attempts = 0;
        self.emit_state("connected", "");
        let view = self
            .with_session(|s| s.get_toggle_option("view-only".to_string()))
            .unwrap_or(false);
        self.event(json!({"t": "settings", "view": view}));
    }

    fn close_success(&self) {
        self.emit_state("disconnected", "对端已结束会话");
    }

    fn update_privacy_mode(&self) {
        self.note("对端开启了隐私模式。");
    }

    fn set_permission(&self, name: &str, value: bool) {
        self.event(json!({"t": "perm", "name": name, "on": value}));
    }

    fn update_block_input_state(&self, on: bool) {
        self.event(json!({"t": "block-input", "on": on}));
    }

    fn update_quality_status(&self, qs: QualityStatus) {
        self.event(json!({
            "t": "stat",
            "fps": qs.fps.values().copied().max().unwrap_or(0),
            "speed": qs.speed.clone().unwrap_or_default(),
            "delay": qs.delay.unwrap_or(0),
        }));
    }

    fn update_record_status(&self, start: bool) {
        self.event(json!({"t": "recording", "on": start}));
    }

    fn set_multiple_windows_session(&self, sessions: Vec<WindowsSession>) {
        let list: Vec<Value> = sessions
            .iter()
            .map(|s| json!({"sid": s.sid, "name": s.name}))
            .collect();
        self.event(json!({"t": "sessions", "list": list}));
    }

    fn msgbox(&self, msgtype: &str, title: &str, text: &str, _link: &str, retry: bool) {
        match msgtype {
            "input-password" | "re-input-password" => {
                self.event(json!({
                    "t": "msgbox", "type": msgtype, "title": title, "text": text, "retry": retry,
                }));
                self.try_login();
            }
            "success" => {
                self.note(&format!("{}：{}", title, text));
            }
            other => {
                // Errors, questions and the insecure-connection prompt all reach the page unchanged;
                // the page decides what a button means, the gateway never answers on its own.
                self.event(json!({
                    "t": "msgbox", "type": other, "title": title, "text": text, "retry": retry,
                }));
            }
        }
    }

    fn cancel_msgbox(&self, tag: &str) {
        self.event(json!({"t": "msgbox-cancel", "tag": tag}));
    }

    fn new_message(&self, msg: String) {
        self.event(json!({"t": "chat", "text": msg}));
    }

    // ---------------------------------------------------------------- no window here
    fn job_error(&self, _id: i32, _err: String, _file_num: i32) {}
    fn job_done(&self, _id: i32, _file_num: i32) {}
    fn clear_all_jobs(&self) {}
    fn update_transfer_list(&self) {}
    fn load_last_job(&self, _cnt: i32, _job_json: &str, _auto_start: bool) {}
    fn update_folder_files(
        &self,
        _id: i32,
        _entries: &Vec<FileEntry>,
        _path: String,
        _is_local: bool,
        _only_count: bool,
    ) {
    }
    fn confirm_delete_files(&self, _id: i32, _i: i32, _name: String) {}
    fn override_file_confirm(
        &self,
        _id: i32,
        _file_num: i32,
        _to: String,
        _is_upload: bool,
        _is_identical: bool,
    ) {
    }
    fn job_progress(&self, _id: i32, _file_num: i32, _speed: f64, _finished_size: f64) {}
    fn switch_back(&self, _id: &str) {}
    fn portable_service_running(&self, _running: bool) {}
    fn on_voice_call_started(&self) {}
    fn on_voice_call_closed(&self, _reason: &str) {}
    fn on_voice_call_waiting(&self) {}
    fn on_voice_call_incoming(&self) {}
    fn get_rgba(&self, _display: usize) -> *const u8 {
        std::ptr::null()
    }
    fn next_rgba(&self, _display: usize) {}
    fn printer_request(&self, _id: i32, _path: String) {}
    fn handle_screenshot_resp(&self, _sid: String, _msg: String) {}
    fn handle_terminal_response(&self, _response: TerminalResponse) {}

    #[cfg(feature = "flutter")]
    fn is_multi_ui_session(&self) -> bool {
        // One tab, one session: the Flutter multi-window bookkeeping does not apply here.
        false
    }

    #[cfg(all(feature = "vram", feature = "flutter"))]
    fn on_texture(&self, _display: usize, _texture: *mut std::ffi::c_void) {
        // `webgate::run()` pins `use_texture_render()` to false, so the decoder never hands us a
        // GPU handle. If that ever changes, frames keep arriving in `on_rgba` and this stays a no-op.
    }
}

// ---------------------------------------------------------------------------
// The one bridge slot
// ---------------------------------------------------------------------------

/// Take the gateway's single bridge slot, or refuse when a live tab already holds it.
pub fn attach(out: SyncSender<OutMsg>) -> Option<Token> {
    let mut gate = wlock(&GATE);
    if gate.is_some() {
        return None;
    }
    let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
    let mut state = UiState::default();
    state.jpeg_quality = jpeg_quality_from(&Config::get_option("webgate-jpeg-quality"));
    state.out = Some(out);
    let ui = WebUi {
        state: Arc::new(Mutex::new(state)),
    };
    *gate = Some(Gate {
        token,
        ui,
        session: None,
    });
    Some(token)
}

/// Clamp what the page can ask for into something an encoder will accept.
fn jpeg_quality_from(raw: &str) -> u8 {
    match raw.trim().parse::<u8>() {
        Ok(quality) if (30..=95).contains(&quality) => quality,
        _ => 70,
    }
}

/// Drop the bridge slot; the session goes with it.
pub fn detach(token: Token) {
    let gate = {
        let mut gate = wlock(&GATE);
        if gate.as_ref().map(|g| g.token) == Some(token) {
            gate.take()
        } else {
            None
        }
    };
    if let Some(gate) = gate {
        if let Some(session) = gate.session {
            session.close();
        }
        // `gate.ui` goes out of scope here; its `out` sender is dropped, so the frame pump ends.
        log::info!("webgate: bridge {} detached", token);
    }
}

/// One JSON object per line of the contract in `mod.rs`.
pub fn on_command(token: Token, text: &str) {
    let (ui, session) = {
        let gate = rlock(&GATE);
        match gate.as_ref() {
            Some(gate) if gate.token == token => (gate.ui.clone(), gate.session.clone()),
            _ => return,
        }
    };
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(e) => {
            ui.note(&format!("网关无法解析该指令：{}", e));
            return;
        }
    };
    dispatch(&ui, session.as_ref(), &value);
}

fn str_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

fn int_field(value: &Value, key: &str, default: i64) -> i64 {
    value.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
}

fn bool_field(value: &Value, key: &str) -> bool {
    value.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn dispatch(ui: &WebUi, session: Option<&Arc<Session<WebUi>>>, value: &Value) {
    let kind = str_field(value, "t");
    match kind.as_str() {
        "open" => open_session(ui, value),
        "login" => {
            let password = str_field(value, "password");
            lock(&ui.state).password = password.clone();
            if let Some(session) = session {
                session.login(String::new(), String::new(), password, false);
            }
        }
        "insecure" => {
            let yes = bool_field(value, "yes");
            ui.with_session(|s| s.continue_insecure_connection(yes));
        }
        "mouse" => {
            if let Some(session) = session {
                send_mouse(ui, session.as_ref(), value);
            }
        }
        "key" => {
            if let Some(session) = session {
                // `input_key` takes the same names the Flutter UI sends: `VK_*` for the mapped keys
                // and any single character for the rest, so the page's key map needs no gateway-side
                // table beyond what upstream already ships.
                let name = str_field(value, "code");
                session.input_key(
                    &name,
                    bool_field(value, "down"),
                    bool_field(value, "press"),
                    bool_field(value, "alt"),
                    bool_field(value, "ctrl"),
                    bool_field(value, "shift"),
                    bool_field(value, "meta"),
                );
            }
        }
        "text" => {
            if let Some(session) = session {
                session.input_string(&str_field(value, "s"));
            }
        }
        "clip-set" => push_clipboard(ui, value),
        "clip-get" => pull_clipboard(ui),
        "display" => {
            if let Some(session) = session {
                session.switch_display(int_field(value, "i", 0) as i32);
            }
        }
        "refresh" => {
            if let Some(session) = session {
                let display = lock(&ui.state).display;
                session.refresh_video(display);
            }
        }
        "quality" => {
            if let Some(session) = session {
                session.save_image_quality(str_field(value, "v"));
            }
        }
        "custom-quality" => {
            if let Some(session) = session {
                session.save_custom_image_quality(int_field(value, "v", 50) as i32);
            }
        }
        "fps" => {
            if let Some(session) = session {
                session.set_custom_fps(int_field(value, "v", 30) as i32);
            }
        }
        "view" => ui.toggle_if_needed("view-only", bool_field(value, "on")),
        "remote-cursor" => ui.toggle_if_needed("show-remote-cursor", bool_field(value, "on")),
        "ctrlaltdel" => {
            // The `with_session` arms are statements, not arm values: the helper answers `Option`
            // so a command that arrives after the session is gone can be told apart from one that
            // ran, and a dropped session has nothing left to do about a late ctrl-alt-del.
            ui.with_session(|s| s.ctrl_alt_del());
        }
        "lock" => {
            ui.with_session(|s| s.lock_screen());
        }
        "select-session" => {
            let sid = int_field(value, "sid", 0).to_string();
            ui.with_session(|s| s.send_selected_session_id(sid));
        }
        "close" => {
            ui.emit_state("closing", "");
            ui.close_session();
        }
        "ping" => ui.event(json!({"t": "pong"})),
        other => ui.note(&format!("网关不认识指令 {:?}。", other)),
    }
}

/// Build a session for `addr` and let the ordinary `io_loop` do everything after that.
fn open_session(ui: &WebUi, value: &Value) {
    let addr = str_field(value, "addr");
    let password = str_field(value, "password");
    let view = bool_field(value, "view");
    if addr.is_empty() {
        ui.note("地址为空。请填写被控端的字面 IP，可带端口（例如 10.0.12.34:9001）。");
        return;
    }
    // Literal IP only, same rule as the desktop client: the resolver is not in this build, so a
    // hostname here would fail late and quietly instead of saying so now.
    if !crate::common::is_direct_ip_access(&addr) {
        netguard::audit_denied(
            "in",
            &addr,
            "webgate::peer::open",
            "reason=not_literal_ip note=the page may only name a literal address",
        );
        ui.note(&format!(
            "{:?} 不是字面 IP。本构建不做域名解析，请填写 IPv4，或带端口的 [IPv6]:端口。",
            addr
        ));
        return;
    }
    if let Some(session) = ui.session() {
        // Replacing a live session is a deliberate act, not a surprise: say so, then let the old
        // round wind down before the new one starts.
        ui.note("已断开上一个会话，正在按新的地址连接。");
        session.close();
    }
    {
        let mut state = lock(&ui.state);
        state.password = password.clone();
        state.password_attempts = 0;
    }

    let session: Session<WebUi> = Session {
        password: password.clone(),
        ui_handler: ui.clone(),
        server_keyboard_enabled: Arc::new(RwLock::new(true)),
        server_file_transfer_enabled: Arc::new(RwLock::new(true)),
        server_clipboard_enabled: Arc::new(RwLock::new(true)),
        ..Default::default()
    };
    // `adapter_luid` is `None` on purpose: the gateway has no GPU context, and a luid would put the
    // decoder on the texture path, where `on_rgba` never runs and the page would stay black.
    // `shared_password` stays `None` because the operator typed this password into a connect form,
    // which is exactly the "preset password" case the desktop UI uses; the `password` field above is
    // what `handle_hash` consumes when the peer asks for it.
    session
        .lc
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .initialize(
            addr.clone(),
            ConnType::DEFAULT_CONN,
            None,
            false,
            None,
            None,
            None,
        );

    let session = Arc::new(session);
    lock(&ui.state).session = Arc::downgrade(&session);
    {
        let mut gate = wlock(&GATE);
        if let Some(gate) = gate.as_mut() {
            gate.session = Some(session.clone());
        } else {
            return;
        }
    }
    // Only after the session exists: `toggle_option` writes the per-peer config *and* sends the
    // option message, and the login message reads that config - so view-only has to be recorded
    // before `io_loop` builds its login, and there is nothing to toggle against otherwise.
    if view {
        ui.toggle_if_needed("view-only", true);
    }
    ui.emit_state("connecting", &format!("正在连接 {}", addr));
    // A plain thread with its own current-thread runtime, which is how the Flutter UI starts a
    // session too; `io_loop` is `#[tokio::main(flavor = "current_thread")]`, so nothing nests.
    let runner = (*session).clone();
    std::thread::spawn(move || {
        let round = runner
            .connection_round_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .new_round();
        io_loop(runner, round);
    });
}

/// The mask is built exactly the way `flutter_ffi::session_mouse_event` builds it, because
/// `Session::send_mouse` is the same function either way.
fn send_mouse(_ui: &WebUi, session: &Session<WebUi>, value: &Value) {
    use crate::common::input::{
        MOUSE_BUTTON_BACK, MOUSE_BUTTON_FORWARD, MOUSE_BUTTON_LEFT, MOUSE_BUTTON_RIGHT,
        MOUSE_BUTTON_WHEEL, MOUSE_TYPE_DOWN, MOUSE_TYPE_UP, MOUSE_TYPE_WHEEL,
    };
    let mut mask = match str_field(value, "type").as_str() {
        "down" => MOUSE_TYPE_DOWN,
        "up" => MOUSE_TYPE_UP,
        "wheel" => MOUSE_TYPE_WHEEL,
        _ => 0,
    };
    let button = match str_field(value, "button").as_str() {
        "left" => MOUSE_BUTTON_LEFT,
        "right" => MOUSE_BUTTON_RIGHT,
        "wheel" => MOUSE_BUTTON_WHEEL,
        "back" => MOUSE_BUTTON_BACK,
        "forward" => MOUSE_BUTTON_FORWARD,
        _ => 0,
    };
    mask |= button << 3;
    let x = int_field(value, "x", 0) as i32;
    let y = int_field(value, "y", 0) as i32;
    session.send_mouse(
        mask,
        x,
        y,
        bool_field(value, "alt"),
        bool_field(value, "ctrl"),
        bool_field(value, "shift"),
        bool_field(value, "meta"),
    );
}

/// One plain-text clipboard entry, in the shape the peer expects.
fn clipboard_text(text: &str) -> Clipboard {
    Clipboard {
        compress: false,
        content: text.as_bytes().to_vec().into(),
        format: ClipboardFormat::Text.into(),
        ..Default::default()
    }
}

/// Send text to the peer through the same multi-clipboard message the desktop client uses, with the
/// same fallback for peers too old to understand it.
fn push_clipboard(ui: &WebUi, value: &Value) {
    let text = str_field(value, "text");
    let Some(session) = ui.session() else {
        ui.note("还没有连接，无法发送剪贴板。");
        return;
    };
    let version = lock(&ui.state).peer_version.clone();
    if version.is_empty() {
        ui.note("会话尚未就绪（对端信息还没到达），稍后再试。");
        return;
    }
    if !session.is_text_clipboard_required() {
        ui.note("对端不允许剪贴板同步（或当前是只观看模式）。");
        return;
    }
    let multi = MultiClipboards {
        clipboards: vec![clipboard_text(&text)],
        ..Default::default()
    };
    let platform = session.peer_platform();
    let msg = match crate::clipboard::get_msg_if_not_support_multi_clip(
        &version,
        &platform,
        &multi,
    ) {
        Some(old) => old,
        None => {
            let mut msg = Message::new();
            msg.set_multi_clipboards(multi);
            msg
        }
    };
    session.send(Data::Message(msg));
}

/// The peer's clipboard lands in this machine's clipboard through the ordinary client path, so
/// "pull" is a read of what is already here. Only Windows has a working read-back in this build.
fn pull_clipboard(ui: &WebUi) {
    #[cfg(target_os = "windows")]
    {
        match crate::clipboard::check_clipboard_cm() {
            Ok(multi) => {
                let text = multi
                    .clipboards
                    .iter()
                    .find(|c| {
                        c.format.enum_value() == Ok(base::message_proto::ClipboardFormat::Text)
                    })
                    .map(|c| {
                        let raw = if c.compress {
                            hbb_common::compress::decompress(&c.content)
                        } else {
                            c.content.to_vec()
                        };
                        String::from_utf8_lossy(&raw).to_string()
                    })
                    .unwrap_or_default();
                ui.event(json!({"t": "clip", "text": text}));
            }
            Err(e) => ui.note(&format!("读取本机剪贴板失败：{}", e)),
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // The non-Windows clipboard backends need a display server of their own; the page is told
        // rather than left guessing why nothing came back.
        ui.note("当前构建只在 Windows 上支持从本机剪贴板取回内容，请直接使用「发送到远端」。");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jpeg_quality_is_clamped_not_trusted() {
        assert_eq!(jpeg_quality_from(""), 70);
        assert_eq!(jpeg_quality_from(" 85 "), 85);
        // Out of the useful band, and not a number at all: back to the documented default.
        assert_eq!(jpeg_quality_from("29"), 70);
        assert_eq!(jpeg_quality_from("96"), 70);
        assert_eq!(jpeg_quality_from("abc"), 70);
    }

    #[test]
    fn a_bridge_slot_is_handed_out_once() {
        // Two browsers must not both think they own the keyboard.
        let (tx, _rx) = std::sync::mpsc::sync_channel::<OutMsg>(1);
        let token = attach(tx.clone());
        assert!(token.is_some(), "the first tab must get the slot");
        assert!(attach(tx).is_none(), "a second tab must be refused");
        if let Some(token) = token {
            detach(token);
        }
        // And a stale token must never be able to detach somebody else's bridge.
        let token = attach(tx);
        assert!(token.is_some());
        detach(0);
        detach(u64::MAX);
        assert!(rlock(&GATE).is_some(), "foreign detach must be a no-op");
        if let Some(token) = token {
            detach(token);
        }
        assert!(rlock(&GATE).is_none());
    }

    #[test]
    fn the_command_fields_default_instead_of_failing() {
        let value: Value = serde_json::from_str(r#"{"t":"mouse","x":12}"#).unwrap();
        assert_eq!(str_field(&value, "button"), "");
        assert_eq!(int_field(&value, "x", 0), 12);
        assert_eq!(int_field(&value, "y", 0), 0);
        assert!(!bool_field(&value, "alt"));
    }
}
