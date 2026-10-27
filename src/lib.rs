#[cfg(any(test, not(target_os = "linux")))]
mod audio_resampler;
mod keyboard;
/// cbindgen:ignore
pub mod platform;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use platform::{
    clip_cursor, get_cursor, get_cursor_data, get_cursor_pos, get_focused_display,
    set_cursor_pos, start_os_service,
};
#[cfg(not(any(target_os = "ios")))]
/// cbindgen:ignore
mod server;
#[cfg(not(any(target_os = "ios")))]
pub use self::server::*;
mod client;
// netguard L9 (步 6-D): `mod lan;` is deleted. It bound a wildcard UDP listener on 21119 and answered
// LAN pings, then broadcast discovery probes to 255.255.255.255 - all outside the two allowed
// segments. The UI entry points (`main_wol`, `ui_interface::discover`) stay as no-op stubs.
// netguard L5 (步 6-G): `rendezvous_mediator` is renamed to `direct_access` and its rendezvous half
// is deleted; what remains is the one inbound listener (`direct_server`) plus the `restart` /
// `NEEDS_DEPLOY` stubs the UI and IPC call. The glob re-export keeps `crate::*` paths valid.
#[cfg(not(any(target_os = "ios")))]
mod direct_access;
#[cfg(not(any(target_os = "ios")))]
pub use self::direct_access::*;
/// cbindgen:ignore
pub mod common;
#[cfg(not(any(target_os = "ios")))]
pub mod ipc;
#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    feature = "flutter"
)))]
pub mod ui;
mod version;
pub use version::*;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
mod bridge_generated;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter;
#[cfg(any(target_os = "android", target_os = "ios", feature = "flutter"))]
pub mod flutter_ffi;
use common::*;
mod auth_2fa;
#[cfg(not(target_os = "ios"))]
mod clipboard;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub mod core_main;
mod custom_server;
mod lang;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod port_forward;
mod port_forward_mux;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod tray;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod whiteboard;

// netguard L2 (步 6-C): `mod updater;` is deleted together with `src/updater.rs` (version check,
// download, auto-update scheduler). The session-state helpers it also owned moved to
// `ipc::{has_no_active_conns,set_controlling_session_count}` and `platform::macos`.

mod ui_cm_interface;
mod ui_interface;
mod ui_session_interface;

mod hbbs_http;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod clipboard_file;

pub mod privacy_mode;

#[cfg(windows)]
pub mod virtual_display_manager;

mod kcp_stream;
