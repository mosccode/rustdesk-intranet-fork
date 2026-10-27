// netguard L3 (需求 §二.1/§二.5): the hbbs HTTP API client is deleted.
//
// Upstream's `src/hbbs_http/` held the app's cloud API: a `reqwest`-based client, the OIDC account
// flow, the heartbeat/registration sync (`sync`), session-recording upload, and a downloader. It is
// gone - all five modules and the `reqwest` dependency are removed, so this crate links no HTTP
// client at all.
//
// What remains here is:
//   1. the **URL policy** every caller used before dialling (`check_http_url_allowed` /
//      `is_allowed_http_url`). It is pure: parse the URL, require a literal IP on the allow-list,
//      refuse every host name. `common::can_dial_url` still uses it.
//   2. **stubs** with the same signatures for the APIs the UI, IPC and the Flutter bridge still
//      name. They perform no I/O: "pro" is false, a switch grant is dropped, the signal receiver
//      never yields, record upload is disabled, the downloader answers "removed", and the account
//      flow reports that it is unavailable. Keeping the symbols means a missing feature shows as a
//      clear message instead of a missing-symbol crash in the Dart bridge.

use hbb_common::{netguard, ResultType};

/// See `check_http_url_allowed`. Kept for callers that only need a yes/no answer.
pub fn is_allowed_http_url(url: &str, ctx: &str) -> bool {
    check_http_url_allowed(url, ctx).is_ok()
}

/// The app-level HTTP stack used to dial whatever URL it was handed and `reqwest` resolved the
/// host inside itself, so a check after the fact was not available - the DNS query is already the
/// egress. The host therefore has to be an IP literal already, and that literal has to be on the
/// allow-list. The audit line carries the URL without its query string, because API URLs carry
/// tokens there.
pub fn check_http_url_allowed(url: &str, ctx: &str) -> ResultType<()> {
    let parsed = url::Url::parse(url)?;
    let display = match (parsed.host(), parsed.port()) {
        (Some(host), Some(port)) => format!(
            "{}://{}:{}{}",
            parsed.scheme(),
            host,
            port,
            parsed.path()
        ),
        (Some(host), None) => format!("{}://{}{}", parsed.scheme(), host, parsed.path()),
        (None, _) => "<invalid-url>".to_owned(),
    };
    match parsed.host() {
        Some(url::Host::Ipv4(v4)) => {
            netguard::check_outbound_ip(std::net::IpAddr::V4(v4), ctx, &display)
        }
        Some(url::Host::Ipv6(v6)) => {
            netguard::check_outbound_ip(std::net::IpAddr::V6(v6), ctx, &display)
        }
        // A domain in a request URL would be resolved by an HTTP client; refuse it by name form.
        _ => Err(netguard::deny_name_form(&display, ctx)),
    }
}

pub mod sync {
    /// Upstream stored the licence state from the heartbeat. There is no heartbeat, so nothing can
    /// become "pro": the limits that keyed off it (`server::connection`, `ipc`) take the free path.
    pub fn is_pro() -> bool {
        false
    }

    /// Fire-and-forget POST in upstream (`switch-sides` flow). Dropped.
    pub fn register_switch_grant(_switch_uuid: String) {}

    /// The GUI used to push subscription signals from the heartbeat into live sessions. The channel
    /// is created here and its sender is kept alive but never used, so `recv()` waits forever -
    /// exactly the behaviour of "the server never sent anything", without a busy loop.
    pub fn signal_receiver() -> hbb_common::tokio::sync::broadcast::Receiver<Vec<i32>> {
        lazy_static::lazy_static! {
            static ref NEVER_TX: hbb_common::tokio::sync::broadcast::Sender<Vec<i32>> = {
                let (tx, _rx) = hbb_common::tokio::sync::broadcast::channel(1);
                tx
            };
        }
        NEVER_TX.subscribe()
    }
}

pub mod record_upload {
    use hbb_common::log;
    use std::sync::mpsc::Receiver;

    /// Upstream flipped this on when a recording upload was requested; nothing sets it any more, so
    /// `server::video_service` takes the "local recording only" path.
    pub fn is_enable() -> bool {
        false
    }

    /// Drains the recorder's state channel so a caller that already built one does not block on a
    /// full channel. No file is opened and no request is made.
    pub fn run(rx: Receiver<scrap::record::RecordState>) {
        log::info!("session recording upload is removed from this build (netguard L3); recording stays local");
        std::thread::spawn(move || for _ in rx {});
    }

}

pub mod downloader {
    use hbb_common::{anyhow, ResultType};
    use std::path::PathBuf;

    #[derive(serde::Serialize, Default)]
    pub struct DownloadData {
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub data: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<PathBuf>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub total_size: Option<u64>,
        pub downloaded_size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    /// The only user was the Flutter bridge's `download-data-*` key, which served the update
    /// downloader. Updates are deleted (步 6-C), so this reports that instead of reading a file.
    pub fn get_download_data(_id: &str) -> ResultType<DownloadData> {
        Err(anyhow::anyhow!(
            "the downloader is removed from this build (netguard L3)"
        ))
    }

    pub fn cancel(_id: &str) {}

    pub fn remove(_id: &str) {}
}

#[cfg(feature = "flutter")]
pub mod account {
    use serde::Serialize;

    /// Same JSON shape as upstream, so `ui_interface::account_auth_result` (and the Dart login
    /// page) can keep parsing it. `auth_body` is a free-form value because no real payload exists.
    #[derive(Serialize, Default)]
    pub struct AuthResult {
        pub state_msg: String,
        pub failed_msg: String,
        pub url: Option<String>,
        pub auth_body: Option<serde_json::Value>,
    }

    /// The OIDC account flow posted to the API server. Both the flow and the server are gone; the
    /// methods keep their signatures so the three FFI entry points in `ui_interface` still compile.
    pub struct OidcSession;

    impl OidcSession {
        pub fn account_auth(
            _api_server: String,
            _op: String,
            _id: String,
            _uuid: String,
            _remember_me: bool,
        ) {
        }

        pub fn auth_cancel() {}

        pub fn get_result() -> AuthResult {
            AuthResult {
                state_msg: String::new(),
                failed_msg:
                    "Account login is removed from this build (netguard L3): no HTTP client is linked."
                        .to_owned(),
                url: None,
                auth_body: None,
            }
        }
    }
}
