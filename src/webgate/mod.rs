// netguard webgate: an intranet web console that controls another machine through THIS fork's own
// RustDesk implementation, instead of through a second protocol.
//
// 需求方 2026-10-27 的取舍是「网页版仍旧采用 rustdesk 方案」。这句话在工程上决定了很多事，写下来免得
// 下一个人重新推导：
//
//   * 被控端**一行都不改**。它继续只听它的直连端口（`netguard::direct_peer_port()`，默认 21118），
//     不会为了浏览器多开一个入站口子 —— 那才是真正新增攻击面的做法。
//   * 加密、握手、编解码、输入语义全部沿用 `crate::client` / `Session`，不是"在网页里重写一遍 RustDesk
//     协议"。浏览器不能直连 TCP，所以中间必须有这个网关；网关是**控制端**侧的进程，不是被控端侧的。
//   * 因此网关进程是「又一个控制端」：它出口照旧经过 netguard 的 allow-list（`intranet-allowlist.conf`
//     没写进去的地址，网关也拨不通），失败关闭，不回退中继。给它新增的只有「监听一个 HTTP/WS 端口 +
//     一条口令」。
//   * 浏览器的可达性：页面由网关自己下发（内嵌在二进制里），`ws://` 用字面 IP + 运维指定的端口，
//     全程零域名、零 DNS、零外网。
//
// 明确的边界（不能声称超过这些）：`http`/`ws` 是明文。同网段能抓包的人能看到画面与键鼠内容 ——
// 口令本身不上网（见下面的 nonce 摘要），但画面不能。这一条写在 README 与本模块的交付说明里，
// 不靠"内网所以安全"糊过去。
//
// 开箱即用是需求方 2026-10-28 02:00 明确要的：「连谁，输什么密码全在网页里搞」「最好是单文件版本」。
// 所以下面这三格**都不填也能跑** —— 双击 exe 就监听，浏览器打开页面，目标 IP 和被控端密码都在页面里输：
//   webgate             = "Y"|"N"              可选；只有显式写成 "N" 才拒绝启动（留给不想开网关的机器）
//   webgate-bind        = "<本机字面 IP>"       可选；不填 = 监听 0.0.0.0，即本机所有网卡
//   webgate-passphrase  = "<口令>"              可选；不填 = 不做口令校验，谁能连到这个端口谁就能用
// 可选不等于没有防护：`0.0.0.0` 上来的每个连接，先过 `netguard::check_inbound_addr`（非私有段一律拒并记
// 审计），口令只是在这道门之后再加一层。要收窄就写 `intranet-allowlist.conf`，那是同一份名单。
//
// 运维可配置的键都在 `RustDesk2.toml` 的 `[options]` 里，一个都不编译进源码（站点值仍然不许硬编码）：
//   webgate-port        = "21124"              可选，HTTP/WS 端口
//   webgate-jpeg-quality= "70"                 可选，画面 JPEG 质量，只接受 30..=95，否则回 70
//
// ---------------------------------------------------------------------------
// WebSocket contract (the only two routes are `/` for the page and `/ws` for the bridge)
// ---------------------------------------------------------------------------
// Text frames carry JSON objects, always with a `"t"` tag. Binary frames are one complete JPEG
// video frame, nothing else. The page is the only client that speaks this; there is no other
// supported consumer, so the shapes below are the whole interface.
//
// gateway -> page
//   {"t":"hello","auth":"required|off","nonce":"<base64 16 B,仅 required 时给>","host":"<Host header>",
//    "peer_port":21118}   right after the socket opens; `nonce` is fresh per connection and
//     `peer_port` is what `netguard::direct_peer_port()` says, so the page can prefill the connect
//     form. `auth:"off"` means no `webgate-passphrase` is configured and the page must not prompt.
//   {"t":"state","s":"auth-ok|connecting|connected|closing|disconnected|busy","msg":""}
//   {"t":"geom","w":1920,"h":1080,"disp":0,"embedded":0|1,"scale":1.0}  remote geometry (scale only
//     arrives with `set_display`, so it may be absent)
//   {"t":"displays","list":[{"i":0,"name":"","w":0,"h":0,"online":true}]}
//   {"t":"cursor","id":"7","w":32,"h":32,"hotx":0,"hoty":0,"png":"<base64>"}  one shape per id
//   {"t":"cursor-id","id":"7"}                                                 select a cached shape
//   {"t":"cursor-pos","x":16,"y":40,"embedded":0|1}
//   {"t":"info","platform":"Windows","username":"ops","hostname":"pc","version":"1.5.0","displays":1}
//   {"t":"transport","secured":true,"direct":true,"stream":"tcp"}
//   {"t":"fingerprint","value":"..."}
//   {"t":"msgbox","type":"input-password|re-input-password|insecure-connection|...","title":"","text":"","retry":false}
//   {"t":"msgbox-cancel","tag":"..."}
//   {"t":"perm","name":"keyboard|clipboard|...", "on":true}
//   {"t":"block-input","on":true} | {"t":"recording","on":true}
//   {"t":"stat","fps":30,"speed":"1.2Mbps","delay":12}
//   {"t":"sessions","list":[{"sid":1,"name":"ops"}]}
//   {"t":"clip","text":"..."}                         remote clipboard pulled on request
//   {"t":"settings","view":false}
//   {"t":"chat","text":"..."}
//   {"t":"msg","text":"..."}                         gateway prose, in the status line
//   {"t":"pong"}
//   {"t":"closed","reason":"..."}                    last frame before the socket dies
//
// page -> gateway
//   {"t":"auth","d":"<base64 sha1(nonce_bytes || passphrase_utf8)>"}  first message, only when
//     `hello` said `auth:"required"`
//   {"t":"open","addr":"192.168.10.15:9001","password":"...","view":false}
//   {"t":"login","password":"..."}                    answer to a password prompt
//   {"t":"insecure","yes":true}                       answer to the e2ee-unavailable prompt
//   {"t":"mouse","type":"move|down|up|wheel","x":..,"y":..,"button":"left|right|wheel|back|forward",
//    "alt":false,"ctrl":false,"shift":false,"meta":false}
//   {"t":"key","code":"VK_BACK|VK_TAB|A|1|..","down":true,"press":false,modifiers as above}
//   {"t":"text","s":"中文字符"}                              IME / CJK, sent as a key sequence
//   {"t":"clip-set","text":"..."} | {"t":"clip-get"}
//   {"t":"display","i":1} | {"t":"refresh"}
//   {"t":"quality","v":"best|balanced|low|custom"} | {"t":"custom-quality","v":50} | {"t":"fps","v":30}
//   {"t":"view","on":true} | {"t":"remote-cursor","on":true} | {"t":"select-session","sid":1}
//   {"t":"ctrlaltdel"} | {"t":"lock"} | {"t":"close"} | {"t":"ping"}
//
// Coordinates are integers in the remote image space (`geom.w` x `geom.h`), not CSS pixels: the page
// does the scaling, the gateway does not guess the browser's box.

use hbb_common::log;
use hbb_common::netguard;
use std::sync::atomic::{AtomicBool, Ordering};

mod http;
mod peer;
mod sha1;

/// The page, inlined. It ships with the binary on purpose: the gateway must be able to serve
/// something before the operator has put any file on disk, and a console that can be swapped out by
/// a stray file in the working directory is not a console we want to audit.
const PAGE: &str = include_str!("index.html");

/// Set once by [`run`], before any session exists. `ui_interface::use_texture_render()` reads it.
static GATEWAY_PROCESS: AtomicBool = AtomicBool::new(false);

/// True only inside a process started by the `rustdesk-webgate` binary. See the note on
/// `use_texture_render` for why the gateway must not use the GPU path.
pub fn is_gateway_process() -> bool {
    GATEWAY_PROCESS.load(Ordering::Relaxed)
}

/// Where the gateway listens. Defaults are deliberately boring numbers, and nothing here is a
/// destination: which machines the gateway may *dial* is still decided only by the allow-list.
pub const DEFAULT_HTTP_PORT: u16 = 21124;

fn option(key: &str) -> String {
    hbb_common::config::Config::get_option(key)
}

/// The listen port, from `webgate-port`; anything unusable falls back to the documented default,
/// and `run` refuses to start on a value that would fall back silently - the same rule
/// `startup_self_check` applies to `direct-access-port`, because a web console that is not
/// reachable is otherwise indistinguishable from a firewall problem.
fn http_port() -> u16 {
    port_from_str(&option("webgate-port"), DEFAULT_HTTP_PORT)
}

fn port_from_str(raw: &str, fallback: u16) -> u16 {
    match raw.trim().parse::<u16>() {
        Ok(port) if port > 0 => port,
        _ => fallback,
    }
}

/// The turnkey default: no `webgate-bind` means every interface. This is the only guess the gateway
/// makes, and it is a guess about *reach*, not about a destination - which peers may connect is still
/// decided by `check_inbound_addr`, and which peers we may dial by the allow-list.
fn bind_or_wildcard(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        "0.0.0.0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// `netguard::parse_bind_addr` wants one string, and an IPv6 address only survives being split on
/// the last colon if it is bracketed first. Operators write either shape in `webgate-bind`.
fn bind_target(ip: &str, port: u16) -> String {
    if ip.contains(':') && !ip.starts_with('[') {
        format!("[{}]:{}", ip, port)
    } else {
        format!("{}:{}", ip, port)
    }
}

/// Start the gateway. Blocking; the caller (`src/bin_webgate.rs`) never returns from it.
///
/// 开箱即用：三格都不填也要能跑起来。目标机器与被控端密码都在网页里输，所以这里只决定两件小事——
/// 在哪个地址上听、要不要口令。二者都有默认值，且默认值是安全上说得通的那一个：
/// `0.0.0.0` 只是"每个网卡都听"，每个进来的连接仍然先过 netguard 的入站策略（非私有段一律拒绝并写审计），
/// 不写口令 = 谁能连到这个端口谁就能用，这一点在页面与状态文件里都写明，不靠"内网所以安全"糊过去。
/// 仍然一个站点值都不编译进源码：没有写死的 IP、端口、口令。
pub fn run() {
    GATEWAY_PROCESS.store(true, Ordering::Relaxed);

    // 显式 `webgate = "N"` 是关掉这台机器网关的唯一开关（不设 = 开），给的是"装了但不想让浏览器控制"
    // 的机器一个不留后门口的退路。
    if option2yes(&option("webgate")) == Some(false) {
        refuse("这台机器把网关关着：[options] 里写了 webgate = \"N\"，改成 \"Y\" 或直接删掉这一行再启动。");
        return;
    }
    let stored_port = option("webgate-port");
    if !stored_port.trim().is_empty() && port_from_str(&stored_port, DEFAULT_HTTP_PORT).to_string()
        != stored_port.trim()
    {
        eprintln!(
            "webgate: `webgate-port = {:?}` is not a port number 1-65535; it would fall back to \
             {} instead of the port you asked for.",
            stored_port, DEFAULT_HTTP_PORT
        );
        refuse(&format!(
            "端口号没写对：`webgate-port = {:?}` 不是 1-65535 的数字。删掉这一行就用默认端口 {}。",
            stored_port, DEFAULT_HTTP_PORT
        ));
        return;
    }

    // `webgate-bind` 不填就听 0.0.0.0。写死了就必须是个字面地址——仍然不许填域名，绑定不能走到解析器
    // （任务书 §二.1），这条由 `parse_bind_addr` 自己把关并写审计。
    let bind_ip = bind_or_wildcard(&option("webgate-bind"));
    let port = http_port();
    // `parse_bind_addr` is netguard's own bind gate (the same one `tcp::new_listener` runs): a
    // literal address or nothing, no resolver, and the policy reason is recorded in the audit if
    // somebody tries to bind something weird.
    let bind = match netguard::parse_bind_addr(&bind_target(&bind_ip, port), "webgate::run") {
        Ok(bind) => bind,
        Err(e) => {
            eprintln!("webgate: cannot bind {} - {}", bind_target(&bind_ip, port), e);
            refuse(&format!(
                "监听地址用不了：`webgate-bind = {:?}` 必须是本机某个字面 IP（不给域名）。删掉这一行就听所有网卡。",
                option("webgate-bind")
            ));
            return;
        }
    };
    let passphrase = option("webgate-passphrase");
    let turned_off = passphrase.trim().is_empty();
    write_status(bind, turned_off);
    log::info!(
        "webgate: listening on {} (page at http://{}/), passphrase check: {}, allow-list file: {}",
        bind,
        bind,
        if turned_off { "off" } else { "on" },
        netguard::allowlist_path().display()
    );
    if let Err(e) = http::serve(bind, if turned_off { "" } else { &passphrase }) {
        log::error!("webgate: server loop ended: {}", e);
        status_note(&format!("服务循环结束：{}", e));
    }
}

/// 双击 exe 时控制台会一闪而过，所以拒绝启动的理由除了打到 stderr，还写进配置目录里那个永远存在的
/// 状态文件——运营看一眼文件就知道差什么，不用去找日志。
fn refuse(reason: &str) {
    eprintln!("webgate: refusing to start - {}", reason);
    status_note(reason);
}

/// `<config_dir>/webgate-status.txt`：一行说清现在听在哪、口令校验开没开。写完就丢，不是日志。
fn write_status(bind: std::net::SocketAddr, turned_off: bool) {
    // A wildcard bind has no URL worth typing: `http://0.0.0.0/` is not it, and loopback is refused
    // by the Host check on purpose (a gateway is meant to be opened through the address the network
    // can actually reach). So the wildcard case names the rule instead of a fake address.
    let page = if bind.ip().is_unspecified() {
        format!(
            "浏览器打开 http://<这台机器的内网 IP>:{}/（不要用 127.0.0.1，本机回环会被拒绝）",
            bind.port()
        )
    } else {
        format!("浏览器打开 http://{}/", bind)
    };
    status_note(&format!(
        "已在 {} 监听，{} —— 连哪台机器、被控端密码都在页面里输。{}",
        bind,
        page,
        if turned_off {
            "当前没有网关口令：能连到这个端口的私有段地址都能用这台网关（入站仍受内网策略约束）。"
        } else {
            "已启用网关口令校验：页面要先输 webgate-passphrase。"
        }
    ));
}

fn status_note(text: &str) {
    let path = hbb_common::config::Config::path("webgate-status.txt");
    let line = format!(
        "{} pid={} {}\n",
        netguard::now_stamp(),
        std::process::id(),
        text
    );
    if let Err(e) = std::fs::write(&path, line) {
        log::error!("webgate: cannot write status file {:?}: {}", path, e);
    }
}

/// `option2bool` semantics are `=="Y"` for keys that do not start with `enable-`, so an unset value
/// is `None` — which is exactly the turnkey case: 没写 = 开。Only an explicit `"N"` closes it, and
/// only `run` reads that; the helper stays separate so the three-way shape is testable.
fn option2yes(value: &str) -> Option<bool> {
    match value.trim() {
        "Y" => Some(true),
        "N" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unusable_port_falls_back_and_only_after_trimming() {
        assert_eq!(port_from_str("", DEFAULT_HTTP_PORT), DEFAULT_HTTP_PORT);
        assert_eq!(port_from_str(" 8080 ", DEFAULT_HTTP_PORT), 8080);
        assert_eq!(port_from_str("0", DEFAULT_HTTP_PORT), DEFAULT_HTTP_PORT);
        assert_eq!(port_from_str("65535", DEFAULT_HTTP_PORT), 65535);
        // Over 65535 does not parse as u16 at all, so the fallback is the whole story.
        assert_eq!(port_from_str("65536", DEFAULT_HTTP_PORT), DEFAULT_HTTP_PORT);
        assert_eq!(port_from_str("abc", DEFAULT_HTTP_PORT), DEFAULT_HTTP_PORT);
    }

    #[test]
    fn the_listener_switch_has_no_opt_out_by_leaving_it_empty() {
        // 开箱即用靠的就是这条：留空不是"关"，只有显式的 "N" 才是。
        assert_eq!(option2yes(""), None);
        assert_eq!(option2yes("true"), None);
        assert_eq!(option2yes("Y"), Some(true));
        assert_eq!(option2yes("N"), Some(false));
    }

    #[test]
    fn an_empty_bind_is_every_interface_and_a_written_one_is_kept() {
        // 开箱即用那一半：什么都不写也要有地址可听；写了就照写，只多一个 trim。
        assert_eq!(bind_or_wildcard(""), "0.0.0.0");
        assert_eq!(bind_or_wildcard("   "), "0.0.0.0");
        assert_eq!(bind_or_wildcard(" 10.0.12.5 "), "10.0.12.5");
        assert_eq!(bind_or_wildcard("fd00::15"), "fd00::15");
    }

    #[test]
    fn an_ipv6_bind_target_is_bracketed_before_the_port_is_appended() {
        assert_eq!(bind_target("10.0.12.5", 21124), "10.0.12.5:21124");
        assert_eq!(bind_target("::1", 21124), "[::1]:21124");
        assert_eq!(bind_target("fe80::1", 8080), "[fe80::1]:8080");
        // Already bracketed in the config: do not wrap it twice.
        assert_eq!(bind_target("[::1]", 21124), "[::1]:21124");
    }
}
