// netguard webgate: the operator-facing entry point for the browser control console.
//
// Two lines of policy make this binary different from `rustdesk.exe`, and both matter:
//
//   * `common::global_init()` first, exactly as the Flutter entry point runs it. That is what pulls
//     the policy-shaped options out of the config, loads `intranet-allowlist.conf`, and *refuses to
//     start* when the compiled policy fails its self-check. A gateway that skipped this would be a
//     weaker copy of the desktop client.
//   * nothing else. No tray, no `test_rendezvous_server()`, no service, no updater, no server loop.
//     This process only ever dials out to an allow-listed peer and serves one page.
//
// It is a console-subsystem binary on purpose: `webgate::run()` reports why it refused to start on
// stderr, and an operator needs to see that the first time, not hunt for a log file.
//
// The console itself is desktop-only (see `src/lib.rs`), but a `[[bin]]` is compiled whatever the
// target, so the mobile build gets this stub instead of a build failure.

use librustdesk::*;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn main() {
    if !common::global_init() {
        eprintln!(
            "Global initialization failed. See netguard-audit.log next to the config file; the \
             gateway does not start when the compiled policy does not check out."
        );
        return;
    }
    webgate::run();
    common::global_clean();
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn main() {
    eprintln!("webgate: the browser control console is built for desktop targets only.");
}
