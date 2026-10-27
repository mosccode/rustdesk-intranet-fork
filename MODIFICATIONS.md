# Modifications relative to RustDesk 1.5.0

This file lists the changes made by this fork so that the corresponding source is documented, as
required by AGPL-3.0 section 5(a). Modifications are dated 2026-10.

## Network restriction

- Added `libs/hbb_common/src/netguard.rs`: a process-wide egress/ingress guard with a
  user-supplied allow-list, literal-IP-only parsing, CIDR matching, audit logging and
  policy self-checks.
- The allow-list is read at startup from `intranet-allowlist.conf` in the application config
  directory and can be reloaded while the process runs. Entries are restricted to RFC1918, CGNAT and
  link-local IPv4 space; public entries, host names and domain names are rejected and audited.
  `127.0.0.1` is always allowed. A file with no entries - and no file at all - means no narrowing:
  the guard then allows every private range it accepts, so an unconfigured machine still reaches its
  own LAN. Listed entries only take ranges away.
- Applied the guard to the TCP/UDP socket layer, raw sockets, HTTP clients, KCP, port forwarding,
  server accept paths and the Dart side's direct HTTP usage.
- Removed name-resolution paths and NAT64 rewriting; targets must be literal addresses.

## Removed capabilities

- Removed the rendezvous (hbbs) client path, relay negotiation and relay fallback, hole punching,
  LAN discovery, WebSocket transport, proxy transport, HTTP API clients, record upload, software
  update checks, NAT-type/STUN probing and the Telegram 2FA path.
- Removed server-shaped settings and credentials from the UI and force-reduced the remaining
  network options to safe values at runtime.

## Configuration and UI

- Added the intranet allow-list file and its commented template.
- Added an allow-list editor to the desktop settings page: it says whether the guard is narrowed to
  the file's entries or standing at the private default, how many ranges that is, and the resolved
  file path; it edits the file through the same validation the guard uses at startup, refuses a
  whole save when one line is refused, reloads the list in the running process, and requires this
  machine's permanent password for the write. Reading is not gated - the file is plain text any local
  account can open - only changing it is.
- The gate reuses the password storage this build already keeps (`Config::verify_local_permanent_password`,
  i.e. the same hashed-storage check plus constant-time compare the auth path uses). No second
  credential is stored, and a wrong answer is written to `netguard-audit.log` like any other refused
  local action.
- Kept upstream's **Use IP Whitelisting** and **Use ID whitelisting** cards present and editable:
  `whitelist` and `id-whitelist` are inbound access controls - one is checked against the peer
  address of the accepted socket, the other against the id the controller announces - so this fork
  does not pin them. The ID card's tip was extended in the English, Simplified Chinese and
  Traditional Chinese strings to say that an id is self-reported and carries no signature, so it
  keeps out a mistyped address rather than an attacker.
- Hid the cloud-account UI through upstream's own `is_disable_account()` check: that function now
  reports the feature as disabled in this build, which also removes the address-book and device-group
  tabs upstream gates on the same flag. No settings widget was edited for it.
- Removed the two software-update switches from the desktop settings page and deleted upstream's
  `checkUpdate()` together with its two call sites in the app entry points, because the update
  transport itself is out of the build; `enable-check-update` and `allow-auto-update` stay pinned to
  `N`, so the file, the UI and the binary say the same thing.
- Made the direct-connection port operator-settable: both the listener and the dial now read one
  option (`direct-access-port`) through a single `netguard::direct_peer_port()`, so the two ends
  cannot drift apart. The default is still `21118`.
- Removed the ID/relay server dialog, proxy dialog, WebSocket switch, server test action,
  `id@server` handling and the "change ID" action.
- Removed vendor URLs from in-app help/about links.
- Replaced the ID board and connection-status widget on the desktop home page with the machine's
  own reachable direct-access address and an intranet-mode status line.

## Control ends

- Added `src/webgate/` and the `rustdesk-webgate` binary: a browser control console. It serves one
  page and speaks the native protocol to the controlled machine by reusing `Session`, so the
  controlled side is unchanged and listens on the same port it always did.
- Everything it can be told to do is filtered by the same allow-list the desktop client uses; the
  listener itself refuses to start without an explicit bind address and passphrase, and accepts
  peers only from allow-listed addresses.
- Added `src/webgate/sha1.rs` (RFC 6455 handshake) and `src/webgate/http.rs` (HTTP/1.1 + WebSocket
  framing) rather than adding crate dependencies to this build.

## Build

- GitHub Actions builds a Windows x64 release artifact and runs a vendor-domain scan over the
  produced binaries.
- `scripts/scan_strings.py` reports vendor domains found in the binaries.

No changes were made to the license of the upstream code. All files remain under AGPL-3.0.
