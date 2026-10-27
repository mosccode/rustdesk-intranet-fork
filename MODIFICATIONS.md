# Modifications relative to RustDesk 1.5.0

This file lists the changes made by this fork so that the corresponding source is documented, as
required by AGPL-3.0 section 5(a). Modifications are dated 2026-10.

## Network restriction

- Added `libs/hbb_common/src/netguard.rs`: a process-wide egress/ingress guard with a
  user-supplied allow-list, literal-IP-only parsing, CIDR matching, audit logging and
  policy self-checks.
- The allow-list is read at startup from `intranet-allowlist.conf` in the application config
  directory. Entries are restricted to RFC1918, CGNAT and link-local IPv4 space; public entries
  are rejected and audited. `127.0.0.1` is always allowed.
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
