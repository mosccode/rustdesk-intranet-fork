# Intranet-only RustDesk fork (unofficial)

This is an unofficial fork of [RustDesk](https://github.com/rustdesk/rustdesk) 1.5.0 for
**isolated intranets**. It keeps the remote-desktop function and removes the ability to talk to
anything outside a local allow-list.

It is **not affiliated with or endorsed by the RustDesk project**. "RustDesk" is the name of the
upstream project and remains the property of its owners; this repository only describes the code
it was forked from.

## What this fork changes

- **No rendezvous / relay / update / telemetry path.** Server lookup, relay negotiation, online
  status, software update checks, NAT-type probing and the hosted HTTP clients are removed from
  the build, not merely disabled by configuration.
- **One network guard for every socket.** `libs/hbb_common/src/netguard.rs` checks every outbound
  connect/send and every inbound accept/datagram. A target that is not on the allow-list is
  refused with an audit line; there is no retry and no fallback transport.
- **Direct connections only.** A peer is reached by entering a literal IP address; the connection
  goes to TCP 21118 on that address. If the direct connection fails, the session fails - it does
  not fall back to a relay.
- **The allow-list is yours, not the source code's.** Edit
  `intranet-allowlist.conf` in the application config directory (see below). Only private IPv4
  space is accepted; public addresses are rejected and logged, so a configuration mistake cannot
  turn this build back into an internet client.
- **Server-shaped settings are removed.** The ID/relay-server dialog, proxy dialog, WebSocket
  switch, generic server test, `id@server` targets and domain-name targets are gone or fail
  before dialing.

## Download and build

Prebuilt Windows x64 binaries are attached to releases in this repository. Each release notes the
source commit it was built from.

Build from source (same steps as CI):

```bash
# Linux check
cargo check --features flutter,linux-pkg-config --lib --bins
# Windows release (Visual Studio 2022 + LLVM + vcpkg with libvpx/libyuv/opus/aom)
cargo build --release --features flutter,hwcodec,vram --lib
cd flutter && flutter build windows --release
```

The GitHub Actions workflow in `.github/workflows/` performs these steps and runs a vendor-domain
scan over the produced binaries.

## Configuration

On first start the application writes a commented template:

- Windows: `%APPDATA%\RustDesk\config\intranet-allowlist.conf`
- Linux: `~/.config/rustdesk/intranet-allowlist.conf`
- macOS: `~/Library/Application Support/RustDesk/intranet-allowlist.conf`

Edit it, one entry per line, then restart the application:

```conf
# a CIDR ...
192.168.10.0/24
# ... or a single host
192.168.10.15
```

Accepted ranges are RFC1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`) and
link-local (`169.254/16`). `127.0.0.1` is always reachable for local IPC. An empty file means
nothing is reachable; that is the default.

Every refused target is appended to `netguard-audit.log` in the same directory, and mirrored to
the normal application log.

## Security boundaries

- This is a code-level restriction of the application's own network behavior. It does not claim
  to control the operating system, a proxy, a firewall, or a compromised machine.
- A local administrator can replace the binary or edit files; this fork does not protect against
  that.
- The code has not been audited by a third party. Treat it as an engineering change, not a
  security certification.
- Only direct IP connections are supported. There is no ID-based lookup, relay, file transfer
  server, web client or cloud account.

## License

This fork is distributed under the **GNU Affero General Public License v3.0**, the same license as
upstream RustDesk. See [`LICENCE`](LICENCE) for the full text, [`NOTICE`](NOTICE) for upstream
copyright and [`MODIFICATIONS.md`](MODIFICATIONS.md) for the list of changes.

Because this is a modified version, the complete corresponding source is this repository. If you
redistribute a binary built from it, you must keep the same license and make the source available
under AGPL-3.0.
