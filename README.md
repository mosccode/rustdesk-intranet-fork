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
  `intranet-allowlist.conf` in the application config directory, or use the editor under Settings ·
  Security (see Configuration below). Only private IPv4 space is accepted; public addresses are
  rejected and logged, so a configuration mistake cannot turn this build back into an internet
  client.
- **Server-shaped settings are removed.** The ID/relay-server dialog, proxy dialog, WebSocket
  switch, generic server test, `id@server` targets and domain-name targets are gone or fail
  before dialing.

## Download and build

Prebuilt Windows x64 binaries are attached to releases in this repository. Each release notes the
source commit it was built from.

- `rustdesk-intranet-1.5.0-x86_64.exe` - a single-file portable build. Double-click to run; it
  unpacks its payload to `%LOCALAPPDATA%\rustdesk`. The in-app **Install** card installs the same
  files to Program Files (UAC required), exactly like the upstream portable executable.
- `rustdesk-intranet-windows-x64.zip` - the full `Release/` directory, plus the license files.

Build from source (same steps as CI):

```bash
# Linux check
cargo check --features flutter,linux-pkg-config --lib --bins
# Windows release (Visual Studio 2022 + LLVM + vcpkg with libvpx/libyuv/opus/aom)
cargo build --release --features flutter,hwcodec,vram --lib
cargo build --release --features flutter,hwcodec,vram --bin rustdesk-webgate
cd flutter && flutter build windows --release
```

The GitHub Actions workflow in `.github/workflows/` performs these steps and runs a vendor-domain
scan over the produced binaries.

## Configuration

### Editing the allow-list inside the app

**Settings · Security · Intranet direct-connect allow-list** (`Edit`) opens the file in the app
itself: it shows how many entries the guard is enforcing right now and the exact path of the file
for this build, then lets you add and remove lines and save. Saving validates with the same rules
as startup - one refused line refuses the whole save and names the line - and reloads the list in
the running process, so the machine you are typing on can connect immediately without a restart.

Two honest limits:

- Saving requires **this machine's permanent password** (the one set under Settings · Security ·
  Password). If none is set there is nothing to check the edit against, and the dialog says so
  instead of letting the change through. The gate is on the write only: the file itself is plain
  text in the config directory, readable by any local account, so gating the read would protect
  nothing.
- The list is read by each process at its own start. Saving applies to the process that saved; the
  side that **accepts** incoming connections picks the file up on its next start, so after changing
  it on a controlled machine restart that program (or the service).

The two upstream cards **Use IP Whitelisting** and **Use ID whitelisting** are gone from the desktop
settings page. `whitelist` and `id-whitelist` are pinned empty by this build's forced options, so
every value they wrote came back empty on the next read while the checkbox still looked usable; a
control that silently drops your input is worse than no control. The card above writes to what the
guard actually reads.

### Editing the file directly

On first start the application writes a commented template:

- Windows: `%APPDATA%\RustDesk\config\intranet-allowlist.conf`
- Linux: `~/.config/rustdesk/intranet-allowlist.conf`
- macOS: `~/Library/Application Support/RustDesk/intranet-allowlist.conf`

Edit it (or use the card above), one entry per line:

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

### Direct connection port

Upstream dials port `21118` for a direct connection and listens there on the controlled machine,
and the two halves used to read the port from different places, so changing only one side silently
broke connectivity. In this fork both halves call one function
(`hbb_common::netguard::direct_peer_port()`), so a single option moves the pair together.

Set it in the settings page (Security / Direct access port) or in
`RustDesk2.toml` under `[options]`:

```toml
direct-access-port = "9001"
```

Both sides must be configured the same way, and the controlled machine has to be restarted for the
listener to move. Leaving the option unset keeps `21118`. A value that is not a number in
`1-65535` is refused at startup with an explanation instead of quietly falling back, because a
silently wrong port is indistinguishable from a firewall problem on site.

The port is a port, not a destination: it cannot widen the allow-list, every dial still has to
match `intranet-allowlist.conf`.

You can also override the port per connection by typing it into the connect box, e.g.
`192.168.10.15:9001` (or `[fd00::15]:9001` for IPv6). An explicitly typed address wins over the
option, which is useful for reaching a peer that has not moved its listener.

## Browser control console (`rustdesk-webgate`)

The zip also contains `rustdesk-webgate.exe`: a small listener that serves one HTML page and
drives a normal RustDesk session on your behalf. It is a **control end only** - the machine being
controlled runs the ordinary client and gains no new inbound port, and the wire protocol between
the gateway and that machine is the native RustDesk one.

```bat
:: on the operator machine, with the same config directory the client uses
rustdesk-webgate.exe
:: then open http://<the address you bound>:<webgate-port>/ in a browser on a host in the allow-list
```

The gateway refuses to start until all three of these are present under `[options]` in
`RustDesk2.toml`; none of them is compiled in, and there is no default bind address:

```toml
webgate = "Y"
webgate-bind = "192.168.10.20"
webgate-passphrase = "operator passphrase"
# optional
webgate-port = "21124"
webgate-jpeg-quality = "70"
```

What that buys you, and what it costs:

- The browser proves knowledge of the passphrase with `sha1(nonce || passphrase)` over a nonce the
  gateway generates per connection, so the passphrase itself never crosses the socket. This is
  authentication of the operator, not a secret shared with the peer.
- The browser-to-gateway hop is plain HTTP and WebSocket, **not TLS**, so run it on a trusted
  network segment. The gateway-to-controlled-machine hop keeps RustDesk's own handshake.
- The page reaches the gateway over TCP, which is an inbound connection like any other, so the
  **browser's own address must be in `intranet-allowlist.conf`** on the machine running the gateway
  or the listener drops it (with an audit line).
- Frames are decoded and JPEG-encoded on the CPU. That is deliberate: the gateway has no GPU
  context, so it takes the RAM path rather than the texture path. Expect lower throughput than the
  desktop client, which is the price of having no plugin in the browser.
- Everything the allow-list rules still apply to the address you type into the page. The gateway is
  a `Session`, not a proxy: a target outside the allow-list is refused exactly as it would be in
  the desktop client.

## Security boundaries

- This is a code-level restriction of the application's own network behavior. It does not claim
  to control the operating system, a proxy, a firewall, or a compromised machine.
- A local administrator can replace the binary or edit files; this fork does not protect against
  that.
- The code has not been audited by a third party. Treat it as an engineering change, not a
  security certification.
- Only direct IP connections are supported. There is no ID-based lookup, relay, file transfer
  server, hosted web client or cloud account. The browser page in
  [`src/webgate/`](src/webgate/) is a local control console you run yourself; it is not a hosted
  client and it does not change what the controlled machine listens for.

## License

This fork is distributed under the **GNU Affero General Public License v3.0**, the same license as
upstream RustDesk. See [`LICENCE`](LICENCE) for the full text, [`NOTICE`](NOTICE) for upstream
copyright and [`MODIFICATIONS.md`](MODIFICATIONS.md) for the list of changes.

Because this is a modified version, the complete corresponding source is this repository. If you
redistribute a binary built from it, you must keep the same license and make the source available
under AGPL-3.0.
