# Torinator

A Go tray application for Windows 11 x64 that routes ordinary Windows TCP
connections through Tor, without per-app proxy configuration or an external VPS.
One executable embeds Tor, sing-box and the signed Wintun DLL. No separate Tor,
sing-box, Go, or VPN installation is needed on the target PC.

```text
Windows apps → Torinator TUN → local Tor SOCKS5 → Tor network → destination
                     DNS → HTTPS resolver through Tor
              other UDP / ICMP → rejected
```

## Run

1. Run `dist\torinator.exe` and accept Windows' administrator prompt. Admin rights
   are required to create the virtual adapter and routes. The app starts
   **disconnected**, with a grey T icon in the notification area (possibly under
   Windows' hidden-icons arrow).
2. Click or right-click the icon and choose **Connect**. Amber indicates bootstrap
   progress; green appears after Tor boots, the TUN starts, and a request to
   `https://check.torproject.org/api/ip` through normal Windows routing returns
   `"IsTor":true`.
3. Run SSH, browsers and other TCP applications normally. Disconnect and reopen
   existing application connections when switching routing.

| Tray action | Behavior |
| --- | --- |
| Connect | Extract embedded runtimes, bootstrap Tor, create the Torinator adapter, validate routing. |
| Disconnect | Cancel startup or stop routing and Tor; remove the adapter, restore saved interface options and flush DNS. Ordinary internet access resumes. |
| Reset network changes | Disconnect, retry recovery of this app's adapter/settings, and delete extracted runtimes/configs. Can recover after a previous crash. |
| Show status | Display current progress or the complete error. |
| Open log | Open diagnostics for this run. |
| Exit | Disconnect and clean up before removing the tray icon. |

Tor routing is rechecked once per minute. A failed check turns the icon amber
and leaves the tunnel active; a later successful check returns it to green.
Process failure turns the icon red and triggers cleanup. Reset can retry failed
cleanup. A successful reset returns the icon to grey.

## Traffic and cleanup

* Tor carries TCP, including SSH. DNS on port 53 is captured and resolved using
  Cloudflare DNS-over-HTTPS at `1.1.1.1` through Tor. The Tor Project check endpoint
  is contacted on connect and during the periodic health checks.
* Other UDP (including QUIC, games and most real-time calling) and ICMP/ping
  cannot traverse Tor and are rejected by the active TUN. Browsers generally
  fall back from QUIC to TCP. Tor exit policies can also reject TCP ports.
* IPv4 and IPv6 are routed. Only the exact embedded `tor.exe` process path has a
  direct TCP exception so Tor can reach its relays without looping into itself.
  Windows loopback/local networking and apps explicitly binding other adapters
  are outside the guarantee of default-route capture. This is not an audited
  anonymity environment or a replacement for Tor Browser's browser protections.
* This is on-demand routing, **without a persistent kill switch**. Disconnect,
  Exit, or a sing-box/app crash restores ordinary internet routing. Do not rely
  on it to keep this PC offline after the routing process stops.
* Cleanup targets the app's deterministic adapter GUID and Wintun hardware ID.
  It does not reset physical adapters, change the global proxy, reset Winsock,
  or create persistent firewall rules. sing-box's temporary DNS protections are
  removed when its process exits. An interface journal recovers original
  `WeakHostSend` settings of adapters present when connecting.
* Windows may retain the shared signed Wintun driver package in its driver
  store. Reset removes Torinator's virtual adapter; it does not uninstall a
  driver other software may use.

Runtimes, a recovery journal, logs and Tor guard/cache state live under the
administrators-only `%PROGRAMDATA%\Torinator-<Windows-user-SID>` directory.
Reset/Exit remove extracted runtimes. Tor guard/cache state and diagnostics are
retained across connections; retaining guards is intentional. No service,
scheduled task or startup entry is installed. Only one system-routing instance
is allowed across Windows sessions.

## Build and checks

Use Go 1.24+ and PowerShell on Windows x64:

```powershell
.\build.ps1
```

The script downloads official release archives **at build time**, verifies all
three pinned SHA-256 digests, runs tests and `go vet`, executes the embedded
runtime/configuration self-test, and builds the windowless `dist\torinator.exe`.
It generates a multi-size executable icon and stamps the application version
and source revision into Windows file properties, the tray menu and `-version`.
`assets/torinator.ico` and `assets/torinator.png` are generated from the geometric
mark in `internal/branding`; the resource object is generated, not committed.
Offline archives can be supplied with `-Archive`, `-SingBoxArchive` and
`-WintunArchive`. They must match the pinned versions/digests. A fresh checkout
needs these assets prepared by the build script before `go test ./...` can
compile the embedded-assets package.

For visible CLI diagnostics, build without the GUI linker flag:

```powershell
go build -o dist/torinator-console.exe ./cmd/torinator
.\dist\torinator-console.exe -self-test
.\dist\torinator-console.exe -tor-version
.\dist\torinator-console.exe -version
.\dist\torinator-console.exe -licenses
```

`-self-test` checks actual embedded Tor/sing-box executables, DLL loading and the
generated routing configuration offline, without elevation or routing changes.
Tests cover bootstrap cancellation, failed cleanup, health-check behavior,
graceful child shutdown, process-tree termination, and routing-policy invariants.
Optional desktop/CIM smoke tests are read-only with respect to networking:

```powershell
$env:TORINATOR_TRAY_TEST = '1'
$env:TORINATOR_PLATFORM_TEST = '1'
go test ./internal/tray ./internal/platform -v
```

Live full-tunnel, DNS/IPv6 leak, UDP-blocking and crash-recovery verification must
be performed on a Windows test machine; the offline self-test does not establish
those guarantees.

## Manual releases

Push or merge these changes into `main`. The ordinary **Build Windows executable**
workflow validates pushes and pull requests to `main`; publishing is a separate
manual action:

1. Open the repository's **Actions** tab and select **Release Windows**.
2. Click **Run workflow**, keep branch **main**, and select `patch` (default),
   `minor`, or `major`.
3. Click **Run workflow**. The first stable release is `v0.1.0`; subsequent runs
   increment the highest stable `vMAJOR.MINOR.PATCH` tag. Prerelease and unrelated
   tags are ignored. For example, `v0.1.0` becomes `v0.1.1` with `patch`, `v0.2.0`
   with `minor`, or `v1.0.0` with `major`.

The workflow builds the exact `main` commit selected when dispatched, reruns the
checks, and only then tags and publishes a GitHub Release. The downloads include
`torinator.exe`, `torinator-vX.Y.Z-windows-amd64.zip` (with README/notices/build
metadata), `SHA256SUMS.txt`, and `build-info.json`. Releases run one at a time to
avoid concurrent version selection. No personal access token is needed; the
workflow uses GitHub's built-in token with `contents: write` for its release job.

The manual button becomes available after the workflow is on the repository's
default branch. This workflow accepts `main` only. Pushing/merging by itself
does not publish a release. If publication fails after tagging, inspect the
existing tag/draft before retrying; the workflow never overwrites release tags.

For an explicitly versioned local build (without tagging or publishing):

```powershell
.\build.ps1 -Version v0.1.0
```

Normal local/CI builds use `v0.0.0-dev`.

## Layout

* `cmd/torinator`: entry point, elevation, logging and offline diagnostics.
* `internal/app`: serialized connection state and cancellation.
* `internal/engine`: Tor bootstrap, TUN startup, verification and rollback.
* `internal/routing`: explicit TCP/DNS policy, rejecting other traffic.
* `internal/platform`: privileged storage, adapter removal and recovery journal.
* `internal/process`: atomic Windows job containment and hidden graceful shutdown.
* `internal/tray`: native Win32 icon, status and menu; no CGO or webview.
* `internal/assets`, `internal/tor`: embedded runtime extraction and notices.

Bundled versions: Tor Expert Bundle 16.0.1 (Tor 0.4.9.16), sing-box 1.14.4,
Wintun 0.14.1. Update the build hashes, asset member names, version text and
notices together. Recheck the pinned sing-tun GUID derivation and interface
mutation behavior when changing sing-box. Third-party notices and source links
are in `internal/assets/THIRD_PARTY_NOTICES.md` and accompany the build artifact.
