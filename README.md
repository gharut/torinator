# Torinator

A Go tray application for Windows 11 x64 that routes ordinary Windows traffic
through embedded Tor or your own SOCKS5 proxy, without per-app configuration.
One executable embeds Tor, sing-box and the signed Wintun DLL. No separate Tor,
sing-box, Go, or VPN installation is needed on the target PC.

```text
Windows apps → Torinator TUN → selected provider → destination
                              ├─ Tor (default): TCP
                              └─ Custom SOCKS5: TCP + UDP relay
                     DNS → HTTPS resolver through the selected provider
                     ICMP/ping → rejected
```

## Run

1. Run `dist\torinator.exe` and accept Windows' administrator prompt. Admin rights
   are required to create the virtual adapter and routes. The app starts
   **disconnected**, with a grey T icon in the notification area (possibly under
   Windows' hidden-icons arrow).
2. Click or right-click the icon. To use your own proxy, choose **Settings…**,
   select **Custom SOCKS5 proxy**, enter its host/IP and port plus optional
   username/password, and click **Save**. Tor remains the first-run default.
3. Choose **Connect**. The app arms persistent Windows enforcement before
   starting the selected transport. Amber indicates startup progress. Green
   **Protected** appears only after the expected rules are verified, direct TCP
   and UDP/DNS probes bound to available pre-TUN routes are denied by Windows,
   and `https://check.torproject.org/api/ip` is reachable through the tunnel.
   Tor mode additionally requires `"IsTor":true`. Custom mode
   does not extract or launch Tor and accepts the proxy's ordinary exit IP.
4. Run SSH, browsers and other applications normally. Disconnect and reopen
   existing application connections when switching routing.

| Tray action | Behavior |
| --- | --- |
| Connect | Arm persistent protection, start only the selected provider, create the adapter and verify enforcement/connectivity. |
| Settings… | Select Tor or SOCKS5 and save host, port and optional credentials while disconnected. |
| Disconnect | Cancel startup or stop routing and Tor; remove the adapter, restore saved interface options and flush DNS. Ordinary internet access resumes. |
| Reset network changes | Disconnect, retry recovery of this app's adapter/settings, and delete extracted runtimes/configs. Can recover after a previous crash. |
| Show status | Display current progress or the complete error. |
| Open log | Open diagnostics for this run. |
| Exit (keep protection armed) | Stop the tunnel and tray while retaining direct-access blocking. Disconnect first to exit with normal internet access. |

Connectivity is rechecked once per minute. A failed check turns the icon amber
and leaves the tunnel active; a later successful check returns it to green.
Windows policy and tunnel identity are checked every two seconds. Process or
policy failure stops the tunnel; its persistent deny rules are retained.
**Blocked** means protection is armed while no tunnel is active. Reopening the
app after a crash/Exit shows this state. Connect retries; Disconnect or Reset
explicitly restores normal access. Failed cleanup retains protection and shows
the error. The app never automatically restores direct internet on failure.

## Traffic and cleanup

* Tor carries TCP, including SSH. Custom SOCKS5 routes TCP and UDP through the
  selected proxy; UDP requires the proxy's standard SOCKS5 UDP ASSOCIATE support.
  Unsupported UDP fails through the proxy; there is no direct fallback.
  ICMP/ping and other raw IP protocols cannot be transported by SOCKS5.
* DNS on port 53 is captured and resolved using Cloudflare DNS-over-HTTPS at
  `1.1.1.1` through the selected provider. The Tor Project check endpoint
  is contacted on connect and during the periodic health checks.
* In Tor mode, other UDP (including QUIC, games and most real-time calling)
  cannot traverse Tor and is rejected by the active TUN. Browsers generally
  fall back from QUIC to TCP. Tor exit policies can also reject TCP ports.
* IPv4 and IPv6 are routed. Windows host applications and services are denied
  direct access outside the live Torinator interface, including LAN routes,
  direct DNS, and applications binding another adapter. Existing host flows are
  subject to WFP reauthorization when policy is installed. In Tor mode, the exact embedded `tor.exe` process path
  has a direct TCP transport exception so Tor can reach its relays without looping into
  itself. In remote SOCKS5 mode, the protected router may make TCP connections
  only to the selected proxy IP/port. Its UDP transport exception accommodates
  the proxy's delegated UDP relay addresses/ports. Other executables have no
  such exception.
  For a local proxy, start its daemon before connecting; Torinator identifies
  the listening executable and gives only that process a TCP/UDP exception so
  its upstream connections can leave the PC. Ambiguous/unidentifiable local
  listeners fail before the TUN starts.
  A proxy hostname is resolved once using the existing Windows connection
  before tunneling; use a literal proxy IP to avoid that bootstrap DNS lookup.
  While protection is already armed, a proxy hostname must match the cached
  endpoint; a changed hostname needs a literal IP or an explicit Disconnect
  before bootstrap resolution. No temporary DNS exception is added.
* The kill switch is always enabled when connecting. Persistent WFP rules deny
  ordinary host traffic independently of the routing processes. A dynamic
  permission admits only the live tunnel LUID and its expected local address;
  it disappears when the app/session dies. Boot-time deny rules cover the early
  startup period before persistent filters are loaded by Windows BFE.
  Sing-box's own competing WFP hard permits are disabled; Torinator owns this
  policy. A conflicting highest-priority hard-permit policy prevents Protected
  status rather than being silently accepted.
* Loopback, tightly scoped Windows DHCP traffic and link-local IPv6 neighbor/
  router discovery remain permitted. These are local/network-control
  exceptions, not a general application internet allowance. ARP and other
  non-IP link-layer protocols are outside this IP firewall's scope.
* Approved transport executables are trusted components. Administrator/SYSTEM
  policy changes, kernel drivers, and guests attached through independent VM
  virtual switches are outside the host-app guarantee. IP forwarding through
  the Windows host is blocked. This is not an audited anonymity environment or
  a replacement for Tor Browser's browser protections.
* Cleanup targets the app's deterministic adapter GUID and Wintun hardware ID.
  It does not reset physical adapters, change the global proxy, reset Winsock,
  or edit other software's firewall rules. Only Torinator's provider/sublayer
  and filter namespace is removed on explicit Disconnect/Reset. An interface journal recovers original
  `WeakHostSend` settings of adapters present when connecting.
* Windows may retain the shared signed Wintun driver package in its driver
  store. Reset removes Torinator's virtual adapter; it does not uninstall a
  driver other software may use.

Runtimes, a recovery journal, logs and Tor guard/cache state live under the
administrators-only `%PROGRAMDATA%\Torinator-<Windows-user-SID>` directory.
The selected provider and proxy details are retained in `settings.json`.
Passwords are encrypted with Windows DPAPI for the current user/machine. The
router's temporary config necessarily contains usable credentials inside the
protected directory and is deleted on disconnect. Passwords are masked in the
settings window. Changing settings neither connects nor switches an active
session; disconnect first, save, then connect again.
Reset removes extracted runtimes. Exit/crash preserves the protected state and
enforcement; usable router credentials are removed during ordinary shutdown.
Tor guard/cache state and diagnostics are
retained across connections; retaining guards is intentional. No service,
scheduled task or startup entry is installed. Only one system-routing instance
is allowed across Windows sessions.

### Recovery

If protection remains armed after a crash or restart, reopen Torinator and use
**Connect**, **Disconnect**, or **Reset network changes**. If saved settings
prevent the GUI from opening, run the executable's recovery command and accept
the administrator prompt:

```powershell
.\torinator.exe -reset-network
```

This removes only Torinator's protection after adapter/interface cleanup
succeeds. Avoid deleting the EXE while protection is armed; retain it for
recovery. Another administrator can run a fresh copy of the executable to
release the global Torinator policy.

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
graceful child shutdown, process-tree termination, settings/password persistence,
provider selection without Tor startup, and routing-policy invariants.
Security-state tests also verify that failure, cancellation, Exit, and reopening
never release armed protection; only successful explicit cleanup does.
Optional desktop/CIM smoke tests are read-only with respect to networking:

```powershell
$env:TORINATOR_TRAY_TEST = '1'
$env:TORINATOR_PLATFORM_TEST = '1'
go test ./internal/tray ./internal/platform -v
```

An additional loopback-only integration test exercises authenticated SOCKS5 TCP
and UDP relay using the actual embedded sing-box binaries. It replaces TUN with
local SOCKS listeners and changes no system routes or adapters:

```powershell
$env:TORINATOR_PROXY_TEST = '1'
go test ./internal/engine -run TestCustomProxyTCPAndUDPRelay -v
```

Live full-tunnel, DNS/IPv6 leak, UDP-blocking and crash-recovery verification must
be performed on a Windows test machine; the offline self-test does not establish
those guarantees.

The native protection test requires an administrator and uses only local echo
servers plus rules scoped to two temporary test executables. It verifies IPv4/
IPv6 TCP/UDP denial, established-flow reauthorization, the approved transport
exception, persistent blocking after killing its installer, automatic removal
of dynamic permissions on process death, and explicit recovery. A second test
validates all production filter definitions, including forwarding and early boot,
in an uncommitted transaction that is always aborted. Neither test commits
host-wide or early-boot filters or alters system routes/adapters:

```powershell
$env:TORINATOR_PROTECTION_TEST = '1'
go test ./internal/protection -run '^TestNative' -count=1 -v
```

CI and releases require this isolated native test as well as the ordinary
build checks. Whole-machine tunnel changes, adapter transitions, competing VPNs,
boot/BFE restart behavior and VM boundaries still need a dedicated Windows test
machine; the isolated native test does not certify those scenarios.

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
* `internal/settings`: provider preferences, validation and DPAPI password storage.
* `internal/protection`: persistent transactional WFP policy, dynamic TUN leases,
  policy verification and direct-access denial probes.
* `internal/platform`: privileged storage, adapter removal and recovery journal.
* `internal/process`: atomic Windows job containment and hidden graceful shutdown.
* `internal/tray`: native Win32 icon, status and menu; no CGO or webview.
* `internal/assets`, `internal/tor`: embedded runtime extraction and notices.

Bundled versions: Tor Expert Bundle 16.0.1 (Tor 0.4.9.16), sing-box 1.14.4,
Wintun 0.14.1. Update the build hashes, asset member names, version text and
notices together. Recheck the pinned sing-tun GUID derivation and interface
mutation behavior when changing sing-box. Third-party notices and source links
are in `internal/assets/THIRD_PARTY_NOTICES.md` and accompany the build artifact.
