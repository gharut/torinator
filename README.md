# Torinator

A portable Tor SOCKS5 client for 64-bit Windows. Download the Windows artifact from a successful GitHub Actions build, unzip it and run `torinator.exe`. The executable carries Tor, its dependencies and its data files. Only the build machine downloads the expert bundle.

## Use

Start `torinator.exe` and wait for Tor to log `Bootstrapped 100%`. Configure your application's SOCKS5 proxy as `127.0.0.1:9050` and enable proxy-side DNS. For a connection check from another terminal, run:

```powershell
curl.exe --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip
```

Look for `"IsTor":true`. Press Ctrl+C in Torinator's terminal to stop it. Use `-port 9150` to select another port or `-tor-version` to check the embedded runtime offline. Only applications configured to use the proxy send traffic through it.

Torinator extracts runtime files into a unique temporary directory on startup and removes them on normal exit. Tor keeps its guard state and network cache in `%APPDATA%\Torinator\data`. Run one instance per user.

## Build

With Go 1.24 or newer and PowerShell on Windows x64, run `.\build.ps1`. The script verifies the pinned SHA-256 digest, runs tests, builds `dist\torinator.exe`, and executes the embedded Tor version check. To use a previously downloaded official archive, pass `-Archive C:\path\to\bundle.tar.gz`.

The CLI and process lifecycle live in `cmd/torinator`. Archive handling lives in `internal/tor`. To update Tor, update both the version and archive digest in `build.ps1` using the Tor Project's release manifest.
