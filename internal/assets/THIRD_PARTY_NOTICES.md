# Bundled software

Torinator embeds upstream archives without modifying their executables. Their
license texts travel inside the executable and are extracted with the runtimes.
Use `torinator.exe -licenses` from a console build to print these notices.

* Tor Expert Bundle 16.0.1: https://dist.torproject.org/torbrowser/16.0.1/
  Embedded Tor version: 0.4.9.16.
  Tor source: https://dist.torproject.org/tor-0.4.9.16.tar.gz
  Bundle build recipes/dependency sources:
  https://gitlab.torproject.org/tpo/applications/tor-browser-build/-/tree/tbb-16.0.1-build2
  See the embedded `tor/docs/tor.txt` and other `tor/docs/*.txt` files for Tor and
  its bundled dependencies' licenses. The expert bundle includes additional
  transport binaries and their notices; they are not launched by Torinator.
* sing-box 1.14.4: https://github.com/SagerNet/sing-box/releases/tag/v1.14.4
  License: GPL-3.0-or-later, with the additional naming restriction in its LICENSE file.
  Corresponding source and build instructions:
  https://github.com/SagerNet/sing-box/tree/v1.14.4
  https://github.com/SagerNet/sing-box/archive/refs/tags/v1.14.4.tar.gz
  Upstream go.mod/go.sum identify the source dependencies used by this release.
  Its release archive also includes libcronet.dll; see the upstream source and
  license information for that bundled dependency.
* Wintun 0.14.1: https://www.wintun.net/
  Signed binary distribution: https://www.wintun.net/builds/wintun-0.14.1.zip
  The prebuilt DLL's license is embedded as `sing-box/WINTUN-LICENSE.txt`.
  Source: https://git.zx2c4.com/wintun/
* golang.org/x/sys v0.38.0: BSD-3-Clause.
  Source and license: https://cs.opensource.google/go/x/sys/+/v0.38.0:LICENSE

Torinator is an independent application, not a Tor Project product. The Tor
name and Wintun trademark belong to their respective owners.
