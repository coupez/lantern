# Install Lantern

Lantern supports source builds and self-contained macOS/Linux archives. Download [v0.1.0-rc.7](https://github.com/coupez/lantern/releases/tag/v0.1.0-rc.7) from the public repository. All four published archives and the checksum file were downloaded without authentication and matched the locally verified release artifacts.

## Build from a checkout

Install Go 1.26.8 or newer, or use Go's automatic toolchain selection. From a checkout of the revision you want to build:

```sh
make build
./bin/lantern demo
./bin/lantern demo --watch
```

To install into your user directory:

```sh
make install
```

The default destination is `$HOME/.local/bin/lantern`. Add `$HOME/.local/bin` to your shell's `PATH` if needed. A custom destination uses `make install PREFIX=/your/prefix`; package builders can also set `DESTDIR` to a staging directory. Neither target invokes sudo. Installation replaces the `lantern` executable at that destination.

## Versioned Go installation

The module path is `github.com/coupez/lantern`. Install the published prerelease without a checkout:

```sh
go install github.com/coupez/lantern/cmd/lantern@v0.1.0-rc.7
```

This command was verified through the public Go proxy in an empty temporary module cache on macOS ARM64, including version, model lookup and offline demo checks. Use the explicit tag to select this prerelease. Source installation requires Go 1.26.8 or newer, or automatic toolchain selection; `GOTOOLCHAIN=local` disables automatic selection. A versioned install reports its module version through `lantern version`.

Go installs commands into `GOBIN` when set, otherwise into the first `GOPATH` entry's `bin` directory (normally `$HOME/go/bin`). Put that directory on `PATH` to invoke `lantern` directly.

## Install a release archive

Local archives are generated with `make release VERSION=dev` (choose a release version when preparing a candidate). They support macOS and Linux on ARM64 and x86-64; choose `darwin-arm64` for Apple Silicon, `darwin-amd64` for Intel Macs, and the corresponding Linux architecture.

Download the archive and checksum file from the release page. Place the archive and its checksum file in the same directory. Archive names use `lantern-VERSION-OS-ARCH.tar.gz`. Verify the archives listed in the checksum file using `shasum -a 256 -c lantern-VERSION-checksums.txt` (or `sha256sum -c` on Linux). That command expects all listed archives to be present; for a single downloaded archive, compare its `shasum -a 256 ARCHIVE` output with the matching line in the checksum file.

Extract into an empty directory, then run or copy the executable:

```sh
./lantern version
./lantern demo --watch
mkdir -p "$HOME/.local/bin"
install -m 755 lantern "$HOME/.local/bin/lantern"
```

The executable contains its runtime datasets; it does not need the adjacent docs to scan. Archives also include the README, offline documentation, licensing notices, public dataset provenance, and the Fing inspection inventory. They contain no Fing application code or extracted proprietary resources. Developer ID signing and notarization are not configured for macOS archives.

## Runtime requirements

Default scanning uses normal user permissions on macOS. On Linux, install `iproute2` for neighbor-cache discovery; ICMP availability depends on the host's ping socket configuration. Optional `--arp` needs raw link access (`CAP_NET_RAW` on Linux or access to BPF devices on macOS). Lantern never elevates itself or modifies those permissions.

For profile choices, network scope, and known discovery limits, see [the README](../README.md) and [discovery behavior](discovery.md).

## Reproduce installation checks

After dependencies are cached (`go mod download`), `make install-test` builds a temporary file-only Go module proxy. It verifies canonical versioned installation outside the checkout, the installed version string, an independent program importing the core and datasets, and `PREFIX`/`DESTDIR` installation into a temporary tree. It does not install into the user's home directory or publish a module. `python3 scripts/test-release.py VERSION` validates already-built archives, checksums, platform headers, licenses, offline links, and the host-compatible packaged executable.
