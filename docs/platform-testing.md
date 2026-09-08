# Platform runtime verification

Lantern builds for macOS and Linux on ARM64 and x86-64. Cross-compilation and executable-header checks establish the target format; executing the packaged binary provides stronger evidence about its behavior. Translation or virtualization still does not establish behavior on every physical machine or network adapter.

## Linux suites

```sh
make linux-test                              # Docker daemon's native architecture
make linux-test LINUX_PLATFORM=linux/amd64    # x86-64
make linux-test LINUX_PLATFORM=linux/arm64    # ARM64
```

The runner accepts only these two platforms and uses a separate local image for each: `lantern-linux-test:amd64` and `lantern-linux-test:arm64`. It passes the platform explicitly to both the build and every container run. The suite checks Go's target, the container's reported machine architecture, and the actual CLI's `doctor` architecture field. A mismatched image or binary fails verification.

Running a foreign architecture requires a translation/emulation runtime already supported by Docker. The runner does not install one or silently skip failed tests. Native runs do not require cross-architecture support.

Each architecture runs vet/race tests, controlled IPv4/IPv6 protocol exchanges, a full 1–65,535 TCP-port loopback scan, isolated module installation/core imports, terminal and snapshot checks, JSONL cancellation/broken-pipe fixtures, Samba interoperability, and ARP/NDP runtime tests. Capability variants exercise raw-access denial as well as successful discovery. Temporary veth links exist only in disposable test containers. Containers have no host mounts, host networking, or published ports.

## Packaged binaries

```sh
make release VERSION=dev
python3 scripts/test-release.py dev
```

The default verifier checks all four archives, checksums, executable architecture, licensing/provenance, and offline document links. It executes the host-matching archive to check version, demo, offline lookups, and diagnostic architecture.

After building both Linux test images, add:

```sh
python3 scripts/test-release.py dev --linux-containers
```

This also executes each Linux archive's verified binary in its matching image. Only the binary is transferred through stdin; the containers run without external networking or capabilities. Loopback JSONL, broken-pipe, interruption, pseudo-terminal, and snapshot fixtures exercise the release build itself, which is built with `CGO_ENABLED=0`.

On macOS, `--macos-amd64` also executes the Intel archive and runs those CLI fixtures for both Mac architectures. Apple Silicon requires Rosetta to be installed already; this flag neither installs it nor changes system settings. The options can be combined:

```sh
python3 scripts/test-release.py dev --linux-containers --macos-amd64
```

## Evidence and limits

The checked-in verification notes distinguish native execution, containers, and translation. An Intel Mac binary running through Rosetta and a Linux x86-64 binary running under Docker's translation are useful compatibility checks, but neither establishes native Intel/AMD hardware performance. Raw macOS ARP/NDP exchanges still require separate privileged BPF verification. No local test publishes release assets or establishes public download availability. See [verification results](verification.md) and [remaining work](STATUS.md).

The Linux image also installs Debian's `wsdd` package as an independent interoperability peer. `scripts/test-wsdd.py` starts an owned, temporary daemon with HTTP metadata serving disabled, checks actual CLI discovery and repeated-scan diffs, disables multicast to confirm the opt-out, and terminates the daemon on every exit. IPv4 runs with all capabilities removed; scoped IPv6 uses a temporary veth pair and only `NET_ADMIN`, with automatic address generation disabled so DAD does not race the fixture. No host networking, published ports, shares, host mounts, or persistent daemon are used. The installed package version is included in test output.

The scoped IPv6 wsdd case also places a kernel-rejected failed-DAD address first in the address inventory, confirms that an actual UDP bind returns `EADDRNOTAVAIL`, then checks scan and `doctor` recovery through the usable source on that interface. The disposable peer owns the duplicate address; test cleanup deletes the entire veth pair.

## macOS direct Ethernet verification

`scripts/test-ethernet-darwin.py` exercises the actual CLI against explicitly supplied, known peers on one local interface. Start with the prerequisite check, which sends no discovery packets:

```sh
python3 scripts/test-ethernet-darwin.py --interface en0 --check-only
```

For a live check, run in a session with BPF access and supply an independently known peer address and Ethernet MAC. Replace the example interface, address, and MAC below with the test peer's actual values:

```sh
python3 scripts/test-ethernet-darwin.py --interface en0 \
  --ipv4 192.0.2.2 --mac4 02:11:22:33:44:55
```

For NDP, supply `--ipv6` and `--mac6` instead, or alongside the IPv4 pair. Link-local IPv6 addresses automatically acquire the selected interface zone; an explicit conflicting zone is rejected. The IPv4 and IPv6 peers may have different MACs. CIDRs, multicast/unspecified/loopback targets, and the scanning Mac's own addresses are rejected.

The fixture checks all requested raw capabilities before probing. An unavailable prerequisite exits with status 2 and leaves live verification explicitly unproven. It does not invoke privilege escalation, change BPF permissions, modify interfaces or neighbor caches, or select an automatic scan target. The live path performs two raw-only scans of each supplied address and one scan with active discovery disabled. It requires fresh ARP/NDP evidence with the expected MAC, a single scoped target, no unrelated probes or advertisements, saved snapshots matching JSON output, unchanged repeated observations, and no raw-response evidence after disabling the method. Temporary snapshots are removed on exit.

`python3 scripts/test-ethernet-fixture.py` verifies the harness with simulated prerequisite/reply data and actual CLI snapshot comparisons. It runs in CI without raw access; passing it does **not** establish live macOS Ethernet exchange. The local prerequisite-only run still reports BPF permission denial; physical ARP/NDP verification remains pending.
