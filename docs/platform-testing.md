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
