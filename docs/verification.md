# Verification

Local environment: Apple M4 Max, macOS arm64, Go 1.26.3. Date: 2026-09-08.

## Executed checks

- `go test -race ./...`: target boundaries, port validation/deduplication, bounded worker concurrency, cancellation, cached-neighbor evidence, snapshot roundtrip/diff, MAC classification and longest-prefix matching, mDNS SRV/A/TXT correlation, SSDP parsing, CSV formula escaping, terminal-control sanitation, and invalid CLI inputs.
- `go vet ./...` passed.
- `LANTERN_NETWORK_TESTS=1 go test -race ./pkg/scanner -run TestNetworkIntegration -v`: passed against a controlled localhost listener. Verifies actual ICMP, detection of the dynamically allocated TCP port, and the exact SSH banner.
- `go test ./pkg/vendors -bench BenchmarkLookup -benchmem -run '^$'`: 76.67 ns/op, 24 B/op, 2 allocations/op for warm parsed-string lookups, with 58,421 assignments loaded.
- Live quick scan of the en1 IPv4 /22: 1,022 addresses, 3,771 ms, two observed devices, one ICMP responder, at 256 workers. DNS/multicast were disabled. The ICMP send queue dropped 39 sends; TCP discovery continued. The report is local at `research/results/local-quick.json` and is excluded from distribution.

The initial broad scan found a blocking Darwin ICMP send. A goroutine dump identified `icmp.PacketConn.WriteTo` waiting for socket writability. Each send now has a 2 ms deadline; blocked sends are reported as incomplete coverage instead of holding the scan indefinitely. The failed run was explicitly stopped before the successful rerun.

These checks establish functional behavior and one-network performance, not exhaustive network discovery or a comparative Fing benchmark. Network isolation, filters, response latency, and neighbor cache state affect results. Linux runtime validation and a broader reference-device corpus remain outstanding.

## Final expanded checks

- Standard scan at the current 512-worker default: 1,022 addresses in **2,389 ms**, two observed devices; DNS and multicast enabled. No multicast advertisements arrived on this network. The OS ICMP send queue dropped 23 sends and that limitation was reported. Local snapshot: `research/results/local-standard.json`.
- Full **65,535-port** localhost scan: **861 ms**, 30 open TCP ports, no warnings. ICMP, DNS, and multicast disabled for this measurement. Local snapshot: `research/results/loopback-full-ports.json`.
- mDNS parser fuzzing: **886,080 executions** in two seconds, passed. This is a short malformed-packet exercise, not exhaustive protocol validation.
- A canceled /20 × 65,535-port plan returns in approximately 10 ms without allocating the host × port matrix.
- `govulncheck` against the current database: **zero reachable known vulnerabilities**. It also reported two findings in imported packages and eleven in required modules that this code does not appear to call. No claim is made that the dependency graph contains zero advisories.
- Updated dependencies to `golang.org/x/net v0.58.0`, `x/term v0.45.0`, and transitive `x/sys v0.47.0`; minimum Go version is now 1.25.
- Built local release archives for macOS and Linux, ARM64 and x86-64. These are build checks; only the macOS ARM64 executable has been run here. CI has been defined but has not run on a remote runner.

- The public-data refresh script completed end to end against IEEE and IANA, preserving the expected 58,421 and 5,889 assignment counts.
- The controlled ICMP/TCP/banner integration test passed again after the dependency upgrades.
- Human report rendering was checked at 80 and 120 columns, including oversized names and terminal escape sanitization.

## Recognition expansion

- Standard scan after recognition changes: **1,022 addresses in 2,297 ms**, two devices, one model identification from a live advertisement. Sixteen ICMP writes timed out and were reported. Full local record: `research/results/recognition-standard.json` (excluded from distribution).
- Controlled localhost mDNS integration reconstructs a previously unknown service type from separate enumeration, PTR, SRV, TXT, and A responses.
- Controlled UPnP integration verifies device/embedded-device UDN matching, URL-fetch deduplication, off-device rejection, no redirect following, body limits, and cancellation of slow HTTP responses.
- Pure tests cover TXT case folding/duplicate keys, scope-bounded followups, description parsing limits, identity conflicts and source attribution, exact catalog matches, and identity CSV output. All packages pass with the race detector; `go vet` passes.
- Short fuzz runs: 354,405 description-parser cases and 589,287 mDNS cases; both passed. These runs predated the toolchain change below; the final patched build's full tests and controlled network checks also passed.
- New HTTP/XML call paths made Go 1.26.3 standard-library advisories reachable to `govulncheck`. The project now requires patched **Go 1.26.8** (verified in the official Go release feed), and the final scan reports **no vulnerabilities found**. This supersedes the earlier toolchain requirement for the current build.
- Added 40 exact Cast model/manufacturer mappings from a pinned MIT-licensed PyChromecast source, with content hash and license retention.

## IPv6 expansion

- All package tests passed with the race detector on Go 1.26.8; `go vet ./...` passed. Added checks for scoped target parsing, IPv6 range bounds, Darwin/Linux NDP parsing, local-prefix/interface filtering, candidate limits, early option validation, AAAA correlation, scope-safe description URLs, and full address rendering at 60–140 columns.
- Controlled network tests passed on both IPv4 and IPv6: ICMP echo, TCP detection, SSH banners, split DNS-SD enumeration/PTR/SRV/TXT/A-or-AAAA replies. IPv6 HTTP tests verified bracketed Host headers, server banners, and UPnP descriptions.
- Live IPv6 standard discovery on en1 took **1,464 ms**, retained and probed one address, and produced no warnings. The observed device was the scanning machine, with ICMP, mDNS, local-interface, neighbor-cache, and TCP evidence. This validates the local scoped path; it does **not** establish discovery coverage of other IPv6 devices. Private report: `research/results/ipv6-standard.json`.
- mDNS fuzzing with IPv6 hit generation and AAAA follow-ups: **576,488 executions**, passed.
- Large IPv6 prefixes use observed candidates instead of address enumeration. Reports explicitly record this distinction. IPv4 and IPv6 scans remain separate; direct ARP/NDP and Linux runtime validation remain outstanding.
- Rebuilt all four release archives after IPv6 changes; macOS ARM64 archive executable smoke-tested. Linux artifacts remain cross-builds pending runtime verification.

## Direct ARP and Linux runtime

- Added direct Ethernet/IPv4 ARP: Linux AF_PACKET socket and macOS BPF backend, with nonblocking I/O, write/read deadlines, cancellation, burst pacing, and no promiscuous mode. Tests reject foreign recipients, wrong ARP/Ethernet fields, malformed/truncated records, unsolicited/duplicate addresses, and out-of-link targets. Fresh ARP mappings take precedence over stale cache values.
- macOS Go 1.26.8: all packages passed with the race detector; vet passed. ARP reply fuzzing ran **422,270 cases**; Darwin BPF record fuzzing ran **405,222 cases**, both passed.
- Linux ARM64 on OrbStack, official Go 1.26.8 Bookworm image pinned by digest: vet, all race tests, and controlled IPv4/IPv6 ICMP, TCP, SSH/HTTP banner, mDNS, and UPnP integration tests passed. An ARP-only integration test verified the container bridge gateway with cache lookup disabled. The built CLI then identified that gateway using only ARP in **314 ms** with no warnings; the protocol reply latency was **0.026 ms**. This single-target result is not a subnet benchmark. Local log: `research/results/linux-runtime.log` (excluded from distribution).
- The Linux test container had all capabilities removed except `NET_RAW`, no host mounts, and no published ports. `make linux-test` reproduces the workflow. CI includes the same Linux container test; remote CI has not yet run.
- macOS unprivileged ARP fallback completed in **53 ms**, reported BPF permission denial, retained two cache/local observations, and attempted zero network probes. `/dev/bpf*` requires root here, and `sudo -n` requires a password. Native macOS raw ARP exchange therefore remains **unverified**; its implementation is cross-built and its decoding/deadline-independent logic is tested.
- The final Linux rerun passed after adding early termination on send/read errors. Packaged macOS ARM64 and Linux ARM64 binaries were smoke-tested. The Linux release binary also ran in a container with **all capabilities removed** and correctly warned that ARP was unavailable, sending zero probes. That separate artifact test mounted only the extracted release directory read-only; no workspace or host credentials were mounted. Private result: `research/results/linux-arp-no-capability.json`.

## Hardware model catalog expansion

- Imported **606 identifiers / 886 assignments** from MIT-licensed AppleDB revision `95f799d28e45dc110ee2f25b7e3e6cf8c1124dae`. All **124 ambiguous identifiers** retain their source variants. Each of 1,905 input JSON records was verified against its pinned Git blob hash. Generated index: **46,306 bytes** compressed.
- Catalog tests verify an unambiguous Mac Studio, multi-year MacBook Pro identifiers, Apple TV hardware variants, excluded prototypes, unknown/malformed identifiers, immutable lookup results, input/source linkage, index SHA-256, and aggregate counts. Scanner tests preserve the advertised code and reject fuzzy matches, arbitrary TXT fields, and metadata from an unselected conflicting model. CSV candidate output and terminal ambiguity labels are covered.
- All package race tests and vet passed after fixing a test expectation to account for CSV quoting of comma-containing identifiers. Controlled IPv4/IPv6 DNS-SD tests reconstructed a catalog-recognized model from separate SRV/TXT/A-or-AAAA packets.
- Live en1 IPv6 discovery completed in **1,349 ms**, one observed address, no warnings. Its advertised `Mac16,9` now has the catalog candidate **Mac Studio (M4 Max, 2025)** and Apple manufacturer provenance. Raw identifiers remain in the report. Private snapshot: `research/results/apple-model-live.json`.
- Warm `pkg/models.Lookup("Mac16,9")`: **195.6 ns/op**, 376 B/op, 7 allocations/op on Apple M4 Max. This includes building independent result records with escaped source URLs.
- Rebuilding from the pinned local archive and retrieval date produced byte-identical index and source metadata. A modified Git blob inventory was rejected before output creation. The importer executes no upstream code.
- The downloader/importer also passed end to end using a fresh temporary directory; the newly fetched pinned inputs reproduced both output files byte-for-byte.
- Final Linux ARM64 container checks passed with the catalog, including full race/vet and network integration tests. All four release archives were rebuilt and checked for the retained AppleDB license. No cross-brand identifier collisions occur in the imported index.

## ICMP completion and send recovery

- Added per-target sequence validation and reply deduplication, immediate completion when every echo target replies, and a single retry for local send timeouts/`EAGAIN`/`ENOBUFS`. Retry work shares at most 100 ms (or the shorter probe timeout). JSON counters distinguish attempted targets, accepted sends, retries, recovered writes, remaining failures, and unique echo responders.
- Deterministic socket fixtures verify IPv4 and scoped IPv6 completion, the full wait for silent targets, duplicate/foreign/wrong-nonce/wrong-sequence rejection, recoverable versus permanent send failures, retry-budget exhaustion, cancellation, read errors, and failed deadline setup without a blocked reader. All race tests and vet passed on macOS and Linux ARM64.
- Controlled loopback TCP/ICMP/banner integration now completed in **0.02 seconds combined on macOS** and **0.04 seconds combined on Linux**, rather than spending the default 300 ms echo wait per fully responding address. The pre-change Linux run took 0.66 seconds for both address families. These are test-suite wall timings, not TCP throughput measurements.
- A saved pre-change build scanned the local en1 /22 in **4,060 ms**, warning that 1,006 of 1,022 echo sends timed out. The initial revised build took **1,322 ms**, accepted 1,003 echo writes, retained one echo responder, and reported 19 unsent addresses after its retry budget expired. Both observed two addresses overall.
- Alternating follow-up pairs: old/new **4,019 / 1,052 ms**, then **3,853 / 903 ms**. Each new run recovered **40** initially failed echo writes; final unsent counts were **3** and **137**. Both old runs reported 1,006 unsent echo probes; every run observed two addresses overall. Both binaries used Go 1.26.8 and the same dependency versions. The saved baseline binary was built from the preceding worktree before its commit, so its Go VCS metadata reports the earlier parent plus dirty state.
- The varying unsent counts show that local queue/cache state materially affects coverage. These observations establish recovery and local timing improvements, not a universal speedup, complete discovery, or a Fing comparison. Private records: `research/results/echo-comparison.json`, `echo-before.json`, `echo-after-initial.json`; Linux runtime log: `research/results/echo-linux-runtime.log`.
- Rebuilt all four release archives. The packaged macOS ARM64 binary completed an IPv6 loopback ICMP-only scan in **8 ms**, with one attempted/sent/responding address, zero retries/failures, and no warnings. Private record: `research/results/echo-release-loopback.json`.


## Interactive watch dashboard (2026-09-08)

- Passed on macOS ARM64 and in the isolated Linux ARM64 container, alongside all existing race/protocol tests. The macOS pseudo-terminal suite also passed with a race-instrumented CLI binary. All four macOS/Linux ARM64/x86-64 release archives rebuilt successfully. `govulncheck` reported no vulnerabilities after adding the MIT-licensed Unicode segmentation dependency.

- `go test -race ./...` covers grapheme-safe cell widths and truncation, CJK/emoji/combining text, terminal and bidi-control sanitation, stable address selection across refreshes, model search, activity history bounds, all warning retention, scrolling, partial-report change semantics, and fragmented UTF-8/escape/bracketed-paste input.
- Frame checks cover 1×1 and 20×6 resize prompts and 36×10, 60×15, 80×24, 120×40, and 180×55 result layouts. Every frame stays within the terminal's row count and reserves its last column to prevent wrapping. Scoped IPv6 detail values wrap without losing their address.
- `make terminal-test` builds the CLI and runs `scripts/test-watch-pty.py` using real pseudo-terminals. It exercises synthetic selection/search/details/activity, pause and forced/automatic refresh, change detection, live resize, bracketed paste, quit/Ctrl-C while scanning, no-color settings, a loopback scan with snapshot saving, SIGTERM, invalid-scan and save-error cleanup, plain/dumb-terminal fallback, and redirected JSONL parsing. The test restores and compares terminal flags and checks alternate-screen/cursor cleanup. On Darwin it ignores only the kernel's PENDIN bookkeeping bit, which a standard Python raw/restore round trip also sets.
- The dashboard coalesces progress/discovery events independently of terminal rendering and joins a cancelled scanner before restoring the terminal. Reports and errors use a reliable completion channel. UI state stays in `internal/ui`; `pkg/scanner` has no terminal dependency.
- Interactive demo tests send no network traffic; the real scan test is restricted to IPv4 loopback with network probes disabled. These checks do not establish visual compatibility with every terminal emulator or screen reader. Use `--plain` for appended output.


## NetBIOS discovery (2026-09-08)

- Unit/race tests cover exact wildcard wire encoding, full-record length validation, all truncation boundaries, response flags/type/class/counts/owner validation, wrong sender/port/transaction rejection, duplicate suppression, early completion, silent deadlines, stopped writes, read/deadline failures, cancellation with partial results, 32-request pacing, byte-preserving name sanitation, workgroup/host distinction, source claims, and independently scheduling requested TCP ports on NetBIOS-only responders.
- A controlled UDP loopback exchange passed on macOS ARM64 and Linux ARM64. `FuzzNetBIOSReply` completed 2,440,511 inputs in ten seconds without a failure.
- The Linux test image includes Samba only as a test dependency; no Samba source/library is linked or bundled with Lantern. `scripts/test-netbios-samba.sh` runs `nmbd` inside the disposable container without starting an SMB file server or publishing ports. Samba 4.17.12-Debian supplied `LANTERN-SAMBA` and `LANTERN-LAB`; completed node-status-only scans took 4–5 ms. The test verifies name provenance, preserved group registration, no manufactured TCP ports, deep/inspect defaults, and the explicit disable override. Startup readiness is bounded and the daemon is stopped by the script's cleanup trap.
- These results establish protocol interoperability with a real Samba implementation, not Windows hardware coverage or a universal latency claim. Modern hosts with NetBIOS disabled will not answer. Broad real-network identification/coverage comparisons remain pending.
