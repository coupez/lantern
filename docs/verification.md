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
