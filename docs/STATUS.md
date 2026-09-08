# Goal status

The workspace started empty. A runnable CLI and reusable discovery engine now exist. The full Fing-alternative goal remains active.

## Implemented

- Go CLI with styled adaptive-width output, live discoveries/progress, inspect view, quick/standard/deep profiles, automatic default-route selection, and explicit target/interface selection.
- IPv4 automatic target selection retains its interface through local discovery and reports; IPv4/IPv6 neighbor tables and local-address evidence honor explicit scope, including duplicate IPs on different links.
- Local capability diagnostics (`doctor`, `--interface`, `--json`) with actual socket/neighbor-table checks, cancellation, partial failures, and reusable core API; no discovery packets sent.
- Multicast collection preserves decoded replies after socket failures, distinguishes ordinary deadline expiry/cancellation, and reports packet/query-budget exhaustion instead of silently truncating discovery.
- Failed scans preserve printable/saved partial reports with an explicit error marker and conservative snapshot comparisons; broken JSONL pipes cancel and join workers before saving, with real macOS/Linux socket and terminal verification.
- Reports identify incomplete discovery methods separately from requested coverage and warning text. Snapshot/watch comparisons suppress dependent field changes and missing-address claims during partial discovery, and record method failure/recovery.
- Owned live device-update events stream normalized names/models/ports as each device finishes, with explicit progress phases, deep-copy API, JSONL output, and incremental first-scan dashboard details.
- Interactive watch dashboard with selection, grapheme-aware search/rendering, scrollable device details, bounded activity history, warnings, pause/refresh controls, synthetic demo, and terminal restoration. Plain and structured watch streams remain available.
- Watch redraws reuse search/filter/inspector views until inputs change and format only the visible service summary. Full-port search/details remain available, with measured large-report redraw improvements and explicit first-view costs.
- Full-port accumulation avoids quadratic duplicate searches, with exhaustive two-host/65,535-port uniqueness and event-ownership tests, cancellation coverage, and a real full-range loopback CLI fixture.
- Cancellable core with deduplicated incremental port jobs, bounded TCP concurrency, bounded ICMP writes and queue-pressure retries, immediate completion for fully answered echo sweeps, per-scan echo counters, neighbor observation, mDNS/DNS-SD, SSDP, reverse DNS, and bounded parallel service banners with fragmented-response handling.
- Unicast IPv4 NetBIOS node-status discovery with source-attributed computer names, workgroups, raw registration bytes, cancellation, bounded pacing, and live Samba interoperability checks.
- IPv6 single/small-range scanning and bounded local discovery for large prefixes, scoped link-local addresses, ICMPv6, NDP cache, IPv6 mDNS/SSDP, and AAAA resolution.
- Opt-in direct IPv6 NDP with paced solicitations, validated/checksummed replies, early completion, scoped fresh MAC evidence, partial failure handling, capability diagnostics, and real Linux kernel veth verification. Privileged macOS NDP exchange remains pending.
- Explicit direct IPv4 ARP discovery with bounded sending, Linux packet sockets, macOS BPF backend, permission fallback, and solicited-reply validation. Linux ARM64 runtime verified; macOS raw exchange remains unverified.
- Embedded 58,421-entry IEEE MAC database with /24, /28, /36 longest-prefix matching, private/multicast MAC handling, and registry provenance.
- Embedded 5,889-entry IANA TCP service database, public-data refresh tooling.
- mDNS service-type enumeration and follow-up queries; bounded UPnP description reads with embedded-device matching; source-attributed names/models; rejection of duplicate or nested-markup UPnP identity fields; 40 MIT-licensed Cast model/manufacturer mappings.
- ESPHome discovery and firmware recognition with direct DNS-SD queries, friendly names, source-linked build/project claims, firmware exports/search/diffs, and separate IPv4/IPv6 socket fixtures. Physical ESPHome-device coverage remains pending.
- Shelly discovery through direct DNS-SD queries and bounded read-only identity requests, with model/name/firmware provenance and shared UPnP request/time limits. Generation-1 and physical Shelly-device coverage remain pending.
- 155 Apache-2.0 aioshelly model-name/generation records with pinned inputs, reproducible AST-only import, offline lookup, generation-aware recognition, and catalog/source isolation. AppleDB and Shelly together provide 761 offline identifiers.
- HomeKit model/name recognition and 36 protocol category codes, with source-linked type hints, conflict preservation, exact service matching, and IPv4/IPv6 socket fixtures. Physical HomeKit-device coverage remains pending.
- 606 MIT-licensed AppleDB hardware identifiers with 886 source assignments, ambiguity-preserving product names, RAOP model recognition, and an offline `models` lookup command.
- JSON, JSONL, CSV, atomic snapshots, and snapshot/watch changes for identity and response evidence, with requested scan coverage, interruption handling, common-port comparisons, and interface isolation. Wake-on-LAN and a no-network demo.
- MIT code license, upstream data notices, repeatable build and tests; local macOS/Linux ARM64/x86-64 release archives. All four packaged binaries passed socket/terminal/snapshot CLI fixtures; x86-64 ran through installed translation, not native Intel/AMD hardware.
- Architecture-selectable Linux runtime suites with explicit platform assertions and separate images; full ARM64 and translated x86-64 suites passed, including raw ARP/NDP and denied-capability fixtures.
- Official Fing 4.0.5 and 3.10.1 downloaded and inspected. No standalone MAC registry recovered; exact findings are documented.
- Additional native Fing disassembly confirms a configurable file-loading OUI initializer and a remote-client path for the inspected catalog lookup. No complete recognition database was recovered; hash-checked evidence and limits are recorded.

## Still required before calling the broad goal finished

1. Expand identification: broader device/model catalogs, additional protocol fingerprints, and real-device coverage of the implemented mDNS/UPnP model paths. No claim of mapping everything.
2. Improve discovery coverage and speed further: privileged macOS ARP/NDP runtime verification, broader IPv6 real-device coverage, broader pacing/retry validation under sustained network pressure, and benchmark/accuracy comparisons across real device networks. The current quick scan is fast but can miss filtered/sleeping devices.
3. Broaden physical Linux/macOS hardware coverage, including native Intel/AMD execution beyond the passing ARM64 and translated x86-64 runtime checks; broaden terminal-emulator and accessibility coverage beyond the passing narrow/wide layout and macOS/Linux pseudo-terminal checks; harden all exported core options and large/full-port scans, and extend cancel/watch/error integration coverage.
4. Investigate any further recoverable Fing mapping data if useful. An absent standalone resource is not proof that no mapping exists in compiled or runtime-fetched form. Do not copy proprietary resources into an open-source release without an applicable redistribution basis.
5. Public release publication. GitHub checks on 2026-09-08 confirmed `coupez/lantern` is private. Draft PR #1 and an unpublished `v0.1.0-rc.1` release target integration commit `3e72244`; its macOS ARM64/Linux AMD64 CI passed, and all five uploaded assets passed authenticated download/checksum verification. Follow-up fixes after that commit are not included in those staged archives. Canonical installation from private GitHub with authentication, core imports from another module, staged installation, and self-contained local archives are verified; unauthenticated public retrieval remains unverified until repository/release visibility is resolved.

The persistent computer service and graphical app are explicitly out of scope for this phase. Core APIs are separated so both can be built later.
