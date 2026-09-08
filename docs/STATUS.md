# Goal status

The workspace started empty. A runnable CLI and reusable discovery engine now exist. The full Fing-alternative goal remains active.

## Implemented

- Go CLI with styled adaptive-width output, live discoveries/progress, inspect view, quick/standard/deep profiles, automatic default-route selection, and explicit target/interface selection.
- Interactive watch dashboard with selection, grapheme-aware search/rendering, scrollable device details, bounded activity history, warnings, pause/refresh controls, synthetic demo, and terminal restoration. Plain and structured watch streams remain available.
- Cancellable core with deduplicated incremental port jobs, bounded TCP concurrency, bounded ICMP writes and queue-pressure retries, immediate completion for fully answered echo sweeps, per-scan echo counters, neighbor observation, mDNS/DNS-SD, SSDP, reverse DNS, and bounded parallel service banners with fragmented-response handling.
- Unicast IPv4 NetBIOS node-status discovery with source-attributed computer names, workgroups, raw registration bytes, cancellation, bounded pacing, and live Samba interoperability checks.
- IPv6 single/small-range scanning and bounded local discovery for large prefixes, scoped link-local addresses, ICMPv6, NDP cache, IPv6 mDNS/SSDP, and AAAA resolution.
- Explicit direct IPv4 ARP discovery with bounded sending, Linux packet sockets, macOS BPF backend, permission fallback, and solicited-reply validation. Linux ARM64 runtime verified; macOS raw exchange remains unverified.
- Embedded 58,421-entry IEEE MAC database with /24, /28, /36 longest-prefix matching, private/multicast MAC handling, and registry provenance.
- Embedded 5,889-entry IANA TCP service database, public-data refresh tooling.
- mDNS service-type enumeration and follow-up queries; bounded UPnP description reads with embedded-device matching; source-attributed names/models; 40 MIT-licensed Cast model/manufacturer mappings.
- 606 MIT-licensed AppleDB hardware identifiers with 886 source assignments, ambiguity-preserving product names, RAOP model recognition, and an offline `models` lookup command.
- JSON, JSONL, CSV, atomic snapshots, and snapshot/watch changes for identity and response evidence, with requested scan coverage, interruption handling, common-port comparisons, and interface isolation. Wake-on-LAN and a no-network demo.
- MIT code license, upstream data notices, repeatable build and tests; local macOS/Linux ARM64/x86-64 release archives.
- Official Fing 4.0.5 and 3.10.1 downloaded and inspected. No standalone MAC registry recovered; exact findings are documented.

## Still required before calling the broad goal finished

1. Expand identification: broader device/model catalogs, additional protocol fingerprints, and real-device coverage of the implemented mDNS/UPnP model paths. No claim of mapping everything.
2. Improve discovery coverage and speed further: privileged macOS ARP runtime verification, direct NDP, broader IPv6 real-device coverage, broader pacing/retry validation under sustained network pressure, and benchmark/accuracy comparisons across real device networks. The current quick scan is fast but can miss filtered/sleeping devices.
3. Broaden Linux/macOS hardware and x86-64 runtime coverage beyond the passing Linux ARM64 container tests; broaden terminal-emulator and accessibility coverage beyond the passing narrow/wide layout and macOS/Linux pseudo-terminal checks; harden all exported core options and large/full-port scans, and extend cancel/watch/error integration coverage.
4. Investigate any further recoverable Fing mapping data if useful. An absent standalone resource is not proof that no mapping exists in compiled or runtime-fetched form. Do not copy proprietary resources into an open-source release without an applicable redistribution basis.
5. Public release publication. GitHub API checks on 2026-09-08 confirm `coupez/lantern` is private and has no release assets. Canonical module installation, core imports from another module, staged installation, and self-contained local archives are verified locally; public retrieval remains unverified until the canonical revision is published and repository/release visibility is resolved.

The persistent computer service and graphical app are explicitly out of scope for this phase. Core APIs are separated so both can be built later.
