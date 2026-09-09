# Goal status

The workspace started empty. A runnable CLI and reusable discovery engine now exist. The full Fing-alternative goal remains active.

The expanded [device-identification roadmap](device-identification-roadmap.md) records the current exploration priorities and measurement criteria.

## Implemented

- Go CLI with styled adaptive-width output, live discoveries/progress, inspect view, quick/standard/deep profiles, automatic default-route selection, and explicit target/interface selection.
- IPv4 automatic target selection retains its interface through local discovery and reports; IPv4/IPv6 neighbor tables and local-address evidence honor explicit scope, including duplicate IPs on different links.
- Multicast source recovery retries kernel-rejected bind addresses on the same selected interface under one deadline, shared by mDNS, SSDP, WS-Discovery, and doctor; actual Linux failed-DAD recovery is verified.
- Local capability diagnostics (`doctor`, `--interface`, `--json`) with actual socket/neighbor-table checks, cancellation, partial failures, and reusable core API; no discovery packets sent.
- Multicast collection preserves decoded replies after socket failures, distinguishes ordinary deadline expiry/cancellation, and reports packet/query-budget exhaustion instead of silently truncating discovery.
- Longer mDNS scans retry unanswered questions at one- then two-second intervals under the original deadline and shared 128-transmission cap. Controlled IPv4/IPv6 loss recovery is verified; the default one-second discovery window remains unchanged.
- Failed scans preserve printable/saved partial reports with an explicit error marker and conservative snapshot comparisons; broken JSONL pipes cancel and join workers before saving, with real macOS/Linux socket and terminal verification.
- Watch and snapshot diffs report comparable catalog service software changes on individual TCP ports, with structured values and compact activity text. Missing recognition, volatile greeting fields, incompatible coverage, and catalog-only reinterpretation do not create service-change alerts.
- Reports identify incomplete discovery methods separately from requested coverage and warning text. Snapshot/watch comparisons suppress dependent field changes and missing-address claims during partial discovery, and record method failure/recovery.
- Snapshot loading and saving reject invalid or repeated device IPs before they can silently overwrite comparison keys. Existing files survive rejected saves; legacy metadata and scoped IPv6 remain supported. Enumeration excludes unspecified addresses.
- Owned live device-update events stream normalized names/models/ports as each device finishes, with explicit progress phases, deep-copy API, JSONL output, and incremental first-scan dashboard details.
- Interactive watch dashboard with selection, grapheme-aware search/rendering with secondary identity claims, scrollable device details, bounded activity history, warnings, pause/refresh controls, synthetic demo, and terminal restoration. Plain and structured watch streams remain available.
- Watch redraws reuse search/filter/inspector views until inputs change and format only the visible service summary. Full-port search/details remain available, with measured large-report redraw improvements and explicit first-view costs.
- Full-port accumulation avoids quadratic duplicate searches, with exhaustive two-host/65,535-port uniqueness and event-ownership tests, cancellation coverage, and a real full-range loopback CLI fixture.
- Single-address and all-hosts TCP scans schedule requested services together with liveness probes, avoiding a separate discovery wait while retaining connection limits, unique jobs and requested-port coverage. Ordinary subnet scans retain liveness filtering.
- Cancellable core with deduplicated incremental port jobs, bounded TCP concurrency, bounded ICMP writes and queue-pressure retries, immediate completion for fully answered echo sweeps, per-scan echo counters, neighbor observation, mDNS/DNS-SD, SSDP, reverse DNS, and bounded parallel service banners with fragmented-response handling.
- WS-Discovery 2005/2009 Probe discovery on IPv4/IPv6, correlated replies, bounded XML and retransmissions, ONVIF name/hardware claims, and source-IP-only attribution. Independent wsdd interoperability is verified on IPv4/scoped IPv6, with typed DPWS compatibility Probes. Physical endpoint interoperability and managed discovery remain pending.
- Unicast IPv4 NetBIOS node-status discovery with source-attributed computer names, workgroups, raw registration bytes, cancellation, bounded pacing, and live Samba interoperability checks.
- IPv6 single/small-range scanning and bounded local discovery for large prefixes, scoped link-local addresses, ICMPv6, NDP cache, IPv6 mDNS/SSDP, and AAAA resolution.
- Opt-in direct IPv6 NDP with paced solicitations, validated/checksummed replies, early completion, scoped fresh MAC evidence, partial failure handling, capability diagnostics, and real Linux kernel veth verification. Privileged macOS NDP exchange remains pending.
- Explicit direct IPv4 ARP discovery with bounded sending, Linux packet sockets, macOS BPF backend, permission fallback, and solicited-reply validation. Linux ARM64 runtime verified; macOS raw exchange remains unverified.
- Embedded 58,421-entry IEEE MAC database with /24, /28, /36 longest-prefix matching, private/multicast MAC handling, and registry provenance.
- Five source-linked VRRP/CARP and HSRP virtual MAC ranges with group IDs, separate from registered vendor and physical/protocol identity. Offline lookup, scan/watch displays, JSON/CSV, snapshots, and independently owned core events retain the metadata.
- Embedded 5,889-entry IANA TCP service database, public-data refresh tooling.
- IMAP/POP3 first-greeting recognition on selected mail ports, including implicit TLS on 993/995, with no mail commands or mailbox access. Bounded collection and scoped claims preserve the common enrichment limits.
- HTTPS banner collection on labeled ports, including self-signed endpoints, within shared deadlines/concurrency and a 256 KiB TLS wire limit. IPv4/IPv6 CLI fixtures cover observations and output; certificate identity remains unverified.
- Banner patterns compile on demand after conservative required-text prechecks, with one shared compiled expression per rule. Cold concurrent lookup and source-example/differential verification preserve ordered matching.
- 946 BSD-2-Clause Recog SSH/HTTP/FTP/SMTP/IMAP/POP3 patterns, with reproducible pinned import, standalone core/CLI lookup, complete bounded greeting replies and field-specific line handling, scoped catalog fields, report/watch/inspector display, JSON/CSV/snapshot persistence, and independent event ownership. Physical-device accuracy remains pending.
- Companion model extraction and Roku ECP device-information reads add discovery-triggered identity evidence; source/model isolation and bounded IPv4/IPv6 fixtures are verified. Physical target coverage remains unverified.
- mDNS service-type enumeration and follow-up queries; bounded UPnP description reads with embedded-device matching; source-attributed names/models; rejection of duplicate or nested-markup UPnP identity fields; 40 MIT-licensed Cast model/manufacturer mappings.
- ESPHome discovery and firmware recognition with direct DNS-SD queries, friendly names, source-linked build/project claims, firmware exports/search/diffs, and separate IPv4/IPv6 socket fixtures. Physical ESPHome-device coverage remains pending.
- Shelly discovery through direct DNS-SD queries and bounded read-only identity requests, with model/name/firmware provenance and shared UPnP request/time limits. Generation-1 and physical Shelly-device coverage remain pending.
- 155 Apache-2.0 aioshelly model-name/generation records with pinned inputs, reproducible AST-only import, offline lookup, generation-aware recognition, and catalog/source isolation. AppleDB and Shelly together provide 761 offline identifiers.
- HomeKit model/name recognition and 36 protocol category codes, with source-linked type hints, conflict preservation, exact service matching, and IPv4/IPv6 socket fixtures. Physical HomeKit-device coverage remains pending.
- Matter DNS-SD recognition across commissionable, commissioner, and operational services, with advertised names/IDs and 65 pinned Apache-2.0 device-type labels. Split-reply IPv4/IPv6 fixtures cover all three roles; physical devices and Thread forwarding remain pending.
- Offline SmartThings Edge Matter catalog with 998 exact vendor/product pairs and source-linked label candidates. Reported model/manufacturer fields remain distinct; namespace-qualified CLI/core lookup, reproducible safe import, and scan recognition are supported. The three hardware catalogs now contain 1,759 identifiers.
- 606 MIT-licensed AppleDB hardware identifiers with 886 source assignments, ambiguity-preserving product names, RAOP model recognition, and an offline `models` lookup command.
- JSON, JSONL, CSV, atomic snapshots, and snapshot/watch changes for identity and response evidence, with requested scan coverage, interruption handling, common-port comparisons, and interface isolation. Wake-on-LAN and a no-network demo.
- MIT code license, upstream data notices, repeatable build and tests; local macOS/Linux ARM64/x86-64 release archives. All four packaged binaries passed socket/terminal/snapshot CLI fixtures; x86-64 ran through installed translation, not native Intel/AMD hardware.
- Architecture-selectable Linux runtime suites with explicit platform assertions and separate images; full ARM64 and translated x86-64 suites passed, including raw ARP/NDP and denied-capability fixtures.
- Official Fing 4.0.5 and 3.10.1 downloaded and inspected. No standalone MAC registry recovered; exact findings are documented.
- Additional native Fing disassembly confirms a configurable file-loading OUI initializer and a remote-client path for the inspected catalog lookup. No complete recognition database was recovered; hash-checked evidence and limits are recorded.

- Offline DHCPv4/v6 PCAP/PCAPNG import is available through `observe`, retaining raw option order, capture provenance and partial summaries without a bundled classifier.
- Direct local Mac kernel-model collection is implemented for selected local-interface addresses, with linked AppleDB candidates and preserved network conflicts. It does not identify other machines through their kernel.
- IPP/IPPS Get-Printer-Attributes collection is implemented for discovered Bonjour endpoints, using bounded response parsing and endpoint-scoped model claims. Only synthetic fixtures establish its current validation; physical printer/queue coverage is not measured.

- Offline identification evaluation scores independently labeled cases, preserves ambiguous/conflicting predictions, and separates observed/responsive discovery, model/type precision and recall. Synthetic arithmetic fixtures do not establish physical-device accuracy.

- ONVIF GetDeviceInformation adds endpoint-scoped manufacturer/model/firmware for eligible same-peer WS-Discovery services. Bounded unauthenticated SOAP reads preserve discovery on failure; serial/hardware-ID fields are discarded. Physical compatibility and credentialed inventory remain pending.

- Explicit SNMPv2c inventory reads one configured peer, with bounded system/ENTITY-MIB requests, chassis model source OIDs, ambiguity preservation and credential-free reports. Scan/watch integration, SNMPv3 and physical device coverage remain future work. See [inventory semantics](snmp-inventory.md).

## Still required before calling the broad goal finished

1. Expand identification: broader device/model catalogs, additional protocol fingerprints, and real-device coverage of the implemented mDNS/UPnP model paths. No claim of mapping everything.
2. Improve discovery coverage and speed further: privileged macOS ARP/NDP runtime verification, broader IPv6 real-device coverage, broader pacing/retry validation under sustained network pressure, and benchmark/accuracy comparisons across real device networks. The current quick scan is fast but can miss filtered/sleeping devices.
3. Broaden physical Linux/macOS hardware coverage, including native Intel/AMD execution beyond the passing ARM64 and translated x86-64 runtime checks; broaden terminal-emulator and accessibility coverage beyond the passing narrow/wide layout and macOS/Linux pseudo-terminal checks; harden all exported core options and large/full-port scans, and extend cancel/watch/error integration coverage.
4. Investigate any further recoverable Fing mapping data if useful. An absent standalone resource is not proof that no mapping exists in compiled or runtime-fetched form. Do not copy proprietary resources into an open-source release without an applicable redistribution basis.
5. Continue release maintenance. The repository is public, PR #1 is merged, and [rc.7](https://github.com/coupez/lantern/releases/tag/v0.1.0-rc.7) is published. All four public archives/checksums and installation through the public Go proxy were verified. Subsequent source changes are not included in rc.7 archives.

The persistent computer service and graphical app are explicitly out of scope for this phase. Core APIs are separated so both can be built later.
