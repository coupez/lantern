# Goal status

The workspace started empty. A runnable CLI and reusable discovery engine now exist. The full Fing-alternative goal remains active.

## Implemented

- Go CLI with styled adaptive-width output, live discoveries/progress, inspect view, quick/standard/deep profiles, automatic default-route selection, and explicit target/interface selection.
- Cancellable core with bounded TCP concurrency, bounded ICMP writes, incremental port jobs, neighbor observation, mDNS/DNS-SD, SSDP, reverse DNS, and simple service banners.
- Embedded 58,421-entry IEEE MAC database with /24, /28, /36 longest-prefix matching, private/multicast MAC handling, and registry provenance.
- Embedded 5,889-entry IANA TCP service database, public-data refresh tooling.
- mDNS service-type enumeration and follow-up queries; bounded UPnP description reads with embedded-device matching; source-attributed names/models; 40 MIT-licensed Cast model/manufacturer mappings.
- JSON, JSONL, CSV, atomic snapshots, snapshot diffs, watch mode, Wake-on-LAN, and a no-network demo.
- MIT code license, upstream data notices, repeatable build and tests; local macOS/Linux ARM64/x86-64 release archives.
- Official Fing 4.0.5 and 3.10.1 downloaded and inspected. No standalone MAC registry recovered; exact findings are documented.

## Still required before calling the broad goal finished

1. Expand identification: broader device/model catalogs, additional protocol fingerprints, and real-device coverage of the implemented mDNS/UPnP model paths. No claim of mapping everything.
2. Improve discovery coverage and speed further: direct ARP/NDP backend with explicit privilege behavior, IPv6 discovery, adaptive pacing/retry behavior, and benchmark/accuracy comparisons across real device networks. The current quick scan is fast but can miss filtered/sleeping devices.
3. Exercise and package Linux/macOS releases, complete terminal UX verification on narrow/wide terminals, harden all exported core options and large/full-port scans, and complete cancel/watch/error integration coverage.
4. Investigate any further recoverable Fing mapping data if useful. An absent standalone resource is not proof that no mapping exists in compiled or runtime-fetched form. Do not copy proprietary resources into an open-source release without an applicable redistribution basis.
5. Remote repository/release publication and installation experience. A local Git repository and release archives now exist. No remote repository exists yet, and nothing has been published.

The persistent computer service and graphical app are explicitly out of scope for this phase. Core APIs are separated so both can be built later.
