# Snapshots and change detection

`lantern scan --save before.json`, `lantern watch --save latest.json`, and the core's `scanner.Save` write schema-1 JSON snapshots atomically. `lantern diff before.json after.json` prints a JSON array of changes. Watch mode uses the same `scanner.Diff` function for plain reports, JSONL change events, and dashboard activity.

## Observations, not physical-device verdicts

An IP address is the comparison key; scoped IPv6 addresses remain distinct. `added` means an address appears in the later observation set, and `missing` means it does not. Neither proves that a physical device joined or left the network. A MAC change can reflect a different device, randomized addressing, proxying, or a changed cache observation.

`changed` records identify a `field` and carry string-set `before`/`after` values, in addition to a readable `detail`. An omitted value array represents an empty set. Compared fields are observed MAC, registered vendor, verified-open TCP port observations, names, workgroups, selected identity name/manufacturer/model, catalog model candidates, type hint, and response evidence. These fields remain separate from their underlying raw advertisements and provenance claims in the report.

Response evidence changes between `responsive`, `cached only`, and `unconfirmed`. `responsive` uses the same core predicate as the CLI's device counts: an active discovery response or local-interface observation. `cached only` means the record has neighbor-cache evidence but no active response in that scan; it is not an assertion that the device is offline. Different responding protocols and changing latency alone do not generate activity.

Name sets ignore order, duplicates, DNS letter case, and a terminal DNS dot. MAC formatting differences, duplicate/reordered port observations, candidate ordering, latency, evidence ordering, banner content, and raw advertisement/claim changes alone do not produce events. Selected advertised identity strings retain their original case. Details quote control characters for safe terminal display; structured values preserve their original content except the documented set normalization.

## Requested scan coverage

New reports include an optional `coverage` object recording requested TCP ports and the ICMP, ARP, multicast, NetBIOS, reverse-DNS, UPnP-description, banner, and all-hosts options. It records configuration, not a guarantee that every probe completed or every protocol answered. Reports still use schema 1; older snapshots without coverage continue to load.

`scan` changes have an empty `ip` and report changed target, interface, or requested coverage. They explain when two snapshots differ in how they were collected:

- TCP port changes compare only ports requested by both scans. Scanning fewer ports does not manufacture disappearing services; newly requested ports have no prior comparable baseline.
- Name/identity/workgroup/type comparisons are suppressed when their relevant probe or enrichment options differ.
- Address additions, missing addresses, and response-state changes are suppressed when the known discovery configuration or target changes.
- Switching between known interfaces suppresses device comparisons altogether, avoiding conflation of identical IPv4 addresses on separate networks. Target changes on the same interface still allow field comparisons for addresses present in both snapshots.
- A cancelled later scan can add newly observed addresses but does not report changes or disappearance of existing records. Watch mode omits the cancelled cycle's change list.
- If coverage is absent in either snapshot, field comparisons fall back to observed values because the old probe plan cannot be reconstructed. Comparing known coverage with a legacy snapshot explicitly reports `unknown (legacy snapshot)`. Two legacy snapshots retain their prior observation-based behavior.

Changes are ordered by numeric IP address, then field/type/detail; scan-level records come first. The comparator reads its inputs without modifying them. It builds the common TCP-port set once for the entire comparison, rather than once per device.

## Verification

`go test -race ./...` covers configuration-aware comparisons, interrupted scans, normalized sets, typed values/JSON round trips, identity and response changes, numeric/scoped address ordering, interface isolation, legacy files, and immutable coverage capture. `python3 scripts/test-snapshot-cli.py` checks the built CLI against real saved JSON artifacts without network access. The same script runs in CI and the Linux container suite.
