# Snapshots and change detection

`lantern scan --save before.json`, `lantern watch --save latest.json`, and the core's `scanner.Save` write schema-1 JSON snapshots atomically. `lantern diff before.json after.json` prints a JSON array of changes. Watch mode uses the same `scanner.Diff` function for plain reports, JSONL change events, and dashboard activity.

Reports with a fatal runtime scan failure retain observations and an optional `error` string. The CLI attempts `--save` before exiting with status 1, including when a JSONL pipe breaks; input validation failures leave an existing snapshot untouched. A saved failed or interrupted scan is a partial observation set.

`scanner.Load` and `scanner.Save` require schema 1 and a unique, valid native IP for each device. Missing, null, unspecified, multicast, IPv4-mapped IPv6, and duplicate addresses are rejected. Equivalent IPv6 spellings count as the same address; different interface zones remain distinct. Load errors return a zero report and identify the input file; `lantern diff` exits 1 without emitting a change array. Save validates before creating a temporary file or replacing the destination. Optional legacy metadata, unknown extension fields, and duplicate port observations remain supported. This validates device keys, not every field in a report; callers constructing reports directly for `scanner.Diff` must supply valid, unique device addresses themselves.

Host enumeration skips unspecified addresses in zero-containing ranges. For example, `0.0.0.0/31` and `::/127` each enumerate one eligible address and fit `--max-hosts 1`.

## Observations, not physical-device verdicts

An IP address is the comparison key; scoped IPv6 addresses remain distinct. `added` means an address appears in the later observation set, and `missing` means it does not. Neither proves that a physical device joined or left the network. A MAC change can reflect a different device, randomized addressing, proxying, or a changed cache observation.

Optional `ports[].fingerprint` objects preserve source-linked banner catalog interpretations and independently scoped service/OS/hardware fields. Loading does not recompute them. They are excluded from port-change comparisons, like raw banner text; adding metadata to a legacy snapshot does not fabricate a new observation.

The optional `vendor.address_role` object preserves a virtual MAC range's label, prefix, encoded identifier, and source references. Older snapshots without it still load. This derived metadata is not compared independently: adding a label to the same MAC does not fabricate a device change; changing the MAC retains the existing MAC-change semantics. Loading a snapshot does not recompute its saved range metadata.

`changed` records identify a `field` and carry string-set `before`/`after` values, in addition to a readable `detail`. An omitted value array represents an empty set. Compared fields are observed MAC, registered vendor, verified-open TCP port observations, names, workgroups, selected identity name/manufacturer/model/firmware/version, catalog model candidates, type hint, and response evidence. These fields remain separate from their underlying raw advertisements and provenance claims in the report.

Response evidence changes between `responsive`, `cached only`, and `unconfirmed`. `responsive` uses the same core predicate as the CLI's device counts: an active discovery response or local-interface observation. `cached only` means the record has neighbor-cache evidence but no active response in that scan; it is not an assertion that the device is offline. Different responding protocols and changing latency alone do not generate activity.

Name sets ignore order, duplicates, DNS letter case, and a terminal DNS dot. MAC formatting differences, duplicate/reordered port observations, candidate ordering, latency, evidence ordering, banner content, and raw advertisement/claim changes alone do not produce events. Selected advertised identity strings retain their original case. Details quote control characters for safe terminal display; structured values preserve their original content except the documented set normalization.

## Requested scan coverage

New reports include an optional `coverage` object recording requested TCP ports and the ICMP, ARP, NDP, multicast, NetBIOS, reverse-DNS, UPnP-description, banner, and all-hosts options. It records configuration, not a guarantee that every probe completed or every protocol answered. Reports still use schema 1; older snapshots without coverage continue to load.

`scan` changes have an empty `ip` and report changed target, interface, requested coverage, or incomplete discovery methods. They explain when two snapshots differ in how they were collected:

- TCP port changes compare only ports requested by both scans. Scanning fewer ports does not manufacture disappearing services; newly requested ports have no prior comparable baseline.
- Name/identity/workgroup/type comparisons are suppressed when their relevant probe or enrichment options differ.
- Address additions, missing addresses, and response-state changes are suppressed when the known discovery configuration or target changes.
- Switching between known interfaces suppresses device comparisons altogether, avoiding conflation of identical IPv4 addresses on separate networks. Target changes on the same interface still allow field comparisons for addresses present in both snapshots.
- A cancelled later scan, or one with a nonempty `error`, can add newly observed addresses but does not report changes or disappearance of existing records. Watch mode omits the cancelled/failed cycle's change list.
- If coverage is absent in either snapshot, field comparisons fall back to observed values because the old probe plan cannot be reconstructed. Comparing known coverage with a legacy snapshot explicitly reports `unknown (legacy snapshot)`. Two legacy snapshots retain their prior observation-based behavior.

Changes are ordered by numeric IP address, then field/type/detail; scan-level records come first. The comparator reads its inputs without modifying them. It builds the common TCP-port set once for the entire comparison, rather than once per device.

## Partial discovery

Reports include optional `incomplete_methods`: a sorted, deduplicated list of discovery methods that reported errors or exhausted collection budgets. Human-readable `warnings` retain the reasons; their text cap does not discard structured method markers. Normal unanswered probes do not mark a method incomplete. Cancellation has its separate `cancelled` marker.

Any listed method in the later report suppresses missing-address and response-state changes. Newly observed addresses remain reportable under the existing scope/configuration rules. For addresses in both snapshots, comparisons are suppressed selectively:

| Incomplete method | Suppressed field comparisons |
| --- | --- |
| `tcp` | TCP ports and type hint |
| `arp`, `ndp`, `neighbors` | MAC and registered vendor |
| `multicast` | Names, selected identity fields, and type hint |
| `netbios` | Names, workgroups, selected identity fields, and type hint |
| `icmp`, `candidates` | No additional fields; retained addresses still receive independent field probes |
| Unknown future method | All device fields |

Multiple failures combine these restrictions. `multicast` covers mDNS, SSDP, and WS-Discovery; `neighbors` covers OS cache reads; `candidates` marks sparse IPv6 candidate truncation. `incomplete_methods` scan changes record failure or recovery even when device comparisons are suppressed. Once a later scan completes without reported discovery errors, normal comparisons resume, including newly recovered observations. This does not establish a physical change during the partial cycle.

An absent list does not prove completeness. Silent/filtered hosts, packet loss without a reported collector error, and unsuccessful reverse DNS, banner, or description enrichment can still leave observations empty. Those enrichment failures are not currently tracked by this field. Older snapshots without the field retain observational behavior; warning text is not parsed to guess a failure's source.

## Verification

`go test -race ./...` covers configuration-aware comparisons, interrupted scans, per-method failure suppression and recovery, warning caps, partial-result persistence, normalized sets, typed values/JSON round trips, identity and response changes, numeric/scoped address ordering, interface isolation, legacy files, and immutable coverage capture. `python3 scripts/test-snapshot-cli.py` checks the built CLI against real saved JSON artifacts without network access. The same script runs in CI and the Linux container suite. The Linux NDP fixture also verifies that actual raw-socket permission denial produces an `ndp` marker while successful exchanges leave it absent.

Automatic IPv4 CLI scans now retain their selected interface in the report. An older snapshot with an empty interface retains legacy observational comparison behavior and cannot establish same-link scope. Two reports with different recorded interface names produce an interface-coverage change and suppress host comparisons.
