# ◈ Lantern

**See your network clearly.** A fast, local-first network scanner with a modern terminal interface and a reusable Go engine. No account, cloud recognition, telemetry, or background daemon.

> Early development. macOS is exercised on a local network. Linux ARM64 passes controlled container network tests; broader hardware coverage is still needed.

```sh
make build
./bin/lantern             # select the default-route network automatically
./bin/lantern demo        # preview the interface without sending packets
./bin/lantern demo --watch # try the interactive dashboard with synthetic data
```

Go 1.26.8 or newer is required to build. Go can download the project-required toolchain automatically. The resulting executable contains the vendor and service databases and runs offline. Default macOS scanning works without root. Linux requires `ip` from iproute2 for neighbor discovery; ICMP permissions depend on the host's ping socket configuration.

## Everyday commands

```sh
lantern scan --profile quick
lantern scan 192.168.1.0/24
lantern scan --ipv6 --interface en0
lantern inspect fe80::1%en0
lantern inspect 192.168.1.42
lantern scan 192.168.1.42 --ports 1-65535
lantern watch --interval 10s --save latest.json
lantern scan --json > network.json
lantern scan --jsonl               # streaming discovery events + final report
lantern scan --csv > network.csv
lantern diff before.json after.json
lantern lookup 00:00:0c:12:34:56
lantern vendors sources
lantern interfaces
lantern wake 00:11:22:33:44:55 192.168.1.255
```

Use `./bin/lantern` until you put the binary on your PATH. Options work before or after the target. `lantern help` lists every option. `NO_COLOR=1` disables colors. Redirected output is plain text; JSON and CSV contain no progress messages.

`lantern watch` opens a live dashboard when stdin and stdout are terminals on macOS or Linux. Use arrow keys or `j`/`k` to select a device, `Enter` to inspect its full record, `/` to search names, addresses, vendors, models, or services, and `a` for recent changes and scan warnings. Details and activity scroll with arrows, Page Up/Down, Home, and End. `Space` pauses automatic refresh, `r` scans once, and `q` or Ctrl-C exits. While typing a search, Enter applies it, Escape clears it, and Ctrl-C exits.

The previous completed report stays visible during refresh; new addresses appear during the first scan. Pausing lets an active scan finish. Scans never overlap, and the interval starts after each scan completes. `--save` also saves partial results when an active scan is cancelled. The dashboard restores the cursor and original terminal mode on exit, scan errors, and save errors.

Use `watch --plain` for appended reports or `watch --jsonl` for a machine-readable stream. Redirected stdin/stdout and `TERM=dumb` automatically use appended reports. `--no-color` preserves keyboard navigation while disabling colors. The dashboard adapts to terminal resizing and requires at least 36 columns × 10 rows to display results; below that it shows a resize prompt. `demo --watch` requires an interactive terminal and never accesses the network.

## Discovery and speed

Lantern combines ICMP echo, TCP connect/refusal, the OS neighbor table, mDNS/DNS-SD, and SSDP. It scans common discovery ports across the target first, then checks requested ports on discovered devices. A single-IP target always checks all requested ports; `--all-hosts` does the same for every address in a subnet.

The TCP worker pool defaults to 512 concurrent probes. Deadlines bound TCP and ICMP sends; large port ranges are produced incrementally rather than allocated as a host × port matrix. DNS enrichment uses its own bounded pool. Ctrl-C cancels sockets and returns partial results. Unicast ICMP finishes early when every target replies. Local send-queue failures get one bounded retry; JSON reports `icmp` counters for attempted/sent/failed addresses, retries, recovered sends, and responders.

| Profile | Behavior |
| --- | --- |
| `quick` | ICMP + TCP discovery + neighbor lookup; checks 80/443; skips multicast |
| `standard` | Adds mDNS/SSDP, device descriptions, and 14 common TCP service ports |
| `deep` | 28 common service ports, device descriptions, mDNS/SSDP, and protocol banner reads |

`--timeout 300ms` controls each probe. Increase it for congested Wi-Fi or sleeping devices. Standard and deep scans allow at least one second for multicast responses. A full TCP scan is `--ports 1-65535`; deep is not a full-port scan. `--ports none` disables TCP probes, leaving ICMP, multicast, and neighbor observations as enabled.

The initial live macOS benchmark scanned **1,022 addresses in 2.39 seconds** in standard mode at 512 TCP workers. A full 65,535-port localhost scan completed in **0.86 seconds**. This is one network measurement, not a completeness guarantee or a comparison with Fing. Later alternating quick-scan runs with ICMP retries completed in **0.90–1.05 seconds**, versus **3.85–4.02 seconds** for the saved earlier build; both observed two addresses. Retry recovery and remaining send failures are recorded in the reports. These timings depend on local queue/cache state. Warm offline vendor lookup measured **76.7 ns/op** on an Apple M4 Max. See [verification](docs/verification.md).

## Know what the results mean

- **● Responsive** means a TCP/ICMP/ARP/mDNS/SSDP response or a local interface was observed. **○ Cached neighbor** means the OS has an address mapping; it does not prove the device is awake.
- MAC vendors are registered IEEE organizations, which may differ from the device's retail brand. Randomized/private MACs are labeled explicitly and do not receive a guessed vendor.
- Device types are hints based on services. An RTSP port can belong to a camera or another media device. Port names come from IANA/common conventions; a name does not prove which application is running there.
- Device names and models are extracted from UPnP descriptions and known Bonjour printing, AirPlay, and Cast TXT fields. Pinned MIT-licensed catalogs add manufacturers for **40 exact Cast model names**, plus **606 Apple/Beats hardware identifiers** with **886 model assignments**. The 124 identifiers with multiple product names retain every candidate. The JSON `identity.claims` records whether each field is advertised or catalog-derived, its source, and conflicting values; MAC ownership stays separate.
- Advertisements and banners are device-reported, untrusted information. Advertised ports are separate from verified open TCP ports. Terminal control characters are removed before rendering.
- Discovery can miss filtered, isolated, sleeping, or slow devices. MAC addresses normally exist only for hosts on the same link. Direct NDP, OS fingerprinting, and a persistent service are not implemented yet.

Use on networks you own or are authorized to inspect. Lantern makes ordinary discovery requests and connections; it does not log in to devices or execute remote commands.

UPnP descriptions are enabled in standard/deep mode. `--no-descriptions` disables them. Reads stay on the SSDP responder’s literal IP, never use a proxy or follow redirects, and share one per-device deadline across at most four URLs. XML is capped at 256 KiB and bounded in depth. mDNS follows missing PTR/SRV/TXT/A/AAAA records and enumerates additional service types within the original discovery deadline and a 128-query budget.

[Recognition sources and rules](docs/recognition.md) describe the supported mappings and limitations.

IPv6 single addresses and small prefixes support TCP, ICMPv6, DNS, banners, and the same device recognition paths. Link-local targets need a zone (`fe80::1%en0`) or `--interface`. `--ipv6` discovers neighbors on one selected interface using all-nodes echo, IPv6 mDNS/SSDP, the NDP cache, and local addresses. Large IPv6 prefixes use this sparse discovery automatically: Lantern never enumerates a /64. `--max-hosts` caps the candidate list; `--all-hosts` checks all discovered candidates, not the entire IPv6 address space. JSON reports distinguish `address_mode: "discovered"` from `"enumerated"` and retain the interface scope. IPv4 and IPv6 currently use separate scans, and a dual-stack device can appear under multiple addresses.

`--arp` adds direct IPv4 ARP requests on a matching local Ethernet interface, concurrently with the other discovery methods. It is disabled by default: macOS needs access to `/dev/bpf*` (normally administrator access), and Linux needs `CAP_NET_RAW`. If access is unavailable, a warning explains the missing capability and the remaining scan methods continue. Replies are marked `arp`, even if every IP probe is blocked. Direct ARP was verified on Linux ARM64; macOS BPF live exchange still needs privileged verification. See [discovery details](docs/discovery.md).

Use `lantern models Mac16,9` to look up a hardware code offline, `lantern models` for the index count, or `lantern models sources` for provenance. Discovery maps Bonjour device-info/AirPlay `model` and RAOP `am` fields to these candidates. The reported `identity.model` stays intact; `identity.model_names` contains catalog candidates. A unique candidate appears in the report, while ambiguous matches are labeled and listed in `inspect` / `--details`. CSV appends `model_candidates`.

## Open data and Fing inspection

The binary includes **58,421 MAC assignments** from IEEE MA-L, MA-M, MA-S, and IAB, with longest-prefix matching, plus **5,889 IANA TCP service names**. Dataset source URLs, retrieval dates, and SHA-256 hashes are checked in next to the embedded indexes. Source data is attributed separately from the code's MIT license; see [NOTICE](NOTICE).

Fing macOS 4.0.5 and 3.10.1 were downloaded from official URLs and inspected locally without installation. No standalone MAC assignment database was found. The native library references an absent `ethernet-ouis.properties`; the legacy UI asks its agent for recognition details. Extracted binaries and proprietary resources stay outside the distributable source. [Inspection evidence](docs/fing-research.md) records exactly what was found and what remains unknown.

## A core for the future app

```go
options := scanner.Defaults()
options.Target = netip.MustParsePrefix("192.168.1.0/24")
report, err := (scanner.Engine{}).Scan(ctx, options, func(event scanner.Event) {
    // Stream progress into a CLI, UI, or future service transport.
})
```

`pkg/scanner` owns discovery, enrichment, reports, snapshots, and diffs. `pkg/vendors` owns offline MAC lookups and `pkg/models` owns hardware-model lookups. `internal/ui` owns terminal rendering; `cmd/lantern` owns flags and signals. The engine takes `context.Context`, produces structured records, and has no dependency on terminal output, process exits, or a daemon. Callbacks run serially and should return promptly. Network test doubles are injectable.

## Development

```sh
make check
LANTERN_NETWORK_TESTS=1 go test -race ./pkg/scanner -run NetworkIntegration -v
go test ./pkg/vendors -bench BenchmarkLookup -benchmem -run '^$'
python3 scripts/update-data.py && make build # refresh the public indexes
python3 scripts/build-apple-models.py --download # rebuild the pinned model catalog
```

To reproduce Linux runtime verification, run `make linux-test` with Docker available. The container receives only `NET_RAW`, has no host mounts or published ports, and probes its own bridge gateway for the ARP check.

The network integration test uses controlled IPv4/IPv6 localhost servers to verify ICMP, port detection, SSH/HTTP banners, DNS-SD follow-ups, and UPnP description boundaries. Regular tests don't send scan traffic. See [status and remaining work](docs/STATUS.md).
