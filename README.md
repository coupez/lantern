# ◈ Lantern

**See your network clearly.** A fast, local-first network scanner with a modern terminal interface and a reusable Go engine. No account, cloud recognition, telemetry, or background daemon.

> Early development. macOS is exercised on a local network. Linux ARM64 passes controlled container network tests; broader hardware coverage is still needed.

```sh
make build                 # from a source checkout
./bin/lantern             # select the default-route network automatically
./bin/lantern demo        # preview the interface without sending packets
./bin/lantern demo --watch # try the interactive dashboard with synthetic data
```

Go 1.26.8 or newer is required to build. Go can download the project-required toolchain automatically. The resulting executable contains the vendor and service databases and runs offline. Default macOS scanning works without root. Linux requires `ip` from iproute2 for neighbor discovery; ICMP permissions depend on the host's ping socket configuration.

Install from a checkout with `make install` (defaults to `$HOME/.local/bin`). The repository is public; [rc.7 downloads](https://github.com/coupez/lantern/releases/tag/v0.1.0-rc.7) are available for macOS and Linux on ARM64 and x86-64. [Installation and archive instructions](docs/install.md) cover custom prefixes, Go module installation, checksums, and runtime requirements.

## Everyday commands

```sh
lantern scan --profile quick
lantern scan 192.168.1.0/24
lantern scan --ipv6 --interface en0
lantern inspect fe80::1%en0
lantern inspect 192.168.1.42
lantern scan 192.168.1.42 --ports 1-65535
lantern scan --netbios             # include IPv4 NetBIOS names/workgroups
lantern watch --interval 10s --save latest.json
lantern scan --json > network.json
lantern scan --jsonl               # streaming discovery events + final report
lantern scan --csv > network.csv
lantern observe --read capture.pcap --jsonl # offline DHCPv4/v6 fingerprint evidence
lantern snmp 192.0.2.1 --community-env LANTERN_SNMP_COMMUNITY --json
lantern android --transport-id 42 --json # use the selected authorized ADB transport
lantern diff before.json after.json
lantern evaluate --truth truth.json --scan network.json --bindings bindings.json --json
lantern lookup 00:00:0c:12:34:56
lantern fingerprint http 'Apache/2.4.65'
lantern fingerprint ssh 'OpenSSH_9.9'
lantern fingerprint smtp 'foo.bar ESMTP Postfix (3.1.4)'
lantern fingerprint pop3 'Dovecot ready.'
lantern lookup 00:00:5e:00:01:2a
lantern vendors sources
lantern interfaces
lantern wake 00:11:22:33:44:55 192.168.1.255
```

Use `./bin/lantern` until you put the binary on your PATH. Options work before or after the target. `lantern help` lists every option. `NO_COLOR=1` disables colors. Redirected output is plain text; JSON and CSV contain no progress messages.

`lantern watch` opens a live dashboard when stdin and stdout are terminals on macOS or Linux. Use arrow keys or `j`/`k` to select a device, Home/End to jump to the first/last device, `Enter` to inspect its full record, `/` to search names, addresses, vendors, models, services, or identity claims (including hardware descriptions and alternate models), and `a` for recent changes and scan warnings. Details and activity scroll with arrows, Page Up/Down, Home, and End. `Space` pauses automatic refresh, `r` scans once, and `q` or Ctrl-C exits. While typing a search, Enter applies it, Escape clears it, and Ctrl-C exits.

The previous completed report stays visible during refresh; new addresses appear during the first scan. Pausing lets an active scan finish. Scans never overlap, and the interval starts after each scan completes. `--save` also saves partial results when an active scan is cancelled or fails. The dashboard restores the cursor and original terminal mode on exit, scan errors, and save errors.

Use `watch --plain` for appended reports or `watch --jsonl` for a machine-readable stream. Redirected stdin/stdout and `TERM=dumb` automatically use appended reports. `--no-color` preserves keyboard navigation while disabling colors. The dashboard adapts to terminal resizing and requires at least 36 columns × 10 rows to display results; below that it shows a resize prompt. `demo --watch` requires an interactive terminal and never accesses the network.

## Discovery and speed

Lantern combines ICMP echo, TCP connect/refusal, the OS neighbor table, mDNS/DNS-SD, SSDP, and WS-Discovery. Ordinary subnet scans check common discovery ports first, then requested ports on discovered devices. A single-IP target and `--all-hosts` combine requested ports and liveness probes into one bounded pass, starting requested services immediately. Each target still receives all requested ports in those modes.

The TCP worker pool defaults to 512 concurrent probes. Deadlines bound TCP and ICMP sends; large port ranges are produced incrementally rather than allocated as a host × port matrix. Each address/port pair runs once, and open-port collection avoids repeated searches through the growing result list. DNS enrichment uses its own bounded pool. Ctrl-C cancels sockets and returns partial results. Fatal TCP failures preserve available results with a JSON `error` field and exit status 1. A broken JSONL pipe cancels work promptly and still attempts `--save`. Unicast ICMP finishes early when every target replies. Local send-queue failures get one bounded retry; JSON reports `icmp` counters for attempted/sent/failed addresses, retries, recovered sends, and responders.

| Profile | Behavior |
| --- | --- |
| `quick` | ICMP + TCP discovery + neighbor lookup; checks 80/443; skips multicast |
| `standard` | Adds mDNS/SSDP/WS-Discovery, device descriptions, and 14 common TCP service ports |
| `deep` | 28 common service ports, device descriptions, mDNS/SSDP/WS-Discovery, and protocol banner reads |

`--timeout 300ms` controls each probe. Increase it for congested Wi-Fi or sleeping devices. Standard and deep scans allow at least one second for multicast responses. A full TCP scan is `--ports 1-65535`; deep is not a full-port scan. `--ports none` disables TCP probes, leaving ICMP, multicast, and neighbor observations as enabled.

Deep scans read service banners in parallel, with at most four connections per device and 32 across the scan (fewer when `--concurrency` is lower). Each banner connection shares one timeout across dialing and reading. See [discovery limits](docs/discovery.md).

The initial live macOS benchmark scanned **1,022 addresses in 2.39 seconds** in standard mode at 512 TCP workers. A full 65,535-port localhost scan completed in **0.86 seconds**. This is one network measurement, not a completeness guarantee or a comparison with Fing. Later alternating quick-scan runs with ICMP retries completed in **0.90–1.05 seconds**, versus **3.85–4.02 seconds** for the saved earlier build; both observed two addresses. Retry recovery and remaining send failures are recorded in the reports. These timings depend on local queue/cache state. Warm offline vendor lookup measured **76.7 ns/op** on an Apple M4 Max. See [verification](docs/verification.md).

### Banner recognition

Deep scans and `--banners` interpret observed SSH software/comment text and HTTP/HTTPS Server headers, plus complete FTP/SMTP/IMAP/POP3 greetings (including IMAPS/POP3S), with **946 offline Recog patterns** under BSD-2-Clause. Catalog service labels appear in reports and watch; the inspector and JSON retain separate service, OS, and hardware claims with source links and qualifiers. These claims do not overwrite device-reported manufacturer/model fields. CSV appends `service_fingerprints` after `mac_address_role_id`.

`lantern fingerprint http 'Apache/2.4.65'` works offline. For SSH, pass the software/comment portion after `SSH-<version>-`; for `ftp` or `smtp`, pass greeting text after reply prefixes; `lantern fingerprint sources` prints provenance. Matching adds no connections beyond banner collection. HTTPS accepts self-signed certificates for unverified service observation within the same timeout; see [collection limits](docs/discovery.md#tcp-probes-and-service-banners). Physical-device accuracy remains unverified; see [recognition semantics](docs/recognition.md#banner-fingerprints).

### NetBIOS names

Deep IPv4 scans and `lantern inspect IP` include a unicast NetBIOS node-status pass. Use `--netbios` with other profiles or `--netbios=false` to disable it. It can discover a responding Windows/Samba/NAS address even when the initial TCP probes do not answer. The pass runs concurrently with other discovery and uses one response window for the entire target list, with bounded request bursts.

Computer names, workgroups, registration flags, and reported unit IDs remain in the raw advertisements; recognized computer names also enter the name/identity fields. A workgroup is not a host name, and a reported unit ID does not override an observed MAC. Registrations are service hints, not verified open TCP ports or operating-system identification. NetBIOS-disabled systems need the other discovery paths. This protocol supports IPv4 and the default empty NetBIOS scope only.

## Configured device inventory

`lantern snmp IP --community-env NAME --json` reads system fields and bounded ENTITY-MIB chassis inventory from one explicitly configured SNMPv2c device. A unique root chassis can supply a reported model, while agent descriptions and vendor namespaces remain separate. Communities are supplied through the named environment variable; v2c is unencrypted. Ordinary scan/watch profiles do not send SNMP queries. See [setup, evidence and limits](docs/snmp-inventory.md).

`lantern android --transport-id ID --json` reads four model-related properties from an explicitly selected, already-authorized device through an existing local ADB server. It preserves manufacturer/model, device codename and raw build fingerprint as separate fields with source keys. It neither starts ADB nor infers a LAN address; see [Android setup and evidence boundaries](docs/android-inventory.md).

`lantern enrich --scan scan.json --inventory inventory.json --save enriched.json --details` attaches saved Android/SNMP evidence to explicitly bound existing addresses. It preserves network observations, source hashes and conflicting claims. See the [manifest and runnable example](docs/inventory-snapshots.md). The evaluator includes inventory only with `--include-inventory`.

`lantern scan --ubiquiti --details` adds opt-in IPv4 Ubiquiti UDP discovery alongside the other passes. Dedicated model fields remain separate from platform and firmware-build observations; see [wire behavior and bounds](docs/ubiquiti-discovery.md).

## Check local capabilities

`lantern doctor` checks actual ICMP, multicast, ARP/NDP, neighbor-table, and automatic target-selection access without sending discovery packets. Use `--interface en0` to select a network or `--json` for scripts. Optional failures include a reason and next step; socket access alone does not prove device reachability. See [diagnostics](docs/diagnostics.md).

## Know what the results mean

- **● Responsive** means a TCP/ICMP/ARP/NDP/mDNS/SSDP/WS-Discovery/NetBIOS response or a local interface was observed. **○ Cached neighbor** means the OS has an address mapping; it does not prove the device is awake.
- MAC vendors are registered IEEE organizations, which may differ from the device's retail brand. Randomized/private MACs are labeled explicitly and do not receive a guessed vendor.
- Known virtual-router MAC ranges carry a separate label and group ID. For example, `00:00:5e:00:01:2a` matches the shared VRRP/CARP range with ID 42. This describes the address assignment; it does not establish a running protocol or hardware identity. Reports, watch, and JSON/snapshots retain this metadata; CSV appends `mac_address_role` and `mac_address_role_id` after `firmware_version`. See [supported ranges](docs/recognition.md#virtual-router-mac-ranges).
- Device types are hints based on services. An RTSP port can belong to a camera or another media device. Port names come from IANA/common conventions; a name does not prove which application is running there.
- Device names and models are extracted from UPnP descriptions and known Bonjour printing, AirPlay, Cast, and HomeKit TXT fields. HomeKit also supplies **36 category codes** for more specific type hints without extra probes. Pinned MIT-licensed catalogs add manufacturers for **40 exact Cast model names**, plus **606 Apple/Beats hardware identifiers** with **886 model assignments**. The 124 identifiers with multiple product names retain every candidate. The JSON `identity.claims` records whether each field is advertised, read from the local system, protocol-interpreted, or catalog-derived, its source, and conflicting values; MAC ownership stays separate.
- Advertisements and banners are device-reported, untrusted information. Advertised ports are separate from verified open TCP ports. Terminal control characters are removed before rendering.
- Discovery can miss filtered, isolated, sleeping, or slow devices. MAC addresses normally exist only for hosts on the same link. OS fingerprinting and a persistent service are not implemented yet.

Use on networks you own or are authorized to inspect. Lantern makes ordinary discovery requests and connections; ordinary scans do not log in to devices or execute remote commands. The separate SNMP inventory command uses explicitly configured access.

WS-Discovery adds correlated UDP discovery for compatible endpoints, with ONVIF names and hardware-description claims. Advertised endpoint URLs remain metadata, with bounded device-information reads for qualifying same-peer ONVIF services. They do not become verified open ports.

UPnP, Shelly, Roku, IPP and ONVIF identity reads are enabled in standard/deep mode. `--no-descriptions` disables them. Reads stay on the discovered device’s literal IP, never use a proxy or follow redirects, and share one per-device deadline across at most four request targets. UPnP XML is capped at 256 KiB and bounded in depth; Shelly JSON is capped at 16 KiB. mDNS follows missing PTR/SRV/TXT/A/AAAA records and enumerates additional service types within the original discovery deadline and a 128-query budget.

[Recognition sources and rules](docs/recognition.md) describe the supported mappings and limitations.

IPv6 single addresses and small prefixes support TCP, ICMPv6, DNS, banners, and the same device recognition paths. Link-local targets need a zone (`fe80::1%en0`) or `--interface`. `--ipv6` discovers neighbors on one selected interface using all-nodes echo, IPv6 mDNS/SSDP/WS-Discovery, the NDP cache, and local addresses. Large IPv6 prefixes use this sparse discovery automatically: Lantern never enumerates a /64. `--max-hosts` caps the candidate list; `--all-hosts` checks all discovered candidates, not the entire IPv6 address space. JSON reports distinguish `address_mode: "discovered"` from `"enumerated"` and retain the interface scope. IPv4 and IPv6 currently use separate scans, and a dual-stack device can appear under multiple addresses.

`--arp` adds direct IPv4 ARP requests on a matching local Ethernet interface, concurrently with the other discovery methods. It is disabled by default: macOS needs access to `/dev/bpf*` (normally administrator access), and Linux needs `CAP_NET_RAW`. If access is unavailable, a warning explains the missing capability and the remaining scan methods continue. Replies are marked `arp`, even if every IP probe is blocked. Direct ARP was verified on Linux ARM64; macOS BPF live exchange still needs privileged verification. See [discovery details](docs/discovery.md).

`--ndp` adds direct IPv6 neighbor solicitation on the selected Ethernet interface, with the same raw-access requirements. Use `lantern scan fe80::1234%en0 --ndp` or `lantern scan --ipv6 --interface en0 --ndp`. It probes finite ranges or the bounded candidate list for large ranges, records fresh `ndp` MAC evidence, and finishes early when every requested neighbor answers. Linux kernel exchanges are verified; privileged macOS BPF exchange remains pending.

ESPHome devices advertising `_esphomelib._tcp` gain a friendly name, an ESPHome firmware label, and the reported firmware version. Build-board, platform, and project details appear as source-linked claims in the inspector. These details remain separate from retail hardware identity and observed MAC addresses. CSV appends `firmware` and `firmware_version` after `model_candidates`; JSON/snapshots add the same optional identity fields.

Matter DNS-SD discovery recognizes commissionable, commissioner, and operational advertisements. Reported names and 65 protocol type labels can identify categories such as lights, locks, sensors, and appliances. A pinned Apache-2.0 SmartThings catalog maps **998 exact vendor/product pairs** to label candidates, preserving raw IDs and provenance. Try `lantern models matter:4447:8194` for an offline lookup. No pairing or cloud lookup is required; physical-device and Thread forwarding coverage remain unverified. See [recognition details](docs/recognition.md).

For lossy discovery, a longer `--timeout` also gives unanswered mDNS questions time for bounded retries (`--timeout 4s`, for example). Retries share the original deadline and query cap; the default one-second multicast window remains unchanged. See [discovery limits](docs/discovery.md).

Shelly devices advertising `_shelly._tcp` gain an instance-name fallback and smart-home type hint. With descriptions enabled, a bounded read of `/shelly` adds the reported model, name, firmware/version, and source-linked build/application claims. A pinned Apache-2.0 catalog adds **155 exact model-name/generation records**; matching model and generation can add a catalog product name and Shelly brand label. `lantern models SNSW-001X16EU` also resolves these codes offline. Advertised MACs remain separate from link-layer observations. See [Shelly recognition and limits](docs/recognition.md#shelly-recognition).

Use `lantern models Mac16,9` to look up a hardware code offline, `lantern models` for the index count, or `lantern models sources` for provenance. Discovery maps Bonjour device-info/AirPlay `model` and RAOP `am` fields to these candidates. The reported `identity.model` stays intact; `identity.model_names` contains catalog candidates. A unique candidate appears in the report, while ambiguous matches are labeled and listed in `inspect` / `--details`. CSV includes `model_candidates`.

Watch also labels catalog-only identities: one match appears as `Catalog · <product>`, while multiple matches show a candidate count. Enter opens the full candidate list. Existing names, MAC vendors, and reported models retain display priority.

### Useful watch activity

Use `lantern watch --banners` to include service recognition in monitoring. Watch and snapshot diffs report name/model/vendor/workgroup changes, open-port observations, comparable catalog software versions on individual TCP ports, and transitions from responsive to cached-only evidence. New snapshots record requested scan coverage: changing profiles or scanning fewer ports does not fabricate disappearing services. Interrupted scans do not erase existing observations. Reported discovery failures suppress missing-address claims and comparisons of dependent fields; optional `incomplete_methods` metadata records which methods failed or reached collection limits. Changes are address-based observations, not proof that a physical device joined or went offline. See [snapshot comparison semantics](docs/snapshots.md) for structured fields and legacy-file behavior.

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

External applications import `github.com/coupez/lantern/pkg/scanner` (and `pkg/vendors` or `pkg/models` under the same module path).

`pkg/scanner` owns discovery, enrichment, reports, snapshots, and diffs. `pkg/vendors` owns offline MAC lookups and `pkg/models` owns hardware-model lookups. `internal/ui` owns terminal rendering; `cmd/lantern` owns flags and signals. The engine takes `context.Context`, produces structured records, and has no dependency on terminal output, process exits, or a daemon. Callbacks run serially and should return promptly. Independently owned `device_update` snapshots stream enriched details as each device finishes; JSONL and the first watch scan use these updates. See [core events and ownership](docs/core-events.md). Network test doubles are injectable.

## Development

```sh
make check
make install-test             # isolated Go install + core consumer checks
make release VERSION=dev      # local archives; does not publish
python3 scripts/test-release.py dev
LANTERN_NETWORK_TESTS=1 go test -race ./pkg/scanner -run NetworkIntegration -v
go test ./pkg/vendors -bench BenchmarkLookup -benchmem -run '^$'
python3 scripts/update-data.py && make build # refresh the public indexes
python3 scripts/build-apple-models.py --download # rebuild the pinned model catalog
```

To reproduce Linux runtime verification, run `make linux-test` with Docker available. Set `LINUX_PLATFORM=linux/amd64` or `LINUX_PLATFORM=linux/arm64` to select an architecture explicitly; foreign targets need installed Docker translation support. The main container receives only `NET_RAW` and probes its own bridge gateway for the ARP check. Separate isolated fixtures use `NET_ADMIN` for temporary veth links and add `NET_RAW` only for direct NDP exchange; denied-capability cases are tested too. No test container uses host networking, host mounts, or published ports.

The network integration test uses controlled IPv4/IPv6 localhost servers to verify ICMP, port detection, SSH/HTTP banners, DNS-SD follow-ups, UPnP description boundaries, and NetBIOS node status. The Linux container also checks interoperability with Samba’s actual name server. Regular tests don't send scan traffic. See [status and remaining work](docs/STATUS.md).

[Platform testing](docs/platform-testing.md) documents architecture assertions and how to execute both Linux release archives and the Intel Mac archive, including the CLI socket/terminal fixtures.

On macOS, Lantern also identifies its own selected interface addresses from the kernel's hardware model, resolving the code through AppleDB. The exact local source and any conflicting network claims remain visible in `--details` and JSON. See [local Mac inventory](docs/recognition.md#local-mac-hardware-inventory).

Discovered IPP/IPPS printer endpoints can now supply manufacturer/model details through Get-Printer-Attributes. Queue names stay separate from host identity, and TLS without certificate verification is labeled in the evidence. See [IPP printer attributes](docs/recognition.md#ipp-printer-attributes).

[Identification evaluation](docs/identification-evaluation.md) scores saved scans against independent device labels, separating reported model, retail model, family, type, ambiguity and misses. Explicit address mappings prevent dual-stack records from inflating coverage; synthetic examples are included.

Qualifying ONVIF services can supply manufacturer, model and firmware version through one unauthenticated GetDeviceInformation request per endpoint. Protected endpoints retain their discovery evidence. Serial and hardware-ID response fields are discarded. See [ONVIF device information](docs/recognition.md#onvif-device-information).
