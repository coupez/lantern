# Offline DHCP observations

Lantern’s `observe` command reads an existing PCAP or PCAPNG file. It does not open a capture interface, send DHCP packets, renew leases, resolve addresses, merge packets into clients, or classify an operating system or model. The result is timestamped protocol evidence that can later be reviewed or matched against a separately licensed fingerprint catalog.

## What the importer preserves

`pkg/observe` emits one observation per decodable DHCP datagram. Each row retains the packet number, timestamp, PCAP section/interface/link type, source and destination IP/UDP ports, observed IPv4 TTL / IPv6 hop limit, Ethernet source address when present, up to two VLAN IDs, and a truncation flag. The parsed `dhcp.Message` retains:

- DHCPv4 or DHCPv6 version, message type, transaction ID, addresses, client hardware address where present, and ordered raw options;
- DHCPv4 hints for hostname (option 12), vendor class (60), requested options in the option-55 order, and client ID (61);
- DHCPv6 client ID, hostname and requested-option hints where unambiguous, enterprise ID from vendor-class option 16, and nested relay-forward/relay-reply information. Vendor-class tuples remain in the raw option bytes; no DHCPv6 vendor-class display string is inferred.

These are observations of bytes seen on the capture interface. A hostname, vendor class, client ID, requested-option order, relay address, or hardware address is a device or protocol claim and is not authenticated. The importer does not turn a requested-option list into an OS, product, manufacturer, or model. Packet timestamps and repeated transactions remain separate rows; the summary counts capture records, not unique devices.

Malformed, unsupported, truncated, or non-DHCP packets are counted in the summary. `incomplete` means a malformed, unsupported or truncated packet occurred, or the reader stopped with an error; ordinary non-DHCP packets do not set it. This flag does not mean that a device or DHCP exchange was absent. An option-55 vector alone is especially weak evidence: multiple operating systems and device families can share it, and privacy behavior can deliberately change DHCP identifiers and option lists.

The decoder accepts classic PCAP and PCAPNG, Ethernet, raw IP, BSD null/loopback, Linux cooked, and up to two VLAN tags. It does not reassemble IP fragments, accept IPv6 jumbograms or ESP, or treat transport checksums as authentication. DHCPv4 is recognized on UDP 68↔67 (including server-to-server 67↔67); DHCPv6 is recognized on UDP 546↔547 (including relay/server 547↔547). The capture reader enforces a 128 MiB input bound and a one-million-packet bound; the command also enforces a regular-file input, a 128 MiB file size, and a configurable observation limit of 1–100,000. Retained observation payload for aggregate `--json` output is capped at 16 MiB, so `--jsonl` is the safer format for a larger capture.

## Exact macOS capture and import

On the Mac connected to the LAN, capture at most 1,000 matching packets on `en1`:

```sh
sudo tcpdump -i en1 -nn -s 0 -c 1000 \
  -w "$HOME/Desktop/lantern-dhcp-en1.pcap" \
  'udp and (port 67 or port 68 or port 546 or port 547)'
```

`-i` selects the interface, `-s 0` keeps the full packet rather than a short snap length, `-c 1000` makes the capture bounded, and `-w` writes a packet file instead of printing payloads. This simple BPF filter selects ordinary untagged UDP traffic on the DHCP ports. It can miss VLAN-tagged frames and IPv6 extension-header traffic. For a tagged trunk or such IPv6 traffic, use a capture filter validated for that link type (or import an existing bounded capture that includes it); decoder support does not expand what tcpdump recorded. Stop earlier with Ctrl-C if enough renewals or exchanges have been captured. No reconnect or forced DHCP renewal is required; the command passively records packets that occur naturally.

With the source build in this workspace, import it without network access:

```sh
cd /Users/lucas/Projects/lantern
./bin/lantern observe --read "$HOME/Desktop/lantern-dhcp-en1.pcap" \
  --jsonl --limit 1000 > "$HOME/Desktop/lantern-dhcp-en1.jsonl"
```

For a human-readable summary, omit `--jsonl` and redirect only if the terminal output is desired. `--json` retains all observations in one bounded object; `--jsonl` streams each observation and ends with a `complete` summary event. The input is read-only from Lantern’s perspective.

The command follows tcpdump’s documented `-i`, `-s`, `-c`, `-w`, and BPF expression behavior ([tcpdump manual](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in), [pcap filter syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)). A capture made on a different interface, a bridged Ethernet adapter, or a gateway can be imported the same way; the file’s link type is retained in each observation.

## Visibility limits

A regular laptop capture on `en1` sees packets delivered to that interface: its own DHCP traffic, broadcast/multicast traffic that the access point or switch forwards to it, and traffic visible through a mirror, tap, bridge, or gateway. It does not automatically see every switched unicast exchange between other wired ports. Wi-Fi capture while associated as an ordinary client likewise does not make the laptop a monitor for every other station’s unicast traffic; the AP normally forwards each station’s traffic within its wireless distribution system. A gateway/AP capture point, switch mirror, or authorized relay-side capture is needed for broad client coverage.

DHCP is intermittent. A client that already has a lease may not send a packet during a short capture, and a sleeping or offline device contributes no observation. Missing DHCP rows therefore say only that the selected capture point did not record a matching packet in that interval. Clients behind another VLAN, relay, NAT boundary, VPN, or isolated guest SSID may be invisible or appear only through relay metadata. Capturing at the gateway or relay improves coverage, but it still records only traffic the capture point can receive and does not reveal clients on networks outside that point’s scope.

The protocol references define what can be expected on the wire: [DHCPv4 RFC 2131](https://www.rfc-editor.org/rfc/rfc2131), [DHCPv6 RFC 9915](https://www.rfc-editor.org/rfc/rfc9915.html), and [DHCP privacy considerations RFC 7844](https://www.rfc-editor.org/rfc/rfc7844). RFC 7844 documents that DHCP options and request lists can expose implementation or device information and that privacy profiles can reduce or alter those signals. Lantern should preserve the raw observation and provenance while treating any catalog result as an ambiguous interpretation.

## Data representation and error handling

JSON uses schema version 1. Raw option `data` and client-ID bytes are base64, preserving opaque values without terminal control sequences. DHCPv4 option order excludes Pad/End markers; overloaded `file` and `sname` options retain their area and concatenation order. Duplicate optional DHCPv6 hints are omitted when ambiguous while their raw options remain. The observed hop limit is never treated as a guessed initial TTL. Simple PCAPNG Packet Blocks have no timestamp and emit the zero time; other times are UTC, with sub-nanosecond precision truncated. Interface IDs are local to each numbered PCAPNG section. Interface names, drop counters, comments and other capture metadata are not imported, so `incomplete: false` only describes importer processing, not capture completeness.

A capture framing/read error, output limit or cancellation returns a nonzero exit status after any previously collected JSON/JSONL evidence and final summary. Structurally malformed or unsupported individual packets are counted and skipped; the command can exit successfully with `incomplete: true`, so consumers should examine that field. A broken output stream returns immediately. Human output is a concise view; use JSON/JSONL for all raw options and relay fields.

The limits also include 1 MiB per packet/block, 1,024 interfaces per section, 65,535 DHCP payload bytes, 1,024 DHCP options across overload/relay levels and four nested DHCPv6 relays. Unknown PCAPNG block types are skipped. IP fragments are not reassembled. The UDP length bounds the DHCP payload; trailing link/IP bytes are not parsed as DHCP options. No checksums are verified because capture offload can omit them; this is an evidence importer rather than a packet-validity or authenticity verifier.

The catalog review is recorded in [DHCP catalog research](../research/results/dhcp-catalog-review.md). No current Fingerbank database or Satori rows are embedded, and this command never submits evidence to a cloud service.
