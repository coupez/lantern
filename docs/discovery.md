# Discovery and reachability

Lantern keeps observed address mappings separate from active responses. An OS neighbor-cache entry is useful evidence but may be stale. TCP connection acceptance/refusal, a matching echo reply, a discovery advertisement, or a solicited ARP/NDP reply counts as a response. Proxy ARP/NDP, shared devices, and multiple IP addresses mean the number of reported addresses is not necessarily the number of physical devices. All network claims remain unauthenticated.

## Interface selection

An automatic IPv4 CLI scan retains both the selected subnet and its interface, including when a default-route adapter shares a subnet with a virtual adapter. Reports and saved snapshots record that interface. Core callers can use `AutoTarget4(interfaceName)` to obtain the prefix and interface together, then pass both in `Options`; `AutoTarget` remains available for callers needing only the prefix.

`--interface` selects the link used by local multicast and ARP/NDP discovery, filters OS neighbor mappings and local-address evidence, and scopes link-local IPv6 probes. Unknown interface names fail before scanning for both address families. Ordinary TCP connects still follow OS routing; the option does not bind all TCP sockets to a device or bypass VPN routing.

IPv4/IPv6 neighbor rows from another interface are excluded when an interface is selected, even if the same IP exists on both links. A row with no interface provenance is excluded from a scoped lookup. On Linux the full table is read before filtering because `ip neigh show dev NAME` removes the interface column from its output. A custom `Engine.NeighborSource` must provide observations already appropriate for the requested interface; its IP-to-MAC map has no separate interface field.

## TCP probes and service banners

The core deduplicates requested TCP ports without modifying the caller's slice. Each address/port pair is scheduled once across initial discovery and the remaining-port phase. Open-port observations therefore append directly without repeatedly searching a growing per-device list; results are sorted once after enrichment. Port zero is rejected before network work. Host/port jobs are produced incrementally, including full `1-65535` scans; the engine does not allocate the complete host-by-port product. `--concurrency` limits simultaneous TCP probes. See [performance measurements](performance.md) for the full-port aggregation benchmark and real loopback fixture.

With banners enabled, open ports labeled HTTP, SSH, FTP, or SMTP receive a separate connection. HTTP sends a HEAD request; the other protocols read a greeting. Up to four banner exchanges run per device, with a shared scan limit of `min(32, --concurrency)`. Waiting for a slot does not consume a port's response budget: every eligible port is attempted unless the scan is cancelled. Each exchange shares one `--timeout` deadline across connection setup, writes, and reads, bounded by the caller's context deadline. Cancellation closes active connections and stops queued work. DNS and device descriptions retain their own enrichment limits.

Banner parsing assembles fragmented TCP lines and bounds each response to 8 KiB, each line to 2 KiB, and HTTP inspection to 64 lines including the status line. HTTP uses the first Server header, falling back to the status line; body text is never interpreted as a header. Oversized or interrupted lines are discarded. Terminal and directional controls are removed from returned text. These limits intentionally keep banner collection lightweight; a missing banner does not mean an open service is unavailable.

## ICMP scheduling and counters

Unicast echo uses a random per-scan nonce and per-target sequence numbers. Replies must match the peer address (including IPv6 zone), nonce, sequence, type, and code. Duplicate replies do not create extra observations or inflate responder counts. When every target has replied, the echo phase finishes immediately. If any target remains unanswered, the configured response window after sending still applies. IPv6 all-nodes candidate discovery has an unknown responder set and keeps its full response window.

Each initial send has a 2 ms write deadline. Timeout, `EAGAIN`, and `ENOBUFS` send failures receive at most one retry after the initial pass. Retries pause for 2 ms between writes and share a deadline of `min(--timeout, 100 ms)`; permanent permission/address errors are not retried. Successfully sent but unanswered probes are not resent by this mechanism. The retry budget bounds additional recovery work; it cannot guarantee complete coverage under persistent queue pressure. Read errors and unsupported deadlines are reported instead of silently being treated as silence. Cancellation closes the socket and retains partial results.

The report's optional `icmp` object describes unicast echo:

| Counter | Meaning |
| --- | --- |
| `attempted` | Target addresses whose initial send was attempted |
| `sent` | Target addresses with a successful write, including recovered retries |
| `retries` | Additional send attempts after local queue errors |
| `recovered` | Failed initial sends whose retry succeeded |
| `failed` | Attempted addresses still lacking a successful write |
| `responders` | Unique target addresses with a matching echo reply |
| `retry_budget_exhausted` | Recovery deadline prevented completing the retry queue |

A successful write means the kernel accepted the datagram, not that the host received or answered it. `sent + failed == attempted` for the engine's unique target list. RTT is measured from the target's first echo attempt, so recovered sends can include queue/backoff time. Report-level `probed` remains the count of unique addresses attempted by any probe type. Disabled ICMP omits the counters; an unavailable ICMP socket reports zero counters and a warning.

## Direct IPv4 ARP

Use `lantern scan --interface en0 --arp` to add direct local-link discovery. ARP runs alongside ICMP, TCP, and multicast discovery. It can reveal a local address whose firewall drops IP probes, and its fresh MAC mapping takes precedence over a conflicting cached mapping.

The default remains unprivileged scanning. Raw ARP requires BPF device access on macOS or `CAP_NET_RAW` on Linux. Lantern never escalates itself or changes device permissions. Permission failures become report warnings while other discovery continues. An explicit IPv6 target with `--arp` is rejected before probing.

The selected interface must be up, have an Ethernet MAC and an IPv4 prefix overlapping the target, and not be a point-to-point or loopback interface. Ambiguous interfaces require `--interface`. Only addresses in that local prefix are sent ARP requests; remote routed targets use the other scan methods. If an interface has several matching IPv4 prefixes, the most specific matching prefix is used. VLAN subinterfaces can be selected directly; raw tagged trunk frames are not decoded.

Requests use the interface's real IPv4/MAC source and ask for one target address at a time. Sending is paced in bursts of 32 with 10 ms between bursts (approximately 3,200 requests/second maximum over sustained traffic), with a 10 ms deadline per write. A write failure stops the remaining ARP sends and reports partial results. The response window after sending uses `--timeout`. Cancellation closes the raw descriptor and returns collected observations. Other protocols keep their own timeouts and worker limits.

Reception accepts Ethernet/IPv4 ARP replies addressed to the scanner's IP and MAC. The Ethernet source must match the ARP sender MAC; the sender must be an address actually requested by this sweep. Malformed, multicast-source, foreign-target, unsolicited, and duplicate replies are ignored. Capture is restricted to ARP and never enables promiscuous mode. On macOS only 64 bytes of each ARP frame are captured.

The Linux ARM64 packet socket path is runtime-tested against a container gateway with all other discovery methods disabled. macOS BPF parsing and builds are tested; live privileged exchange is still pending. Test commands and measurements are in [verification](verification.md).

## NetBIOS node status

`--netbios` sends RFC 1002 wildcard node-status requests to UDP 137 on the enumerated IPv4 target addresses. Deep IPv4 and `inspect` enable it by default; `--netbios=false` overrides that default. Standard and quick profiles leave it disabled unless requested. An explicit IPv6 target with `--netbios` is rejected before probing; deep IPv6 scans simply omit this pass.

One ephemeral UDP socket handles the entire pass alongside the existing discovery methods. Requests use independent random transaction IDs, with 32 requests per burst and a 10 ms pause between bursts. Writes have a 2 ms deadline; a write failure stops the remaining requests and produces a warning. Unanswered probes are not retransmitted. The full `--timeout` response window starts after the final write; fully answered target sets finish immediately. Cancellation closes the socket and keeps collected responses. Attempted addresses contribute to report-level `probed`, including a failed final write.

A response must match a successfully sent target address, transaction ID, and UDP source port. It must be an authoritative, successful, untruncated node-status answer with the wildcard owner, correct type/class, one complete name table, and its full 46-byte statistics tail. Wrong, unsolicited, duplicate, compressed-owner, truncated, or malformed responses are ignored. Packets are bounded to 8 KiB and names to the protocol's 255-entry table limit. Broadcast enumeration, named scopes, and TCP fallback are not implemented.

Active unique `<00>` and `<20>` registrations provide computer-name claims. Group `<00>` entries are retained as workgroup advertisements. Inactive, conflicted, or deregistering names do not become computer identity claims. Every name's original 16 bytes and flags are retained. Because the remote OEM code page is unknown, non-ASCII/control bytes are escaped for display instead of guessing a Unicode conversion. A reported unit ID stays in `reported_unit_id`; it never becomes the device's observed MAC or determines its vendor. Samba/Windows compatibility does not establish the operating system of a responder.

## Direct IPv6 NDP

`--ndp` runs neighbor solicitation alongside the TCP/ICMP discovery pass on an IPv6 Ethernet interface. Finite ranges use their enumerated addresses; large ranges use the bounded IPv6 candidate list described below. An IPv4 target with `--ndp` is rejected before probing. Raw access is optional and uses the same BPF/macOS or `CAP_NET_RAW`/Linux requirements as ARP; failures become warnings. `doctor` opens and closes the actual NDP resource without reading or sending frames.

Requests use a real address and MAC from the selected interface. The scanner chooses a source in the target's configured prefix where possible, otherwise an eligible link-local source. It skips its own addresses, foreign zones, multicast/unspecified targets, and global addresses outside all configured interface prefixes. Ambiguous automatic interface selection requires `--interface`. These prefix checks limit local solicitation; they do not infer routers or reconstruct advertised on-link routing policy.

Each unique eligible target receives one request, in bursts of 32 separated by 10 ms, with a 10 ms write deadline. The receive window uses `--timeout` after sending. It ends early if every requested address has replied; an initial write failure does not wait out the receive timeout. Cancellation closes the descriptor and joins the reader. Partial observations survive send/read failures. No neighbor-cache entries, routes, or interface settings are explicitly changed by Lantern; the operating system can update its own cache from ordinary protocol traffic.

Solicitations carry a source link-layer option and use the target's solicited-node multicast destination. Replies must have hop limit 255, a valid ICMPv6 checksum, code zero, and the solicited flag. The decoder requires a unicast reply to the request's source address and local Ethernet destination, plus a target MAC matching the Ethernet sender. Only actually requested targets are retained; unsolicited and duplicate observations are ignored. These checks follow the relevant [RFC 4861 message formats and validation rules](https://www.rfc-editor.org/rfc/rfc4861). Fragmented NDP is rejected, including atomic fragments, as required by [RFC 6980](https://www.rfc-editor.org/rfc/rfc6980).

Capture is limited to IPv6 frames and 2,048 bytes per frame, without enabling promiscuous mode. Up to eight hop-by-hop/destination extension headers are decoded. Routing/authentication headers and raw tagged trunks are excluded; select VLAN subinterfaces directly. NDP claims remain unauthenticated and may come from a proxy. The `ndp` evidence denotes a fresh solicited mapping, not a unique physical-device identity. That mapping takes precedence over stale cached MACs and counts as responsive even with no TCP ports open. `NDPResult` and optional `Engine.NDPSource` expose the same observations to core integrations; injected link-local addresses must carry the selected zone.

## IPv6

Individual addresses and small ranges are probed directly. Large ranges, including normal /64 networks, use candidate discovery from scoped ICMPv6 all-nodes echo, mDNS/SSDP/WS-Discovery, the NDP cache, and local interface addresses. The candidate list is bounded by `--max-hosts`; the address space is never exhaustively enumerated. `--ndp` optionally solicits these bounded candidates after discovery; it does not expand a /64 into an address sweep. Link-local addresses retain the interface zone in structured reports.

## Protocol references

- [RFC 1002](https://www.rfc-editor.org/rfc/rfc1002.html), sections 4.2.17–4.2.18, specifies node-status request/response fields.
- [Microsoft NetBIOS suffix definitions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b) distinguishes computer and workgroup registrations.

- [RFC 826](https://www.rfc-editor.org/rfc/rfc826) defines Ethernet/IPv4 ARP fields and request/reply behavior.
- [Linux packet socket manual](https://man7.org/linux/man-pages/man7/packet.7.html) describes AF_PACKET and its `CAP_NET_RAW` requirement.
- [Apple's BPF ABI header](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.h) defines Darwin capture record lengths and four-byte alignment. No Apple implementation code is incorporated.

## WS-Discovery

Standard/deep multicast discovery includes WS-Discovery over IPv4 and IPv6, in parallel with mDNS and SSDP. `--no-multicast` disables all three; quick mode skips them by default. The pass uses the selected interface and the existing multicast response window (at least one second).

Lantern sends untyped SOAP 1.2 Probes for the 2005/04 and 2009/01 discovery namespaces to UDP 3702 (`239.255.255.250` or scoped `ff02::c`), with a multicast hop limit of one. Each version gets a fresh random UUID. Two retransmissions per version retain their message IDs, with a randomized 50–250 ms initial delay followed by doubled delay, while replies are received concurrently. The original deadline, cancellation, and 512-datagram limit still end the pass; UDP writes have a 10 ms deadline.

Only ProbeMatches with the matching action, namespace, and `RelatesTo` request ID are retained. Replies are attributed to the in-target UDP sender and interface zone. Identical endpoint/message-ID replies from that sender are deduplicated. Discovery-proxy types are excluded; managed discovery, Hello/Bye listening, Resolve, HTTP metadata exchange, and control operations are not implemented. A correlated response is responsive evidence, not an authenticated identity.

Parsing caps datagrams at 65,507 bytes, XML depth at 16, elements at 512, attributes/in-scope namespaces at 64, text per element at 8 KiB, matches at 32, and list fields at 64 values. Duplicate recognized fields, nested value elements, invalid correlation, and malformed XML are discarded. The original sender remains the only discovered address: advertised XAddrs never add targets or ports and are never fetched. ONVIF scope interpretation is described in [device recognition](recognition.md). Unexpected socket/send failures and exhausted packet budgets preserve earlier replies and mark multicast discovery incomplete.

Protocol references: [WS-Discovery 1.1](https://docs.oasis-open.org/ws-dd/discovery/1.1/os/wsdd-discovery-1.1-spec-os.html) and [SOAP-over-UDP 1.1](https://docs.oasis-open.org/ws-dd/soapoverudp/1.1/os/wsdd-soapoverudp-1.1-spec-os.html). Controlled socket fixtures cover both versions and address families; physical Windows/printer/camera interoperability remains pending.
