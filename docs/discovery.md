# Discovery and reachability

Lantern keeps observed address mappings separate from active responses. An OS neighbor-cache entry is useful evidence but may be stale. TCP connection acceptance/refusal, a matching echo reply, a discovery advertisement, or a solicited ARP reply counts as a response. Proxy ARP, shared devices, and multiple IP addresses mean the number of reported addresses is not necessarily the number of physical devices. All network claims remain unauthenticated.

## Direct IPv4 ARP

Use `lantern scan --interface en0 --arp` to add direct local-link discovery. ARP runs alongside ICMP, TCP, and multicast discovery. It can reveal a local address whose firewall drops IP probes, and its fresh MAC mapping takes precedence over a conflicting cached mapping.

The default remains unprivileged scanning. Raw ARP requires BPF device access on macOS or `CAP_NET_RAW` on Linux. Lantern never escalates itself or changes device permissions. Permission failures become report warnings while other discovery continues. An explicit IPv6 target with `--arp` is rejected before probing.

The selected interface must be up, have an Ethernet MAC and an IPv4 prefix overlapping the target, and not be a point-to-point or loopback interface. Ambiguous interfaces require `--interface`. Only addresses in that local prefix are sent ARP requests; remote routed targets use the other scan methods. If an interface has several matching IPv4 prefixes, the most specific matching prefix is used. VLAN subinterfaces can be selected directly; raw tagged trunk frames are not decoded.

Requests use the interface's real IPv4/MAC source and ask for one target address at a time. Sending is paced in bursts of 32 with 10 ms between bursts (approximately 3,200 requests/second maximum over sustained traffic), with a 10 ms deadline per write. A write failure stops the remaining ARP sends and reports partial results. The response window after sending uses `--timeout`. Cancellation closes the raw descriptor and returns collected observations. Other protocols keep their own timeouts and worker limits.

Reception accepts Ethernet/IPv4 ARP replies addressed to the scanner's IP and MAC. The Ethernet source must match the ARP sender MAC; the sender must be an address actually requested by this sweep. Malformed, multicast-source, foreign-target, unsolicited, and duplicate replies are ignored. Capture is restricted to ARP and never enables promiscuous mode. On macOS only 64 bytes of each ARP frame are captured.

The Linux ARM64 packet socket path is runtime-tested against a container gateway with all other discovery methods disabled. macOS BPF parsing and builds are tested; live privileged exchange is still pending. Test commands and measurements are in [verification](verification.md).

## IPv6

Individual addresses and small ranges are probed directly. Large ranges, including normal /64 networks, use candidate discovery from scoped ICMPv6 all-nodes echo, mDNS/SSDP, the NDP cache, and local interface addresses. The candidate list is bounded by `--max-hosts`; the address space is never exhaustively enumerated. Direct NDP solicitation is not implemented yet. Link-local addresses retain the interface zone in structured reports.

## Protocol references

- [RFC 826](https://www.rfc-editor.org/rfc/rfc826) defines Ethernet/IPv4 ARP fields and request/reply behavior.
- [Linux packet socket manual](https://man7.org/linux/man-pages/man7/packet.7.html) describes AF_PACKET and its `CAP_NET_RAW` requirement.
- [Apple's BPF ABI header](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/bpf.h) defines Darwin capture record lengths and four-byte alignment. No Apple implementation code is incorporated.
