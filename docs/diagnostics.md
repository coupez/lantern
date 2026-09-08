# Local diagnostics

Run `lantern doctor` when automatic network selection fails or a scan finds fewer devices than expected. Use `lantern doctor --interface en0` to check a particular interface, or `lantern doctor --json` for structured results.

Doctor inspects interface addresses, automatic IPv4/IPv6 target selection, ICMP socket access, multicast socket configuration, optional raw ARP/NDP access, and OS neighbor-table access. It opens and closes local sockets and reads routing/neighbor tables. It sends no discovery packets, reads no captured frames, changes no permissions, and contacts no cloud service.

| Status | Meaning |
| --- | --- |
| `available` | The named local operation succeeded. Socket access does not establish that packets will reach devices or replies will return. |
| `unavailable` | The local operation failed. The report includes the error and a suggested next step; other checks continue. |
| `not_checked` | The operation was not tested. Remote reachability always has this status because doctor sends no probes. Cancellation also leaves pending checks untested. |

A denied optional capability does not make doctor exit unsuccessfully. Invalid flags/interfaces, cancellation, and output errors return a nonzero exit status. After cancellation, JSON retains completed checks and sets `cancelled: true`.

The JSON report has `schema: 1`, platform/version information, offline database counts, selected-interface inventory, elapsed milliseconds, and named checks. The core exposes the same local checks through `scanner.Diagnose(ctx, interfaceName)`; CLI version/database fields are added by the command. An empty interface name uses the scanner's automatic target selection. IPv4 and IPv6 may choose different interfaces. Explicit selection filters the reported network inventory and returned IPv4/IPv6 neighbor mappings. OS tables are read with their interface columns intact, then filtered.

## Interpreting common results

- **Target selection is unavailable:** run `lantern interfaces`, then use `--interface` or an explicit scan IP/CIDR. VPNs, virtual adapters, and multiple local networks can make automatic selection ambiguous. Doctor reports the same selection rules used by scanning.
- **ICMP is unavailable:** TCP and multicast discovery can still work. Linux unprivileged ICMP sockets depend on the current user's group and the OS `ping_group_range` policy. A command sandbox can also deny sockets independently of the host's normal permissions.
- **Multicast is unavailable:** check that the selected interface is up, has a matching address, and supports multicast. Local-network permission or socket restrictions can block setup. Successful setup still does not establish multicast delivery through Wi-Fi isolation, VLAN boundaries, or firewalls.
- **ARP is unavailable:** direct ARP is optional and enabled with `--arp`. Linux requires `CAP_NET_RAW`; macOS requires access to a BPF device. A valid Ethernet interface and an overlapping IPv4 network are also required. Doctor never escalates privileges or changes those permissions. Other discovery methods can remain available.
- **NDP is unavailable:** `--ndp` needs a usable IPv6 Ethernet interface and the same raw access as ARP. Doctor checks the NDP descriptor separately; a missing IPv6 address can make NDP unavailable even when IPv4 ARP works.
- **Neighbor-table access is unavailable:** Linux uses the `ip` command; macOS uses `/usr/sbin/arp` and `/usr/sbin/ndp`. Readable cache entries can be stale and do not establish device responsiveness.

If local checks succeed but devices remain missing, inspect the scan's warnings and selected profile. Quick mode skips multicast and description reads by default; NetBIOS is enabled for deep IPv4 scans and can be requested explicitly with `--netbios`. `--no-icmp`, `--no-multicast`, and `--ports none` remove different discovery paths. Sleeping, isolated, filtered, or slow devices can remain undiscovered even when all local checks pass. See [discovery behavior](discovery.md) and [device recognition](recognition.md).
