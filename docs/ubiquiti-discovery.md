# Ubiquiti discovery

`lantern scan --ubiquiti --details` adds an opt-in IPv4 discovery pass. It runs concurrently with the other discovery methods and can find a responding device even when TCP/ICMP do not answer. It is disabled by default, including in the deep profile. Use a literal IP to limit the probe to one device:

```sh
lantern scan 192.0.2.8 --ubiquiti --ports none --no-icmp --no-multicast --details
```

The collector sends at most one v1 request (`01 00 00 00`) and one v2 request (`02 08 00 00`) to UDP/10001 on each enumerated target. It does not broadcast, expand the scan range, or follow payload addresses. IPv6 and `--max-hosts` above 4096 are rejected for this option. A selected interface supplies the local IPv4 source address; otherwise the OS chooses the route/source. Replies must originate from an attempted target's IP and UDP/10001. The protocol has no transaction nonce or cryptographic authentication, so these are attributed network observations, not authenticated identities.

Ubiquiti documents UDP/10001 as the device-discovery port used during adoption in its [Required Ports Reference](https://help.ui.com/hc/en-us/articles/218506997-Required-Ports-Reference). The detailed field layout is supported by a maintained implementation, rather than an official wire specification: [pinned Nmap 7.95 protocol parser](https://sources.debian.org/src/nmap/7.95%2Bdfsg-3/scripts/ubiquiti-discovery.nse/). Lantern independently implements the protocol facts and does not bundle Nmap code or its recognition database.

## What becomes identity evidence

| TLV | Retained meaning |
| --- | --- |
| `03` | firmware/build string, as a separate `firmware_build` claim |
| `0b` | reported hostname, as a name claim without resolving it |
| `0c` | platform string, as a separate `platform` claim |
| `14`, `15` | dedicated reported model fields, with competing values retained |
| `16` | firmware version |

Platform never substitutes for a missing model. A literal `unknown` model stays in raw advertisements without becoming the selected identity. `Ubiquiti` is a protocol-derived manufacturer claim, selected only when linked to the selected model's source. Versions, command values and exact TLV keys remain in advertisements; field claims link to the protocol reference. Reported models are not retail-catalog matches and do not establish an operating system or device type.

The collector discards payload interface addresses, MACs, usernames, salts/challenges, ESSID and configuration state. It never changes a device's MAC from these packets and does not add a TCP port. Successful protocol replies add `ubiquiti` responsiveness evidence. An incomplete pass preserves received claims and adds a warning/method marker; dependent absence/identity comparisons are suppressed while unrelated TCP changes remain comparable.

## Bounds and limits

Datagrams are limited to 8192 bytes including the four-byte header, with exact declared length and at most 128 fully framed TLVs. At most six textual field tags are retained; repeated retained tags reject the packet. Outer ASCII space/tab/CR/LF is trimmed, then retained nonempty values are limited to 1024 bytes and must be valid UTF-8 without controls, format characters or replacement runes. Display identity fields use the scanner's stricter 256-character limit; longer raw values remain in advertisements. Distinct model tags and conflicting replies are preserved rather than overwritten.

Sending is paced after each 32 addresses and has a two-second ceiling. One `--timeout` response window follows the final send, rather than a separate timeout per device. The reader accepts at most 8192 packets, 4096 distinct observations and four observations per IP; reaching a limit reports an incomplete pass. Cancellation closes the socket. There are no adoption, configuration, login or controller operations and no retries.

Discovery may be disabled or filtered, and protocol support varies by product/firmware. The checks use controlled protocol fixtures; physical-device coverage and vendor interoperability remain unmeasured. No catalog rows are added. Existing rc.7 archives predate this command.
