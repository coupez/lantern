# Device recognition

Lantern combines independent MAC assignment records with device-reported protocol data. Its core keeps those different kinds of evidence separate; a randomized MAC can still accompany a useful model advertisement.

## Data paths

| Input | Extracted information | Basis |
| --- | --- | --- |
| IEEE MA-L / MA-M / MA-S / IAB | Registered MAC organization | Registry assignment; not the retail brand |
| Bonjour printing `_ipp`, `_ipps`, `_printer`, `_pdl-datastream` | `usb_MFG`, `usb_MDL`, `ty`, `product` | Advertised manufacturer, model, or display description |
| `_airplay._tcp`, `_device-info._tcp` | `model` | Advertised model identifier; no invented marketing-name conversion |
| `_googlecast._tcp` | `md`, `fn` | Advertised model and friendly name |
| Pinned PyChromecast catalog | 40 exact Cast model → manufacturer mappings | Catalog-derived, explicitly labeled |
| SSDP → UPnP description | `friendlyName`, `manufacturer`, `modelName`, `modelNumber`, `deviceType`, `UDN` | Device-reported XML; embedded devices stay distinct |

The `identity` object offers selected name/manufacturer/model fields, plus all recognized claims and their provenance. Explicit standardized fields precede printer display descriptions; catalog-derived manufacturer claims rank below device-reported manufacturer fields. Ties are resolved deterministically by source/key/value, not packet arrival order. Conflicting claims remain visible. A claim is not an authenticated hardware identity.

The CLI shows identity fields in `inspect` / `--details`; JSON and saved snapshots retain claims and raw advertisements. CSV adds reported-name, manufacturer, and model columns.

## Discovery behavior and limits

mDNS asks for common services plus the DNS-SD service-type enumeration record. PTR records lead to missing SRV/TXT queries, and SRV targets lead to missing A or AAAA queries for the scan’s address family. Names and TXT records may arrive in separate packets. TXT keys are case-insensitive and the first occurrence of a duplicate key wins. Human-readable instance spelling is retained. Follow-ups stay in `.local.` and consume a fixed 128-query budget; the original socket deadline never extends. Advertised ports are not reported as verified open TCP ports.

UPnP description requests only accept HTTP URLs with a literal IP matching the SSDP responder. The transport pins that address and disables proxies and redirects. Four unique URLs share one per-device timeout. Response headers, body size (256 KiB), XML depth (32), device count (64), and field lengths are bounded. The USN's device UUID is matched to the description's UDN before attaching a model, so an embedded device does not silently inherit the root device's identity. Unknown, malformed, inaccessible, or unmatched descriptions leave the original SSDP advertisement intact.

Quick mode skips multicast and descriptions by default. Explicit boolean flags override profile defaults, including `--no-multicast=false` and `--banners=false`.

## Sources and provenance

- [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763), particularly service enumeration, instance resolution, and TXT rules.
- [Apple Bonjour Printing 1.2.1](https://developer.apple.com/bonjour/printing-specification/bonjourprinting-1.2.1.pdf), sections 9.2.6–9.2.11, for printing field semantics.
- [UPnP Device Architecture 2.0](https://upnp.org/specs/arch/UPnP-arch-DeviceArchitecture-v2.0-20140901.pdf) for discovery/description structure and embedded-device identity.
- [PyChromecast discovery](https://github.com/home-assistant-libs/pychromecast/blob/8f7f3bfaa3142614b04f04e885b43e7810872adb/pychromecast/discovery.py) for Cast `md` and `fn` semantics.
- [PyChromecast model table](https://github.com/home-assistant-libs/pychromecast/blob/8f7f3bfaa3142614b04f04e885b43e7810872adb/pychromecast/const.py), imported as literal data without executing upstream code. Its MIT license is in `THIRD_PARTY_LICENSES`; the embedded JSON records commit, URL, content hash, and retrieval date. `scripts/build-cast-models.py` rebuilds it from the locally downloaded pinned source.
- [pyatv AirPlay device-info parser](https://github.com/postlund/pyatv/blob/master/pyatv/protocols/airplay/__init__.py) for the advertised `model` field. No pyatv source or catalog is incorporated.

These mappings do not cover every model. Proprietary cloud recognition, direct ARP/NDP, additional discovery protocols, and broader real-device verification remain separate work.
