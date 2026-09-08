# Fing package inspection — 2026-09-08

The requested Mac downloads were performed. Neither application was run or installed. Both disk images were mounted read-only, and files were inspected locally.

## Native Fing 4.0.5

- Official download landing page: https://www.fing.com/desktop/download-mac/
- Package: https://get.fing.com/fing-desktop-releases/mac-v4/Fing.dmg
- SHA-256: `01ad0f63c86c7f94711715aab917dd193c45b20d106f10b8f025e901f3e48eca`
- `Info.plist` reports version 4.0.5.
- 33 files in the app; approximately 59 MB uncompressed.
- Full file hashes and the embedded-stream inventory are in `research/fing-inventory.json`.

`liboverlook.dylib` contains symbols and configuration strings for `EthernetOuis`, including the expected filename `ethernet-ouis.properties` and a failure message for a missing file. No such file appears anywhere in the mounted app.

`Contents/Resources/service/template/conf/ip-services.properties` is present. Its header describes 1,027 TCP ports and 1,025 UDP ports, with 15 quick-scan ports per protocol, and attributes copyright to Overlook. The file was extracted for inspection but is not incorporated into Lantern. IANA supplies Lantern's independent service names.

The binaries were scanned for valid embedded zlib streams. Nine streams were extracted from the UI executable; none yielded a recognizable text MAC registry. No valid large zlib stream was extracted from `liboverlook.dylib` or `fingagent.bin`. This does not rule out other compiled or compressed representations.

## Legacy Fing 3.10.1

- Official package linked by the download page: https://get.fing.com/fing-desktop-releases/mac/Fing-3.10.1.dmg
- SHA-256: `f0ccdf3b1a57117dc08e4e6970aded3f453eae75d1e6d8b28aa7a590381eeacf`
- Approximately 149 MB downloaded, 527 MB mounted.
- Electron `app.asar` contains 48,329 entries. Its header was parsed, every entry inventoried, and first-party JS/JSON resources extracted locally.
- No first-party `.csv`, `.db`, `.sqlite`, OUI-named, or manufacturer-named data file was found.
- The UI bundle has a `fetchRecognition` method that requests `/getDeviceDetail/` plus a device MAC through its local-agent URL helper. That is evidence of an agent-mediated lookup, not proof that the full recognition database is cloud-only.
- The service template again contains the port map, but no `ethernet-ouis.properties`.

## What this establishes

The downloaded packages do not expose the requested standalone MAC mapping file. We have not recovered Fing's complete proprietary recognition catalog and do not claim to have done so. Additional compiled data or data downloaded at runtime remains possible. No credentials, cloud recognition endpoints, or paid services were used.

Local research artifacts are under `research/downloads/` and `research/extracted/`, excluded by `.gitignore`. Lantern's code and generated datasets have no dependency on those proprietary resources.

## Independent recognition sources

| Source | Used for | Status |
| --- | --- | --- |
| IEEE MA-L, MA-M, MA-S, IAB | MAC assignment → registered organization | 58,421 embedded assignments; longest-prefix lookup |
| IANA service registry | TCP port → registered service name | 5,889 embedded names |
| mDNS / DNS-SD | Hostname, advertised service, model/TXT properties | Bounded local discovery implemented |
| SSDP | Advertised service, server, USN, description URL | Discovery implemented; description URLs are not fetched |
| Reverse DNS | PTR names | Bounded optional lookup |
| SSH / HTTP / FTP / SMTP responses | Device-reported software banners | Bounded explicit/deep inspection |
| Wireshark manuf / Nmap fingerprints / community catalogs | Potential extra mappings and fingerprints | Not imported; provenance and applicable source terms need evaluation |

MAC assignment alone cannot identify every device model or undo a randomized MAC. Lantern keeps protocol evidence distinct from inferred device types.
