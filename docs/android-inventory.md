# Owner-authorized Android inventory

`lantern android` reads four model-related properties through an existing local Android Debug Bridge (ADB) server. It requires an explicitly selected, already-authorized device transport. This complements network discovery when an Android device does not advertise its model over the LAN; it is not unauthenticated phone detection.

## Run it

With Android Platform Tools installed and the device already authorized for ADB, find its current `transport_id`:

```sh
adb devices -l
```

Use that number in Lantern; `42` here is only an example:

```sh
lantern android --transport-id 42
lantern android --transport-id 42 --json > android-inventory.json
```

Lantern connects to `127.0.0.1:5037` by default. `--server '[::1]:5037'` selects an IPv6 loopback server; another explicit loopback port is also supported. `--timeout` defaults to five seconds and must be positive and at most 30 seconds. Hostnames, remote server addresses, zones, mapped IPv6, zero transport IDs and positional targets are rejected. Selection does not inherit `ANDROID_SERIAL` or `ADB_SERVER_SOCKET` from the environment.

Lantern does not invoke the `adb` executable, start or stop a server, list devices, pair/connect a new device, enable debugging, or retry with a different transport. The server must already be running. `adb devices -l` is an owner-run setup command; its `transport_id` is the selector, not its serial-number column. Android's [ADB documentation](https://developer.android.com/tools/adb) describes device authorization and Platform Tools setup.

Transport IDs belong to one running ADB server. They can change on reconnect and can be reused after a server restart. They are neither durable device identities nor LAN addresses. Recheck the selection after connection changes. The returned server, transport ID and collection timestamp describe this observation only.

## What each field means

| Report property | Exact requested key | Interpretation |
| --- | --- | --- |
| `manufacturer` | `ro.product.manufacturer` | Reported product manufacturer |
| `model` | `ro.product.model` | Reported end-user model string |
| `device` | `ro.product.device` | Industrial-design identifier/codename |
| `build_fingerprint` | `ro.build.fingerprint` | Raw build-property value; software/build evidence |

The mappings are documented in [AOSP Android 14 Build.java](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/os/Build.java). The Android `Build.FINGERPRINT` API can derive a fallback when the raw property is absent; Lantern reports the requested raw property without constructing that fallback. A codename and a build fingerprint are not additional exact retail-model identifications.

Successful reports retain the four property namespaces and provide field claims with exact property keys and source references. Empty values and case-insensitive `unknown` values remain in the property observation where applicable, but do not create identity claims; their keys appear in `unavailable`. `complete: true` means the bounded four-property command and response completed successfully, not that all four values were available or independently verified.

ADB devices include phones, tablets, TVs, development boards and emulators. Lantern does not infer the device class from the presence of ADB. Custom software can alter the reported properties. No Android model-name catalog is bundled, and no catalog count or physical-device accuracy percentage is implied by this collector.

## Request and validation bounds

One TCP connection to the selected local server carries two smart-socket requests: select `host:transport-id:ID`, then request a raw shell-v2 stream for a constant command. That command runs `/system/bin/getprop` for each of the four allowlisted keys, joined with `&&` so a failed command cannot be hidden by a later success. No caller-provided text enters the remote shell. Full-property dumps, serial numbers, IMEI, Android ID, MAC addresses, accounts, packages and user files are not requested.

The client requires both smart-socket `OKAY` statuses, shell-v2 stdout/stderr/exit framing, one zero exit status and clean connection closure. It rejects nonempty stderr, duplicate/missing exit, trailing bytes, unknown channels, truncated frames and legacy unframed shell output. Modern shell-v2 support is required; unsupported devices fail without a fallback. See [AOSP smart-socket overview](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/android14-release/OVERVIEW.TXT), [service definitions](https://android.googlesource.com/platform/packages/modules/adb/+/7799b4ba18dd0fc0298ccac65014ca533dacbddd/SERVICES.TXT), and [shell protocol framing](https://android.googlesource.com/platform/system/core/+/refs/heads/android10-gsi/adb/shell_protocol.h).

One overall deadline covers connection, transport selection, shell execution, output and closure. Cancellation closes the socket. Limits are 128 shell frames, 8,200 bytes per frame/total stdout, four newline-terminated values and 2,048 bytes per value. CRLF line endings are accepted. Invalid UTF-8, replacement runes, controls, format characters and extra lines fail; ordinary surrounding spaces are trimmed. Failure messages from ADB are bounded and discarded because they can contain device serial numbers.

On collection failure, JSON contains observation metadata, `complete: false` and an `error` field, and the command exits nonzero. No property claims are committed from an incomplete or malformed command. This is one selected-transport observation, so values from a later retry cannot silently combine with an earlier device.

## Reusable core and integration boundary

```go
report, err := android.Read(ctx,
    netip.MustParseAddrPort("127.0.0.1:5037"),
    42, 5*time.Second)
```

The Go core has no ADB executable dependency. It communicates only with an existing local server. Ordinary scan/watch profiles do not query ADB, and this report is separate from a network snapshot. Associating it with a scanned device requires an explicit owner-supplied address binding; transport names and handles must not be used to infer that association. A shared inventory-to-snapshot adapter remains the next integration step for Android and SNMP.

Protocol and synthetic socket tests establish bounded collection behavior. A separate isolated Linux fixture also passes through an unmodified real ADB host server connected to a synthetic adbd, verifying transport selection and stream forwarding. It does not execute Android OS `getprop` or validate pairing. See [verification details](verification.md#owner-authorized-android-inventory). Physical phone/TV model coverage and comparison with Fing remain unmeasured. Owner-authorized inventory results must be evaluated separately from unauthenticated network discovery. The rc.7 release archives predate this command.
