# Core events and live results

`scanner.Engine.Scan(ctx, options, emit)` calls `emit` synchronously and serially. Callbacks should return promptly: slow callbacks can delay probe workers. Pass `nil` when events are unnecessary. The returned `Report` is the authoritative aggregate; JSONL output also emits it as a final `report` record.

| Event type | Meaning | Progress units |
| --- | --- | --- |
| `device` | First observation of an address. Details can be sparse and cache evidence does not imply responsiveness. | None |
| `progress` | Work within `phase`: `discovery`, `ports`, or `enrichment`. Counts restart at phase boundaries. | Discovery/ports: TCP jobs; enrichment: processed devices |
| `device_update` | Normalized device data after its enrichment work, including available names, models, advertisements, verified ports, and banners. | Processed devices in the enrichment phase |
| `done` | All scan workers and update callbacks have finished. The report is about to be returned. | Unique addresses attempted / target addresses |

Every observed device receives an initial event and one update before `done`. Updates are emitted as individual devices finish; they do not wait for all devices' DNS/banner/description work. Completion order can vary across devices. Event consumers should replace a device record by its scoped IP, rather than count an update as a new device. Ignore unrecognized event types for forward compatibility.

TCP phases depend on the execution plan. Single-address and `AllHosts` scans use one `ports` phase that counts both requested ports and any additional liveness probes; ordinary subnet scans use `discovery` followed by `ports`. Empty phases emit no TCP progress event. Consumers must not require every phase or interpret the total job count as the number of requested open-port results. Enrichment and `done` still follow all discovery and TCP workers.

A processed device is not necessarily fully identified. Protocols may be disabled, unavailable, or unanswered; cancellation can leave fields missing. Updates after cancellation retain whatever was observed. `Report.Cancelled`, `Report.Error`, coverage, warnings, and response evidence determine how results should be interpreted. Validation errors can return before any event is emitted; an engine error after work has started can still accompany a partial report. When all TCP probes fail, the core returns that error and sets the report’s optional `error` string while retaining observations from other sources. `done` means workers finished, not that the scan succeeded.

Device payloads have independent ownership. Consumers may retain or mutate an event's `Device`, including names, ports, advertisements/properties, identity claims, and model candidates, without altering another event or the final report. `Device.Clone()` offers the same deep-copy behavior for app-owned records. Consumers remain responsible for synchronization between their own goroutines accessing the same retained object.

The watch dashboard accepts updates during the first scan, showing details as they become available and an identifying-progress phase. During later refreshes it keeps the previous completed report visible until the new report arrives, so partial observations are not mixed into comparison history. Plain JSON and CSV commands omit callbacks to avoid constructing unused event snapshots; JSONL includes the event stream.

```go
options := scanner.Defaults()
var err error
options.Target, options.Interface, err = scanner.AutoTarget4("")
if err != nil {
    return err
}
report, err := (scanner.Engine{}).Scan(ctx, options, func(event scanner.Event) {
    switch event.Type {
    case "device", "device_update":
        // This pointer is an owned snapshot. Hand it to an app queue or replace
        // the app's record keyed by event.Device.IP without making another copy.
        storeDevice(event.Device)
    }
})
```

The example's `storeDevice` must return promptly; queue sizing and backpressure are app responsibilities. Event callbacks are not an asynchronous transport, and the scanner does not start an unbounded goroutine or queue per event.

## CLI failures and partial results

JSON, JSONL, CSV, and plain scan output retain the aggregate when TCP scanning fails. The CLI exits with status 1 and explains the failure on stderr. JSON reports and snapshots carry the optional `error` field; CSV keeps its existing device columns, so consumers must check the exit status and stderr. Invalid options or target setup still return an error without publishing a report or replacing an existing snapshot.

A JSONL write failure cancels the scan’s own context immediately. The CLI ignores SIGPIPE for this stream so a closed stdout pipe returns a write error instead of terminating before cleanup. It stops writing events, joins the scanner, and still attempts an independent `--save`. No final report can be delivered through a broken stream; the saved snapshot carries `cancelled: true` when work was interrupted. Watch stops on the failure instead of beginning another scan. Scanner, output, and save errors remain available together.

For a normal Ctrl-C/SIGTERM interruption, JSONL still emits remaining updates, `done`, and the partial report when output remains writable. Existing cancellation exit behavior is unchanged. Interactive watch also saves reports marked with `error` before exiting and restoring the terminal. A save failure does not suppress printable results in plain/structured scan output.

Watch search includes all identity claim fields and values as well as the selected name/model/firmware and existing address/vendor/service fields. This makes ONVIF hardware descriptions, secondary model claims, and firmware-build strings discoverable without promoting them to the selected identity. Search text is built only for an active query, reused while the report remains unchanged, and replaced when a new report or device update arrives.
