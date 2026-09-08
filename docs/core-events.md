# Core events and live results

`scanner.Engine.Scan(ctx, options, emit)` calls `emit` synchronously and serially. Callbacks should return promptly: slow callbacks can delay probe workers. Pass `nil` when events are unnecessary. The returned `Report` is the authoritative aggregate; JSONL output also emits it as a final `report` record.

| Event type | Meaning | Progress units |
| --- | --- | --- |
| `device` | First observation of an address. Details can be sparse and cache evidence does not imply responsiveness. | None |
| `progress` | Work within `phase`: `discovery`, `ports`, or `enrichment`. Counts restart at phase boundaries. | Discovery/ports: TCP jobs; enrichment: processed devices |
| `device_update` | Normalized device data after its enrichment work, including available names, models, advertisements, verified ports, and banners. | Processed devices in the enrichment phase |
| `done` | All scan workers and update callbacks have finished. The report is about to be returned. | Unique addresses attempted / target addresses |

Every observed device receives an initial event and one update before `done`. Updates are emitted as individual devices finish; they do not wait for all devices' DNS/banner/description work. Completion order can vary across devices. Event consumers should replace a device record by its scoped IP, rather than count an update as a new device. Ignore unrecognized event types for forward compatibility.

A processed device is not necessarily fully identified. Protocols may be disabled, unavailable, or unanswered; cancellation can leave fields missing. Updates after cancellation retain whatever was observed. `Report.Cancelled`, coverage, warnings, and response evidence determine how results should be interpreted. Validation errors can return before any event is emitted; an engine error after work has started can still accompany a partial report.

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
