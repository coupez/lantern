# Original-goal audit — 2026-09-09

This is a historical pre-publication audit. Publication was subsequently completed; see [current status](STATUS.md) and the [expanded identification roadmap](device-identification-roadmap.md).

The goal remains a modern, simple, fast open-source network-scanner CLI with a reusable core and broad device recognition, including inspection of the Fing Mac application. The persistent service and graphical application remain out of scope. This audit does not declare the broad goal complete.

The runtime audited here is `88fa7ce` (direct-target TCP overlap). Prepared rc.6 is based on `4373c5e` and predates that optimization; its four archived executables retain their separate verification record. Later source changes must not be represented as part of those archives.

| Requirement | Authoritative evidence checked | Conclusion and remaining gap |
| --- | --- | --- |
| Runnable modern CLI | Current `lantern demo`; macOS/Linux CLI logs for interactive watch, search, inspector, resizing, cancellation and terminal restoration; structured-output fixtures | Implemented and exercised. Broader terminal-emulator/accessibility and user visual review remain incomplete. |
| Simple everyday use | Default-route selection, quick/standard/deep profiles, ordinary unprivileged operation, help and documented flags; install and diagnostic checks | Implemented. No general usability study or broad physical-network onboarding evidence. |
| Reusable core for future apps/services | Independent consumer import and staged versioned installation; context-driven engine, owned events and reports; [event contract](core-events.md) | Implemented without a daemon or GUI dependency. Physical integration in those future applications is out of scope. |
| Very fast scanning | Recorded real local scans, full-port CLI checks, bounded concurrency/cancellation, direct-target before/after benchmark; [performance evidence](performance.md) | Fast results are established for the recorded workloads. Universal speed, broad congested-network accuracy and a comparable Fing head-to-head result are unproven. |
| Download and inspect Fing Mac app | Both retained DMG hashes match the recorded 4.0.5/3.10.1 packages; file inventory and static loader/remote-client analysis | Download/inspection completed. The requested complete MAC/recognition mapping was not recovered; see [exact findings](fing-research.md). |
| Broad independent recognition | Embedded source manifests, catalog tests and runtime provenance: 58,421 IEEE assignments, 1,759 hardware identifiers, 946 Recog patterns, protocol observations and virtual MAC ranges | Substantial implemented coverage. No source establishes identification of every device; randomized MACs, missing advertisements and unknown products remain unresolved. Broader physical-device checks are incomplete. |
| Open-source distribution | MIT code, upstream data notices, deterministic self-contained archives and independent install checks; read-only GitHub status | Code/licensing and local artifacts are prepared. Repository remains private, current changes are not uploaded, and public retrieval is unverified. |
| Reliable supported-platform behavior | macOS/Linux ARM64 race/protocol/CLI checks; rc.6 actual four-platform archive checks; translated x86-64 execution | Recorded scopes pass. Current-source four-platform packaging, broader native Intel/AMD hardware, macOS BPF peer exchange and wider physical-device coverage remain incomplete. |

On this audit, every retained log hash in `research/results/rc6-verification.json` and `direct-target-verification.json` was rechecked, along with all four rc.6 archive hashes and both Fing DMG hashes. These records are local evidence, not shipped logs. Successful controlled protocol fixtures do not substitute for an independently identified physical endpoint; Linux kernel raw-neighbor tests do not establish macOS BPF operation.

Read-only GitHub checks still show private `coupez/lantern` and draft PR #1 at `c3ab558e97a40844f066a8288b601061770010ac`. Earlier remote CI therefore does not verify current local source. The pending rc.6 publication proposal has not been authorized; automatic continuation is not approval to upload, merge, change visibility or publish.

The next external verification needs an owned endpoint with independently known IP, MAC and expected manufacturer/model, and the relevant network interface. The existing macOS peer harness also needs BPF access. Its earlier prerequisite-only result reported raw discovery unavailable and sent no probes. No endpoint identity should be inferred from Lantern's own output and then used as its accuracy ground truth.

The [remaining work list](STATUS.md#still-required-before-calling-the-broad-goal-finished) continues to apply. Additional code features or simulated tests alone cannot close the publication, physical-accuracy, native-hardware or unrecovered Fing-catalog gaps.
