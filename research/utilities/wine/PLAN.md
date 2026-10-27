# Pinned WinMerge lead and supported CI route

This is preparation, not a reproduced Wine failure. Public issue
[#40](https://github.com/42kyynfqjv-dot/windowstolinux/issues/40) tracks the experiment.
`pins.json` records official WinMerge 2.16.41 **beta**, source commit, downloaded
x64 archive/entry hashes, AMD64 machine header and bundled license-file hashes.
The archive was inspected as data only. No binary, installer, plugin or command
inside it was executed or added to the repository. Top-level COPYING is GPL v2;
third-party notices are separate. No proprietary source is imported or code ported.
Binary redistribution in future artifacts requires corresponding source/notices,
not merely a link to this top-level license. Prefer retaining observation reports
and hashes while fetching the untouched official package in each disposable job.

The official Ubuntu noble universe index currently supplies Wine 9.0~repack-4build3
and Xvfb 2:21.1.12-1ubuntu1; filenames, SHA256 and dependencies are retained. These
are metadata candidates, not a resolved installed dependency closure. In particular,
Wine 9.0 cannot establish the reported Wine 10.13 behavior. Do not downgrade an
existing runner package or add an untrusted repository to force this pin. A future
CI experiment must select a maintained official repository/snapshot and capture
its full authenticated package resolution, including X server dependencies.

## Isolated setup and measurement gates

1. Use a fresh disposable hosted Ubuntu runner, no secrets or persisted prefix.
   Official apt packages installed through its normal supported setup are suitable;
   unavailable Docker here is not a reason to bypass daemon access restrictions.
   Verify pinned package versions/hashes and record the actual Wine runtime.
2. Download/hash the official portable app; restrict extraction to its temporary
   directory, reject path traversal, keep licenses, and disable external command,
   AI, web and archive plugins for this plain-text file test. Do not run installers.
3. Fresh prefix and X display; remove broad host-drive mappings and redirected
   personal folders from that disposable prefix before app execution. Confine test
   paths to tiny authored files in one disposable root; no user files or devices.
   Prefix mapping is not a security sandbox: use no sensitive workspace/credentials
   in the runner, and do not call this protection equivalent to process isolation.
4. First freeze actual Windows GUI actions/expected cancellation and filesystem
   results for the **same** app/hash. Then reproduce those actions under the pinned
   Wine build. Capture version, logs, screenshots and before/after hashes. Never
   replace the actual ShellMenuDelete path with a direct filesystem delete.
5. Preserve any failed setup or timeout without hidden retries. A Wine 9.0 outcome
   is a separate observation; the original Wine 10.13 report and a maintained
   current version require their own verified setup and comparison.

Remaining gates are full package closure, deterministic GUI action/observer and
original Windows baseline. No application execution or current Wine failure is
claimed. A reduced IFileOperation probe could isolate a shared API dependency but
would not replace the application reproduction. DeleteItem queues an operation;
PerformOperations executes, and S_OK does not rule out cancellation. The converter
still rejects this ordinary GUI/COM/CRT program. WinMerge is a development lead,
while VirtualDub and CrystalDiskMark/DiskSpd families remain held out; no storage
benchmark, driver or kernel operation is part of this plan.
