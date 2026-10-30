# API-set acquisition: measured namespace, unproved initialization

## Exact boundary and version

The unchanged authored entry still stops at `LoadLibraryExW`, CALL `0x402b00`,
IAT `0x415074`, requesting `api-ms-win-core-synch-l1-2-0`. The resident-DLL
component in [RESIDENT-LOADER.md](RESIDENT-LOADER.md) cannot issue authority for
this contract. No new native startup or FLS publication is admitted here.

Microsoft's [API-set loader operation](https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation)
and [API sets](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets)
(accessed 2026-10-30) specify a contract namespace whose host mappings depend on
the Windows device/version. They do not establish a universal `kernel32.dll` or
`KernelBase.dll` alias. The documentation describes Windows 10 and later; this
experiment is narrower: Windows Server 2022, build 20348, x86. Actual ntdll and
host-file hashes pin each observed revision. Neither this experiment nor the
resident component establishes Windows XP/7 compatibility.

## Reproducible observation

`api-set-frozen.json` freezes the authored C source and independent expectations
before Windows execution. The pinned MSVC 14.44 x86 workflow builds it without
source changes. `measure_api_set.py` retains compiler/source/PE hashes, commands,
raw output and per-case results. Build and process limits are 60 and 15 seconds;
timeouts retain partial stdout/stderr and fail the job, with no automatic retry.

Four separate processes observe three documented API-set names/exports and an
intentionally missing contract. Successful cases perform two loads, resolve the
export, identify both the load host and actual export host, release one acquired
reference and check that the export remains resolvable through the other. The
probe releases its remaining references before successful process termination.
It does not call those exports or run a utility. A `GetModuleHandleExW` reference
to the export host also remains live during the intermediate release: therefore
this experiment cannot prove last-reference unloading, nor a precise internal
reference count. Already-resident system hosts cannot prove first-load attach.

Paths are resolved through file handles inside the x86 observer, then hashed by
Python. Every host file must have the x86 PE machine type; this prevents hashing
a same-named 64-bit System32 DLL. The observations validate an internally
consistent report; hashes alone do not authenticate a trusted publisher.

The validator rejects missing/duplicate contracts, unsupported build/architecture,
flags or symbol combinations, failed load/reference observations and mixed runtime
identities. Its synthetic tests are validator tests, not real Windows failures,
stale module executions or initialization failure injection. `authorize_native`
rejects every supplied initialization claim, including success: no provider proof
issuer exists yet. The observer's future CI results must be reported separately
from existing Windows/Linux component pairs. This checkpoint adds zero PE/ELF pairs.

## Integration contract and remaining implementation

A mapping record is descriptive evidence, not a callable export. Native acquisition
needs a process-owned provider with an explicit supported contract version, exact
export ABI/effects, initialization phase, and reference/generation lifetime. It
must resolve by contract semantics, never by application name/hash or arbitrary
host `.so` lookup. Several contracts may share a provider; references must share
its identity, while fiber-local values remain distinct from process-owned slots.

The bounded next implementation should first close the lock provider used by
`InitializeCriticalSectionEx`: allocate opaque lock state under process ownership,
apply the documented success/failure transition, and publish the module/export
only when initialization has completed. Its implementation must define permitted
flags, recursive/thread ownership behavior, error state and destruction ordering.
See the [primary API contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex).
An initialized resident handle supplied by a test cannot replace this producer.

Before connecting that provider at `0x402b00`, prove publication is atomic with
respect to acquisition, failed initialization exposes no callable export, stale
exports cannot survive final retirement/reuse, and unsupported loader flags or
ambiguous mappings reject before changing state. Preserve prior effects if a
later operation fails. Explicitly reject unsupported loader callbacks, DllMain,
TLS notifications, concurrent initialization/reentrancy and arbitrary libraries;
do not assume that their effects are absent in the original program. This is a
specific remaining design/implementation gate, not one closed by samples.

## Review and status

Review of `ad8ea68` found its resident-only premises and stale/ambiguous-module
rejections remain explicit. Its Windows component probe job passed at this
checkpoint; full workflows still had Linux work running. The new work changes
measurement/validation only. Historical original-Windows process timeouts remain
unresolved and are unrelated to a claim of API-set closure. PR #45 stays draft;
full formatter/startup/rcedit remains unsupported.

## First recorded Windows result

[Run 41042507916, job 124018486441](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41042507916/job/124018486441)
passed the four original observations at commit `f30aff6`. The frozen source was
unchanged. [Machine-readable evidence](evidence/api-set-observed.json) was
extracted from the job's JSON stdout; artifact 12970567877 holds the build,
executable and raw logs. Its archive digest is upload-reported, not independently
download-verified. These are four original Windows observations, zero translated
pairs and zero export invocations.

| Contract | Load host | Export host |
| --- | --- | --- |
| synch-l1-2-0 / InitializeCriticalSectionEx | x86 KernelBase | x86 KernelBase |
| fibers-l1-1-1 / FlsAlloc | x86 KernelBase | x86 KernelBase |
| heap-l1-1-0 / HeapAlloc | x86 KernelBase | x86 ntdll |

The invented contract failed with error 126 in this observation. This does not
prove that every missing mapping has that result. All successful cases retained
the export after one acquired release. Both DLL files were resolved under
SysWOW64 and their PE machine fields were 0x14c. The distinct HeapAlloc host is
important: `CrtFunction` currently carries one `CrtModule`, and
`module_export_result` explicitly excludes forwarded-owner assumptions. Reusing
a load-handle token as the export's sole lifetime authority would lose this
observed distinction. Forwarded exports require a checked relationship to the
actual provider lifetime before they can be admitted. The first synch contract
has one observed host, but native provider initialization still remains unproved.

Local review tightened the report validator to bind the frozen source and valid
compiler/PE hashes and reject false translation counts or truthy non-Boolean
observations. The existing resident-lifetime native regression passed; Python
ran 70 tests with one existing skip. All three workflows for ancestor `8edb01a`
completed successfully. At the latest read, `ad8ea68` and the new complete
workflows remained in progress; the new API-set job and inventory job passed.
