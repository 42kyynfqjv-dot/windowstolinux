# Independent synchronization conformance

This freezes an authored Windows observer and independent operation expectations
before evaluating it against the native component. It changes no production API
semantics. The original entry remains at LoadLibraryExW402b00/IAT415074.

The observer builds with official MSVC14.44 x86 on Windows Server2022. The checker
admits only observed build10.0.20348; each run records actual compiler/source/PE
hashes and command. It invokes InitializeCriticalSectionEx with flags zero and
spin counts0/4000, acquires recursively twice plus TryEnter once, releases all
three acquisitions, deletes, reinitializes and deletes again. Canaries adjacent
to the object must survive. The opaque object itself is never inspected. Expected
operation sequence and source hash are in sync-frozen.json, independent of observed
outputs. Successful return is normalized to Boolean; successful LastError is
recorded and deliberately unconstrained. All native transitions execute existing
methods; trace events are appended after the operation succeeds.

The Linux job consumes the actual Windows executable/report artifact, verifies
its hash, runs one exact named Rust test, and requires both native scenario
outputs. It compares actual operations and canaries, not a baked-in application
output. These are Windows-versus-Rust **component** pairs, never PE translations.
The native owned-thread recursive acquisition is paired with Windows' successful
TryEnter on an already owned object; this establishes no cross-thread contention
support or standalone native TryEnter guest binding.

Windows build timeout is60seconds; each observer process15seconds. Native component
timeout is180seconds; timeout output is retained and the job fails without retry.
The checker rejects missing test completion, source/PE mismatch, unsupported host,
wrong scenario order and differing outcomes. Independent validator tests cover
missing recursion, failure/deletion order, failed initialization and canary changes.
No invalid pointer, owned deletion, unsafe memory pressure or undefined Win32
operation is used to force a failure. Cross-thread/stale/alias cases remain native
rejection tests from the preceding implementation.

## Exact remaining semantic decision

The [primary InitializeCriticalSectionEx contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex)
specifies zero plus GetLastError on failure. Successful calls do not determine
which native allocation failures correspond to which Win32 error or establish
failure atomicity. This observer does not force allocation failure. The current
native implementation propagates reservation failure as an unclosed effect,
so complete API admission remains blocked regardless of conformance success.

The next implementation must choose an explicit resource contract: either prove
that bounded native storage is reserved before the admitted call, including map
allocation, or specify and implement allowed failure/error/output transitions
under a reviewed platform resource abstraction. A successful probe cannot issue
that proof. An injectable allocator can test the native failure branch, but those
scripted outcomes must remain distinct from original Windows observations. This
is a concrete bounded reasoning task, not a reason for repeated success probes.

Separately, API-set acquisition must justify native system-provider initial state
and guest-observable loader effects, bind the actual original call certificate and
mapped lock object/index, and retain rejection of unknown callbacks/exports. Native
registry readiness alone cannot close those obligations. Full startup/rcedit,
XP/7 support and historical Windows timeout causes remain unresolved.

Primary-source review also found version-specific stronger guarantees for the
separate [InitializeCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsection)
and [InitializeCriticalSectionAndSpinCount](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionandspincount)
functions: their documentation says they succeed even with low memory starting
with Vista, unlike the documented XP behavior. These statements must not silently
be transferred to InitializeCriticalSectionEx, whose own return contract retains
a failure branch. Neither a modern success observation nor these sibling APIs
justify eliminating that branch for every supported Windows version.

## Recorded result

[Windows job124037455190](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41048206319/job/124037455190)
passed both spin configurations at commitf395c4e on build10.0.20348 with x86
MSVC14.44.35207. [Recorded stdout and provenance](evidence/sync-observed.json)
retain the original PE/compiler/source hashes. Local native operations matched
both rows; [comparison evidence](evidence/sync-conformance-review.json) explicitly
labels them component pairs and distinguishes recorded stdout from artifact
verification. LastError retained sentinel0x1234 in these two success observations;
this is not promoted into a preservation guarantee or allocation-failure evidence.
The dependent Linux job additionally checks the actual observer artifact hash.

A concrete bounded next alternative is to replace per-call native synchronization
bookkeeping allocation with preallocated slots for the already admitted maximum
of32 global objects. The current global_objects BTreeMap and native_sync Vec both
need accounting: reserving only the Vec would not close map allocation. This can
remove native initialization allocation as an unclosed operation within an
explicit bounded-resource contract. It still needs proof of admissible indices,
object ownership, phase/lifetime and guest-visible loader state, and does not
establish all Windows low-memory behavior. Decide that resource abstraction before
more successful-call probes; do not map native exhaustion to a guessed Win32 code.

The dependent [Linux job124037739207](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41048206319/job/124037739207)
also passed: it downloaded and hash-checked the Windows observer executable,
executed the native component and matched both traces. These two cross-host
component pairs still represent zero converted-PE executions. Full regression
workflows remained in progress at this checkpoint.
