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
