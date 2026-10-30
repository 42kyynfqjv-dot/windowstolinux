# Original second-resolver lock and protected cache publication

The later [registered UCRT getter connection](STARTUP-PTD-ACQUISITION.md)
supersedes this checkpoint's PTD-call endpoint; its lock/protection evidence remains.

## Address and ownership contract

The original indexed helpers at `0x40bdcf` and `0x40be17` execute their certified
23-byte instructions, including `IMUL index,24`, table addition, the stdcall API,
cdecl return and caller argument cleanup. Complete live executable bytes and the
named IAT are validated before execution. The shared helper proof accepts other
nonoverlapping aligned table/import locations; it supplies the actual arithmetic
address to the ownership kernel.

Logical IDs are separate from native object-tracking slots. The kernel checks
`index < 32`, checked table/address arithmetic, and a unique live Module object
at that exact address. It returns that object's native slot to the host effect
closure. Guest EAX/flags, stack, preserved registers and address arithmetic still
follow original instructions. No slot number is injected into guest state.
The bootstrap record occupies slot0, so this entry's logical14 resolves to slot15;
an independent slot permutation resolves the same logical14 to slot5.

Lock acquisition, recursive leases, use and release revalidate runtime/thread
identity, current depth, canonical object identity, mapping lifetime and all24
writable object bytes. Out-of-range/ambiguous/unconstructed addresses reject.
Fixed storage/resource exhaustion remains unsupported rejection; this does not
claim Windows resource-exhaustion equivalence or contention between guest threads.

## Original publication order

The resolver owns a local, checked lease issued by the actually executed enter
helper. Before write enable, original cache XCHG, read-only restoration and leave,
the runtime revalidates that same lease. Before leave, all128 cache bytes must be
read-only again. The original import adapter retains output-buffer and protection
validation, page boundaries and stdcall cleanup. Original XCHG publishes the
missing-export sentinel; neither a function descriptor nor callable is invented.
The original return requires the local lease to have been consumed.

A rejected later effect preserves earlier effects. There is no synthetic unlock,
permission rollback or Windows FALSE/LastError value on unsupported failure.
For example, rejection after successful write enable retains RW and the lock;
rejection after XCHG retains the sentinel; rejection after successful restoration
retains RO and the lock until the original leave executes. An injected restore
FALSE follows the source branch to the still-unbound abort effect, with RW/cache
and held ownership preserved. This is a scripted failure input, not a Windows
allocation/protection-failure observation. Ordinary guest protection of an opaque
lock's page already rejects; adversarial low-level permission mutation additionally
tests that use of a once-valid lease cannot survive changed permissions.

## Connected entry result and limits

The same unchanged authored PE with SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`
now passes CALL `0x407e92 -> 0x40bdcf`, actual RW enable, cache publication,
RO restore and matching release. `0x41e00c` becomes `0xffffffff`; the selector
returns and its original flag store executes. The original FLS allocation wrapper
allocates **second index1** and stores1 at `0x41c170`, retaining callback `0x40a100`.
Index0 and its previous value stay live. Execution then rejects explicitly at
CALL `0x40a428 -> 0x40a332`: registered PTD acquisition context unbound. No PTD
initialization or callback7 completion is claimed.

This result requires the existing versioned explicit native-profile extension.
Its [Windows mapping evidence](SECOND-FLS-PROFILE.md) remains limited to the observed
x86 KernelBase revision on Windows10.0.20348. No XP/7 equivalence follows.
Default admission still rejects LoadLibraryExW `0x402b00`. Actual delivery,
RtlUnwind/collided-unwind, formatter/locale/FILE completion and remaining startup
contracts remain open. This is connected native instruction component execution,
not whole-PE admission or full rcedit support. Historical Windows timeout causes
remain unresolved. Five recorded Windows wrapper comparisons are retained; this
slice introduces **zero new Windows/ELF or whole-PE comparisons**.

## Independent verification and next gate

Twenty-two native cases cover exact successful partial boundaries, recursive
leases, permuted slots, out-of-range and wrong release IDs, duplicate objects,
foreign threads, stale mappings, early release, out-of-order nesting, changed
enter/leave code, repeated release and failures before/after protection/publication.
Every successful partial path explicitly requires the PTD boundary, actual FLS
allocation and no held inner lease; failures assert exact errors, prior cache and
permission effects, retained ownership and absence of FLS allocation. Two permission
mutants verify both the public opaque-page rejection and stale-lease rejection
following independent low-level mutation. Earlier failed test attempts are retained:
the permission test initially tried a public transition that correctly rejected
opaque bytes, then was corrected to separate that assertion from the adversary.
No runtime gate was relaxed to satisfy the test.

Next connect the existing original registered PTD getter at `0x40a332` to this
live startup exception registry and canonical fiber context. Keep FLS index,
fiber value and heap/PTD view identities distinct; callback completion alone
must not issue event/restoration authority. Sol can review and attempt that bounded
connection; a new concrete ownership/continuation issue would justify Astra.
The concrete connection has three gates: propagate the live `NormalCallEpoch`
through initializer/table/callback execution to `ptd_get_registered_with_lazy`;
issue a native current-fiber read/default-null effect for the actually allocated
index (the existing getter requires an already bound `CrtFlsSlot`, and
`bind_fls_fiber` records independently established state); then execute the
existing original lazy allocation/view/publication path without supplying a PTD
or setter outcome. An allocated index alone is not a heap/PTD pointer. This
checkpoint deliberately issues none of that missing authority.

Reproduce with the unchanged authored `unwind.exe` and retained original
observations using `python3 research/process/startup/check_normal_wrapper.py
ORIGINAL_DIRECTORY OBSERVATION_DIRECTORY NEW_OUTPUT_DIRECTORY`. The harness
verifies PE/import/code and observation hashes, runs the artifact-dependent
canonical-startup case and the five recorded wrapper comparisons, and retains
logs plus emitted Rust. The 22 new cases execute in canonical-startup.

Source, generated artifact and test hashes are in
[evidence/cache-publication.json](evidence/cache-publication.json). Final-head CI
and independent substantive review remain required; PR45 stays draft.

## Recovered verification checkpoint

The same workspace was recovered after an exec-server transport disconnect.
The final replay had completed; source hashes matched the frozen inputs and the
repeated generated Rust hash stayed
`bd164b1580e4d86a615a20af7965d41eba4386ed8e122293b4f7417378758b1f`.
Both artifact-dependent tests and all five recorded wrapper comparisons passed.
The normal suite passed286 tests with those two tests ignored; Python ran76
with one existing skip, Clippy all-targets and formatting passed, and all seven
memory mutants plus ten frame vectors passed. The prior1d8639e workflows
41097873035/41097862644/41097862743 all succeeded; they do not validate this new head.
The failed transient build/test attempts remain preserved and are classified in
the evidence record. No fresh Windows or whole-PE result is claimed.
