# Original locale publication and UCRT getter completion

Later checkpoint: [original descriptor startup](STARTUP-DESCRIPTORS.md) continues beyond this historical callback-8 boundary.


Under the explicit second-fiber native profile, original entry now executes the
second helper at `0x40a00d`, its scope `0x41b600`, indexed lock-4 acquisition,
replacement `0x40a296`, and module-backed reference walker `0x40c4ad`. Original
cleanup `0x40a05b` releases the matching lease, and the proved original epilog
unlinks its EH4 record and returns with `RET 12`.

The original static-child guards at `0x40c672` execute. Null or the original
shared-static address reaches the original return instructions; another or
unknown target cannot receive fabricated success. Dynamic-child execution rejects
at `0x40c686`, before XADD. The original free body at `0x407d50` executes its null
branch. A nonnull free remains unsupported. The lazy producer then executes its
original LastError restoration and return, and the registered UCRT getter executes
its actual epilog/return and removes its C++ record.

The initializer loop completes callback 7 and selects **callback 8, `0x408697`,
at indirect CALL `0x40c946`**. That callback remains unbound. This is an unchanged
PE component path under an explicit profile, not full startup, rcedit, default
admission, XP/7 support or a new Windows/ELF comparison.

## Ownership and effects

The same 868-byte Buffer allocation remains published to its actual current-fiber
FLS slot. The 40-byte VCRUNTIME layout grants no UCRT authority. Replacement checks
that exact UCRT root, slot, allocation lifetime and publication before executing.
Old nonnull locale-release/free paths reject before replacement because those
contracts are still incomplete. The original store at UCRT `+0x4c` precedes new
reference acquisition. A later child/read/code failure retains that store and all
earlier increments. It does not synthesize rollback, release, unregister or return.

Module-backed fields may contain fully known numeric guest addresses. At original
read/effect points they are resolved only within the same canonical mapped process
image. This grants neither heap/stack access nor authority from unknown or foreign
values. Existing typed Buffer pointers retain their original capability/extent;
no allocation is copied or retagged. All effective reads/writes remain checked.

The walker executes its actual conditional reads, optional increments and six-entry
loop. It uses the existing initialization/lease-checked module-word increment and
x86 flag behavior. Static-child paths use actual branch conditions and original
MOV/epilog/RET instructions. Dynamic XADD and dynamic prior-reference release remain
rejected, including when a new pointer has already been published.

Cleanup entries and the null-free entry now validate the active protected call
before body effects. Fresh and replayed cleanup attempts cannot reuse a consumed
lease. This remains normal-path EH4 cleanup; actual exceptional containment and
nonlocal unwind through these functions are not proven.

## Independent tests and provenance

Twenty artifact-bound component cases exercise valid/null replacement, prior
nonnull references, interior aliases, freed roots, foreign fiber, uncertain FLS
identity, stale/replaced leases, unknown counters, invalid module targets, dynamic
and unknown child references, replayed return and fresh repeated cleanup. Success
requires a real returned success and exact live-field/refcount results. Failure
assertions check publication and prior increments at their actual effect boundaries.
Seven additional original-PE code mutations cover second body/epilog/cleanup,
replacement, walker, guarded child and free. They check retained lock/registry state
and whether replacement occurred before the rejection.

The direct component tests construct owned input state; they are not fresh Windows
observations. The connected entry test uses real preceding producers and asserts
callback-8 selection, completed getter record retirement, released leases and the
same published allocation. Existing recorded Windows wrapper comparisons remain
separate. Final validation passed290 CRT tests; both artifact-dependent tests passed in
completed replay. Clippy/format and76 Python tests (one existing skip) passed. Five
recorded Windows wrapper comparisons passed, with zero new Windows/ELF pairs.
Repeated Rust SHA-256: `d387a780f41909561c5323c0063f19e0eed84ea548cb9b0143e82405381a99ab`.
Exact source/PE/Rust/report hashes and final results are in
[evidence](evidence/ucrt-locale-publication.json).

Review corrected two test-state assumptions: logical lock 4 must use its actual
indexed table address for the original cleanup helper, and successful getter
retirement removes the C++ record rather than retaining an unlinked entry. Those
failed local attempts are retained. Production contracts were not weakened to
satisfy either expectation.

## Next coherent gate

Callback `0x408697` has scope `0x41b5c0`, original indexed lock 7 and calls
`0x40bf2a`, `0x408537` and `0x4085e7`, followed by its cleanup `0x4086ee`.
The existing allocation-manager/standard-handle components are relevant reusable
pieces. Bind them to the actual live startup epoch, canonical heap, descriptor
lifetimes and newly produced UCRT state, including proven errno-field authority
where required. Do not insert successful allocation/I/O callbacks or treat the
completed UCRT producer as proof of the entire CRT startup.

The case-19 original-Windows timeout remains unresolved. No retries, timeout
thresholds, formal approvals, merges or releases changed here.
