# Production activation review through 7874a31

Normal helper behavior agrees between `input/proof.rs` and the emitted
`input/continuation.txt`: both enforce the four-active-call limit, protected
continuation/stack shape and saved ESI/EDI/EBP values. The runtime maps these
registers to x86 positions 6/7/5; it leaves EBX, numeric ESP, IP and flags unknown.
The shared `control.rs` extraction preserves per-path return contexts, recursion
and cycle rejection, including repeated calls to a shared helper. Its success
does not bypass `prove` or construct `Proven`.

Snapshot ownership/generations prevent stale or foreign activation selection.
Unwind retains captured context and exposes inner frames before retirement; the
selected frame is retained. Incomplete capture blocks ordinary execution, and
noncontinuable search cannot request retry. There is no transition back to normal
and no guest code can call the phase API. No supported helper regression was
reproduced. The review extends the existing native test to all eight missing
registers, missing IP/flags, stale unwind selection and invalid restoration-phase
selection. This adds assertions, not a new test-function count.

The lifecycle API does not validate Windows CONTEXT semantics or prove cleanup
execution. `retire_cleaned` trusts its internal caller; the current API has one
retirement step per activation, while real local unwind can execute multiple
scopes in a surviving activation. These are open integration gates, not enabled
startup behavior. A retry candidate is immutable captured state, not authority
to repair a fault, change a target or restore memory.

## Concrete next code-level integration

1. Add a separate startup effect proof beside `input/proof.rs`; do not remove
   input acquisition preconditions. Normalize original handler operations through
   shared decoder operands. Its abstract state needs eight register known-value/
   provenance records, numeric stack ownership, thread/context generations,
   exception record, scope cursor and a borrowed-root identity. Enumerate guest
   memory/API/filter/cleanup failure edges as well as ordinary successors.
2. Keep the new proof's certificate and constructor private. A certificate must
   bind original instruction/handler targets, valid CONTEXT fields, same-thread
   target authority, root containment and ordered cleanup scopes. Extend shared
   graph validation with explicit event successors; ordinary Call/Return edges
   cannot imply exceptional closure. Unknown effects reject before source output.
3. Extend `activation.rs` with scope-level cleanup cursors and a restoration
   operation that requires a certificate-derived request. Execute original cleanup
   blocks while their storage is live; retire only completed scopes, then abandoned
   activations, retaining selected-frame locals. Do not expose a Boolean that
   clears search or accepts an arbitrary raw CONTEXT as validated.
4. Add a startup emitter using that certificate to lower original blocks and
   explicit search/unwind/resume transitions. Apply handler context writes through
   checked memory/provenance rules, then validated register/stack restoration.
   Use the existing input emitter only as a normal-helper client of shared storage.

Acceptance needs composed original-instruction resume and ordered-cleanup/nonlocal
transfer executions, with state snapshots and independent Windows expectations.
Production proof negatives must include missing fields, wrong-thread/stale context,
root escape, cleanup fault, invalid target and budget exhaustion. Prove rejection
occurs before emission. Slice execution may establish the architecture but does
not authorize whole-PE admission. Keep PR45 draft and full rcedit/CRT rejected until
all original entry, startup/API and exit effects are closed.
