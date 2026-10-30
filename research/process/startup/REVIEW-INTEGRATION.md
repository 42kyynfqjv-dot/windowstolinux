# Reviewed integration scope after the borrowed-root decision

Review of 42a557b: the identity evidence is appropriately qualified, and the
selected boundary is conditionally sound. It does not yet permit original rcedit
admission. The 19 Python tests check record/model, inventory and metadata behavior;
none proves root opacity. The ten Windows observations check three independently
authored suites, not complete original handler behavior or native translation.
No production semantics changed in this contract review.

## One cohesive Astra implementation scope

Implement a single shared event/activation mechanism in production proof and
native emission, then compose original handler instructions with it. Stay in
PR45. Do not split this into another series of disconnected models.

1. Introduce a thread-generation-bound borrowed predecessor value with a lifetime
   enclosing the entry activation. Preserve it through the actual prolog/epilog
   and validated record links. Copy/restore needs no permission to dereference it.
   Reject conversion for arithmetic, raw-memory inspection, unbound API escape,
   numeric-to-capability casts or an unproved comparison involving that value.
2. Extend the real activation state with valid x86 CONTEXT fields, event record,
   search cursor, selected frame, cleanup cursor and restoration target. Separate
   language filter results from raw dispatcher dispositions. No caller-supplied
   Boolean or raw address may clear pending state or grant continuation authority.
3. Lift one complete original prolog/filter/cleanup/restore path. Derive scope
   and callback targets from original bytes and validated state. Bind every
   reachable call, memory fault and terminal effect. Include guards, notification
   writes and saved registers. The current input helper dispatcher cannot stand
   in for numeric ESP/EBP, FS state or complete saved context.
4. Prove application containment over all admitted states, not observed cases:
   every search selects a live application frame or a validated same-thread
   continuation before the root; every unwind stays within that boundary. Execute
   cleanup before retiring storage and preserve the selected frame. A fault during
   a filter/cleanup, unknown external call, collided unwind or escaped search must
   either have complete semantics or reject admission before emission.
5. Emit statically compiled original blocks and explicit event transitions.
   Do not fetch/decode PE bytes at runtime, return an arbitrary error for an
   unsupported reachable path, substitute expected outputs or identify applications
   by name/hash. Existing continuation and memory machinery can be reused where
   its invariants actually match this contract.

## Acceptance and failure gates

Compare unchanged PE and generated ELF for a composed resume path and a composed
inner-search/ordered-cleanup/nonlocal-transfer path. The existing VR/IOFH programs
give independent expectations, but their full CRT entry is still a prerequisite.
If using original instruction slices first, retain their bytes and state snapshots
and label the result as slice execution, with no whole-PE or rcedit acceptance.
Record original bytes/PE hashes, deterministic Rust, stdout/stderr/exit, selected
successors, context/register/stack/FS state and ordered cleanup effects.

Independent negatives must exercise actual production proof and emitter inputs:
root escape, wrong-thread and stale context, noncontinuable resume, missing valid
context fields, invalid instruction target, uninitialized scope data, protected
return corruption, cleanup fault and exhausted target/proof budgets. Rejection
must produce no newly emitted executable claiming support. Preserve previous
native corpora and all historical failure evidence.

An integrated original-slice result can establish the new architecture; it cannot
remove whole-image admission barriers. Full utility admission additionally needs
every reachable startup/API effect and entry/exit contract. If the selected original
path cannot be closed, report the first originating instruction/event, missing
contract, observable consequence and minimal dependency graph. This is a precise
implementation blocker, not permission to assume that event never happens.

The private ntdll symbol is not needed to prove an opaque boundary that cannot be
observed. If the path reaches that handler, the present metadata and Windows probes
are insufficient to implement it. Obtain its shared observable contract or retain
rejection. Do not claim that the root probes describe the private handler.
