# Same-event capture acquisition: bounded implementation contract

Review baseline: 2cc9c7748a05c265a25b9f5b9e055bdc93e224e2. This is the
remaining implementation gate for PR #45, not an implemented admission proof.
The retained Windows wrapper comparisons validate components; they do not acquire
an OS CONTEXT for the complete original program.

## What the reviewed implementation establishes

`CrtNormalObjects::bind` retains the exact live scalar value and known mask.
`validate` checks the event, storage lifetime and unchanged snapshot before using
its predicates. `CrtOrderedSearch` retains that snapshot through execution and
receipt consumption. `CrtCxxContext::bind_normal` gives partial values no numeric
pointer; numeric unwind still rejects them. The interval endpoints cover every
possible represented value, and ambiguous comparisons reject. The helper's
original decision order and bypass preflight remain intact.

The review found no runtime defect in that connection. It added two strict cases:
a change to only the known mask must invalidate a receipt even when the bound
answers stay the same; a partial value inside the registry thread interval must
still reject when ambiguous against the separately declared C++ stack region.
These are cases 48 and 47 respectively in the 49-case ordered selector.

## Exact missing authority

`CrtNormalException::issue` proves the interrupted CALL binding and owns its
suspension. `produce_record_fields` derives code, count and flag bit 0. Neither
method establishes any captured ESP bits. `CapturedStackView::from_bits` can
observe supplied knowledge but cannot produce knowledge of an unknown word.

The older `OwnedExceptionEvent::from_raise` has an opaque captured predicate token
under a declared valid-stack, fault-free, non-intercepted domain. Its identity is
an `OwnedEventId` tied to a different Machine/selected-frame lifetime. The normal
path instead binds registry identity, normal epoch, NormalFrameId and fresh event
generation. Copying either that token or CALL registers into the normal path
would not establish the required same-event capture authority.

## One cohesive Astra High implementation scope

1. Add a compiler-owned observation certificate assembled from the original
   RaiseException import/CALL binding, `PrefixProof` code and helper targets,
   decoded `ContextCheckProof`, empty-scope return `DispatchProof`, and selected
   C++ prefix/common/dispatcher/getter/guard proof. Record all reachable context
   observations, not just the sampled branch. Initially admit only the existing
   continuable zero-parameter, empty EH4 search → C++ ContinueSearch domain.
   Reject unknown calls, raw context field reads except the decoded stack helper,
   stores, pointer escape, nonempty filters, backend/termination paths and new
   effects. An opcode certificate alone is insufficient: NormalRaiseCallProof
   currently proves only the CALL encoding, not API or process-domain closure.
2. At that certified pending CALL create a normal-event capture capability bound
   to registry identity, epoch, source frame, fresh generation, source binding,
   record/context region capabilities and declared stack bounds. A dedicated
   normal-event token is required; do not cast an old OwnedEventId. Keep the
   valid-stack/fault-free/no-unproved-interception premise explicit and establish
   how the containing proof admits it. If it cannot be established for a program,
   reject that program before emission.
3. Make normal objects and ordered receipts distinguish supplied numeric/masked
   storage from this certified predicate-only capture. For the latter, retain
   unknown raw context bytes. Validate the token and storage identity on every
   borrow and receipt use, even on selector bypass. Mutation, escape, stale or
   foreign source, nested event and lifecycle transition invalidate the relevant
   authority. Do not choose a numeric witness or grant numeric unwind access.
4. Emit the existing decoded helper predicate body through that capability and
   connect both actual handler executions and single-use receipts. Invalidate
   capture authority at the justified transfer/completion/failure boundary.
   Call-entry register state, saved exception context and any restoration context
   remain separate. Keep incoming-handler containment and Windows collided-unwind
   effects rejected unless independently closed.

This scope requires joint proof/emitter and event-lifecycle reasoning. Routine CI
verification and review can stay on Sol. More bit-range arithmetic or isolated
accessor probes will not close the missing authority.

## Observable acceptance and rejection

The connected original EH4 → C++ component must run with every raw captured word,
including ESP, unknown and with no numeric/partial ESP supplied by its harness.
Both receipts must arise from original instruction execution. Reject emission
when the code/effect certificate is absent or invalid; a runtime error replacing
an unsupported Windows effect is not sufficient for whole-program admission.

Independently test all helper predicate branches and query order, stale and foreign
events, wrong source frame, nested captures, changed source/helper/callee bytes,
raw read/write/escape, changed memory capability, mask mutation, replay, early
completion and failed handler effects. Verify prior effects remain observable on
later failure. Preserve the existing numeric/masked domain and its rejection tests.
Record artifact/source hashes and distinguish recorded wrapper replay from fresh
Windows comparisons. Whole-program acceptance still requires unchanged header
entry through stdout/stderr/exit without supplied state or skipped startup.
