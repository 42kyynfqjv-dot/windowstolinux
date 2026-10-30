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

## Observation-proof defect found during implementation

The first acquisition-certificate implementation pass found a prerequisite defect
in `handler_context::Proof::walk`: its decision tree could discard an unused
CONTEXT or FS/TEB load before the selector comparison. Both original outcomes
could still match the required tree while the bypass path performed an extra
memory access. That access can fault, so the old tree alone was insufficient as
a no-observation certificate.

The walker now tracks whether the current path is the selector's non-bypass arm.
Any CONTEXT/TEB/FS memory access before that decision or on the bypass arm rejects.
The flag travels with each symbolic path; it is not inferred from the sample
selector value. Original unchanged helper proof/emission remains supported.
Two independent instruction insertions exercise an unused EDX context load and
an unused FS self load. Disabling the new guard in a separately compiled copy
reproduces acceptance of the changed helper and fails the exact regression.
This is compiler-proof evidence, with no new Windows or whole-PE comparison.

The whole-event certificate and lifetime issuer are still unimplemented. The
corrected local helper proof is a necessary leaf of that certificate. The next
connected step must compose observation summaries for the EH4 prefix, return
path and C++ callees, including discarded reads and external effects, before
issuing any normal-event opaque capture token. The actual bypass branch may need
no captured ESP predicate at all; do not fabricate valid-stack knowledge merely
to satisfy today's numeric preflight. Preserve ownership checks independently of
whether a guest branch reads captured state. Other selector values still need
the justified predicate/acquisition domain. No new capture authority is granted
by this correction, and full startup/rcedit remains rejected.

Validation: 224 CRT tests and all-target Clippy passed; the observation-dependent
test passed separately with retained original-code regions and Windows vectors.
Generated harness SHA256 remains
`8f32a1b51989e531b6e50809461763aad6ae3cd80bd46bf8ff2ccb84269ec21b`.
The five recorded comparisons remain component evidence. No fresh Windows run
or whole-PE result was added. To reproduce the adversarial compiler experiment,
copy src/handler_context.rs, replace the single condition
`if capture_read && !state.capture_observation_allowed` with
`if false && capture_read && !state.capture_observation_allowed`, and compile
that copy as a Rust test with the project's built iced_x86 dependency. Run
`bypass_certificate_rejects_dead_capture_reads_before_selector`. Compilation must
succeed, then the test must fail with actual `None` versus the expected rejection;
an unrelated compiler/runtime failure is not counterexample evidence.
