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

## Independent path and neighboring-transform review

Review of 72974f0 confirms that the new read guard inspects original memory
operands before symbolic execution, tracks copied Context/TEB provenance, and
carries permission separately on each branch. A further test inserts dead
CONTEXT and FS loads at the shared return block. Both the bypass and non-bypass
paths reach that block; an allowed non-bypass path must not grant permission to
the bypass. A separately compiled mutant changing only the selector's yes-arm
permission to true accepts the dead read and fails the exact new assertion.
This challenges path isolation independently of removing the entire guard.

The related transformations inspected were selection filter live-load emission,
normalizer declared-global preflight and prefix object-read validation. Filters
emit their live reads; the normalizer checks declared readable initialized globals
at its explicit composition boundary; prefix reads reject unbound object fields.
This bounded inspection found no additional capture-authority defect. It is not
a certificate covering all callers, asynchronous mutation or external callbacks.

The remaining implementation is unchanged: compose a closed observation summary
for every reachable original prefix/helper/filter/return/C++ callee and bind it
to the live normal event's registry, epoch, source-frame generation, storage
capabilities and lifecycle. The issuer must reject missing summaries, changed code,
raw access/escape and unproved external effects before whole-program emission.
Only then can the component remove supplied ESP bits while leaving raw capture
storage unknown. The no-read bypass path should carry no invented stack predicate;
the non-bypass path still needs its explicit acquisition domain. Receipts must
retain and revalidate that same authority, with single-use completion/retirement.

## Connected no-read lease (current implementation)

The original empty EH4 search and selected C++ ContinueSearch path can now execute
with every one of the 716 CONTEXT bytes unknown. The component supplies no ESP
bits, stack predicate, or numeric witness. This closes the adapters' unconditional
ESP-preflight obstacle on the **proved selector bypass**. It does not complete the
whole-event acquisition certificate described above.

`ContextCheckProof` retains the original helper bytes and entry. Its generated
`bind_unobserved_context` validates the actually pending CALL, suspended source
frame, same-event produced record, fresh disjoint context storage, initialized
live selector, and unchanged helper bytes. It issues one no-read lease per event,
bound to the registry identity/epoch, source-frame generation, event generation,
source CALL return slot, storage capability, and decoded helper. The lease grants
no captured-value or restoration authority. Known or partly known input context
storage rejects instead of being relabeled as acquired state.

The shared runtime seals the entire context capability: all original loads and
stores through any alias reject, including unused loads and writes of unknown
values. The low-I/O backend read also rejects sealed input, including zero length. Only private freshness validation can inspect its abstract representation.
The original helper's proved bypass is lowered without a context read; non-bypass
selectors remain rejected for this lease. Both adapters independently require the
same helper proof, so a lease cannot replace a different helper's observations.
The existing numeric/masked input domain and its bounds checks remain intact.

The EH4 and C++ handlers still execute their original instruction paths and issue
their existing single-use receipts. A shared event/epoch lifetime revokes leases
on failed delivery, failed ordered consumption, successful component consumption,
event destruction, and registry failure/retirement. A retained event cannot keep
a lease alive after its registry epoch fails. Revocation does not remove the
storage seal, manufacture bytes, undo prior writes, or complete the guest event.
The source CALL and incoming owner remain suspended/live under the prior contract.
Limits are the existing region budget and at most 32 sealed contexts per runtime.

There are 21 additional native scenarios, bringing ordered search to 70. They
cover unknown storage through both original handlers; cross-event/source mismatch;
changed selector/helper; read/write aliases; duplicate issuance; no fabricated
numeric ESP; stale storage; event destruction; failure with prior writes; forged
lease identity; replacement context; premature revocation; an event deliberately
retained outside its failed epoch; partly initialized storage; a different valid
helper proof; nested event rejection; and external storage corruption. Positive
paths require both original dispositions, not just an intentionally rejected
outer fixture. Independent compiled mutants remove the raw-read seal or epoch
check and must fail their exact assertions after successful compilation.

### What remains before an acquisition issuer is justified

This is a connected **component no-observation contract**, not a complete static
observation/effect certificate or actual Windows delivery acquisition. Runtime
rejection protects component boundaries; it cannot substitute for conversion-time
rejection of a whole program whose effect proof is missing. Production full-startup
admission remains blocked. In particular:

- The record's delivered system flags and nested-record link are still explicit
  component inputs; the pending API producer only derives code/count and flag bit 0.
- The incoming owned root, initialized selector, C++ metadata/PTD, cached export,
  stationary fiber and FLS slot remain supplied state. ContinueSearch does not
  execute the incoming root or establish containment.
- The C++ dispatcher still contains paths to unbound search/unwind/termination
  effects. Successful component runs do not prove those paths unreachable for
  every admitted producer state. External module/loader mutation and Windows
  delivery/collided-unwind effects are not closed.
- No raw CONTEXT field can be used for restoration, pointer derivation or a
  non-bypass predicate via this lease. Such use needs actual capture knowledge
  and a separate lifetime/effect certificate.

The next cohesive implementation is to derive a closed observation/effect summary
from the original producer and both handler graphs, with explicit scalar/state
preconditions proving each reachable call and context access. Tie that summary to
API/import provenance and live initialization producers, then gate issuance before
whole-program emission. Reuse this event/epoch/storage lease for the no-read case;
do not turn its runtime error paths into Windows behavior or declare unknown
predicates true. Sol can independently review the current kernel/adapter changes
and evidence. Closing the static producer/callee proof remains a bounded Astra
scope. Full startup/rcedit and all historical Windows timeout causes remain open.

Implementation review also closed two lifetime/effect edges: an event retained
outside a failed registry epoch must not keep its lease alive, and the low-I/O
writer's direct memory read must honor the seal. The first new I/O test correctly
failed because it requested an unconstructed FILE lock; its setup now initializes
a descriptor and acquires the actual descriptor lock before testing backend
exclusion. That was a test setup error, not evidence of an original Windows hang.
No timeout or expected rejection was relaxed.

Verified local evidence: 225 CRT tests, 175 root tests and all-target Clippy pass;
the observation-dependent test passes separately against the five retained
Windows wrapper vectors. The artifact-backed reproduction and both compiled
mutants use generated Rust SHA256
`f806819348e74035b23aff014ac2c13ecc7b0fc8aaf27ae77e5192a3e0662e93`.
The original PE hash remains unchanged. The 21 new lease cases are native-only
component cases, not fresh Windows comparisons. Detailed hashes, mutation results,
limits and the local test setup correction are in
[unobserved-context-lease.json](evidence/unobserved-context-lease.json).

## Sol review of c3be6ab

Independent inspection found no runtime defect within the implemented component
domain. All emitted scalar/string accesses use the sealed load/store route; the
separate low-I/O memory reader checks the seal before calling its backend. Private
`load_unsealed` use is limited to scalar loading and lease representation checks.
The lease never initializes captured bytes or produces stack predicates, and
normal objects revalidate event, frame, epoch and storage identity. Both actual
handler calls must produce their original ContinueSearch receipts; failure cannot
count as a successful positive case.

The added case70 (zero-based mode69) fails the original EH4 normalizer after its
original earlier write. It strictly checks the scalar-knowledge failure, unchanged
interrupted registers, retained write, Failed delivery, revoked lease and sealed
unknown storage. The initial outer expectation incorrectly expected the fixture's
closing error; it now requires the registry's retained first scalar-knowledge error,
matching the handler assertion and existing mode12. This changes tests only.

The smallest next executable proof is a closed original ContinueSearch call graph
summary: derive context-pointer transport and memory observations through the EH4
prefix/normalizer/guard/context/terminal return and selected C++ prefix/common/
dispatcher/cached getter under explicit record, metadata and PTD predicates. Walk
every reachable branch under those predicates; reject unresolved callees, raw
reads/writes, escapes and unproved effects. Bind the summary to original bytes,
call targets and the RaiseException import identity, then require it at the issuer.
Do not mint it from the runtime phase, a component result or supplied ESP.

That conditional summary still needs independently justified producers for delivered
flags/nested link, selector, metadata/PTD/FLS and incoming-chain containment before
whole-program admission. Numeric acquisition/restoration and non-bypass observations
remain separate proof obligations. This is the concrete Astra scope; Sol can
verify CI and review the new proof. Full startup/rcedit stays unsupported.
