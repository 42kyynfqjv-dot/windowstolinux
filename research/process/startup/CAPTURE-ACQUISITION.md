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

## Caller/callee composition and the remaining PTD producer

The pass from d192385 does **not** issue a closed whole-event certificate.
It closes a concrete EH4 caller/helper composition gap: the ordered search
emitter now requires the normalizer, guard/security and context proofs together.
It checks their original targets and disjoint byte ranges, the event-code domain,
cookie address and scope header. Generated local callbacks come from those same
proofs, including the context decision, rather than independently named global
callbacks. Live code checks cover all four helper bodies before execution and
receipt consumption. The previous caller/table check did not cover the normalizer
or guard bodies. This matters even when their previously compiled result would
still look correct after code changes.

Six compiler rejection cases cover a different event code, relocated normalizer
and context, a different valid header/cookie, and independently valid helper
proofs that claim conflicting bytes at one address. Four native mutations change
the normalizer, guard, security checker and context helper. A separately compiled
mutant removes only the normalizer byte check; it must fail the changed-code
assertion, not compilation or an unrelated check. The existing same-event,
unknown-byte, alias, lifetime, replay and earlier-write failure tests remain.

Two connected counterexamples identify what a complete certificate must still
prove. Both first execute and consume the original EH4 ContinueSearch result,
then enter the original selected C++ handler with unknown, sealed CONTEXT bytes:

| Missing producer fact | Original instruction/effect | Required outcome now |
| --- | --- | --- |
| Known PTD word at offset32 | `0x403d9c: cmp [eax+0x20],esi` | Exact unknown-scalar rejection; no C++ result receipt |
| Non-null FLS slot value | `0x402906: call 0x402bef` after the null result branch | Exact unbound lazy-setter effect rejection; no C++ result receipt |

Both failures revoke the no-read lease, retain the original record code and
interrupted registers, and leave all 716 capture bytes unknown. Completed EH4
scratch has already retired before the C++ call and cannot be asserted as live
storage at that later failure. The earlier in-handler failure regression still
checks its live prior write separately.

The smallest connected implementation is the original C++ PTD lazy producer:
its setter wrapper at 0x402bef (sentinel, publication and rollback), allocation at
0x407850 and free at 0x407750, including LastError save/restore and the required
getter's termination edge. Prove zero initialization of the actual 40-byte object
from allocation effects before relying on offset32; do not reuse the unrelated
UCRT errno object's contract or declare an existing slot non-null. Bind the real
module/export/slot producer and lifetime. The unknown-word case also requires
tracking any later authorized mutation before the dispatcher comparison.

Only after that producer and the delivered-record predicates are closed can a
conditional reachable-call/effect summary for the selected C++ handler compose
with the EH4 path. The current ordered fixture still uses code 0xe0420042 and an
explicit source-call boundary. The original initial RaiseException argument code
is0xe0424242; the new different-domain rejection explicitly prevents reusing the
wrong normalizer proof. Original import checking elsewhere in the artifact replay
does not make that fixture a whole-program producer. Incoming-root containment,
Windows delivery, collided unwind, termination and full formatter/exit remain
separate gates. No runtime rejection is substituted for Windows behavior in
production admission.

Reviewed d192385 completed all three workflows successfully:
40989022050,40989017448,40989017442. Its predecessor c3be6ab also completed
40988106192,40988100925,40988101018 successfully. Historical timeouts remain
unresolved. Current evidence and limits are recorded in
[callee-composition.json](evidence/callee-composition.json). Sol can review this
bounded emitter/provenance change and its exact CI; the PTD producer integration
is the next connected semantic scope.

Validation for this pass: 225 CRT and 175 root tests, Clippy, 76 ordered native
cases (27 no-read scenarios), and the full retained-artifact replay pass. All
three compiled mutants fail their intended assertions. The five recorded Windows
wrapper comparisons remain component evidence; no new Windows observation or
whole-PE pair is claimed. Generated Rust SHA256 is
`50e0c39edb170cd005db0367292b7bcfaf36deff152e34fd250034a200c75f94`.

## Independent Sol review of 5c9d4c2

No runtime defect was found in the bounded helper composition. Call targets,
event domain, cookie/header and nonoverlapping source extents are checked before
emission; the local callbacks use the matched proofs. Every helper's live bytes
are checked by the ordered caller before execution and consumption. The context
callback retains the existing predicate order and no-read lease checks. Successful
cases explicitly require both dispositions; rejection cases require their actual
error, so an unrelated failure cannot count as success.

The original setter inventory is now bound independently to the retained PE:
0x402bef..0x402c2d resolves index 3 (`FlsSetValue`, cache 0x41cd20), invokes the guard,
then calls the selected function with two arguments. Its fallback is the distinct
`TlsSetValue` import 0x415064. The existing getter wrapper is index 2 and cannot be
reused by changing only the function name. Original bytes and SHA256 are in
[ptd-setter-review.json](evidence/ptd-setter-review.json).

The connected allocation boundary has an additional concrete type/lifetime gap.
`CrtStreamRuntime::allocate(40,true,...)` returns a heap-owned `Buffer`; `fls_value`
requires a rooted `ThreadData`. The new native regression proves that both the
allocator result and a forged ThreadData tag reject before changing FLS or
LastError. A byte copy into a separately mapped ThreadData object has a different
capability and lifetime. Freeing the heap object invalidates its original aliases,
while the copy survives; it cannot stand in for that allocation. Existing explicit
ThreadData and sentinel controls still succeed. No production role check changed.
The first test run used the wrong name for the existing subtraction error; the
strict expectation was corrected to `CRT unrelated pointer subtraction`.

Astra's next bounded refactor should preserve the immutable heap allocation and
all its aliases, and attach a checked PTD object view/authority derived from the
actual original allocator effect. Define who may publish it in FLS, when zeroed
fields become known, and how free, failure, slot/fiber retirement and nested use
invalidate the view. Then connect the original cached setter wrapper, its actual
BOOL/LastError effects and publication/rollback sequence. Cold loader and TLS
fallback paths must retain their own contracts and rejection boundaries. Simply
retagging a pointer/region or copying 40 bytes is not this transition. Complete
capture certification remains blocked until these producers and delivered-record
facts are justified; no whole-event authority was added by this review.

Review validation: 226 CRT tests, the separately run recorded-wrapper test,
76 ordered cases, all-target Clippy and three independently compiled mutants pass.
The generated wrapper remains SHA256
`50e0c39edb170cd005db0367292b7bcfaf36deff152e34fd250034a200c75f94`.
Five recorded Windows comparisons remain component evidence. This review adds
zero fresh Windows observations and zero whole-PE pairs. Historical Windows
process timeouts remain unresolved.

## Heap PTD view and original setter connection

The component now executes the original null-FLS getter branch through the
FlsSetValue wrapper, including sentinel publication, allocation, PTD publication,
rollback, cleanup thunk and LastError restoration. Getter and setter share the
same wrapper lowering, with distinct original bytes, resolver indices, cache
cells, symbols and stdcall argument sizes. The setter preserves the supplied
nonzero BOOL value rather than manufacturing a Boolean return register.

`CrtHeapPtdAllocation` is a non-Clone ticket issued before the protected allocation
call. It records runtime identity, the current fiber/slot generation and every
already live allocation. After a validated return, its consumer requires the
returned root to be a new, live, unassigned 40-byte heap allocation whose complete
contents are known zero. The resulting view retains the original Buffer pointer,
capability and allocation owner. No pointer is relabeled, copied or converted
from an address integer. A caller cannot provide its own before-set.

The view gives no permanent zero-value promise. Original aliases can write the
object, including making bytes unknown; subsequent reads see those effects.
Publication is scoped to the same live fiber/slot. Dispatcher access requires
actual successful publication. Allocation free or slot retirement removes the
view; stale capabilities and tickets, reused slots and foreign runtimes reject.
A live PTD view also cannot be claimed as a FILE buffer.

The native test executes the original allocation thunk and the existing decoded
calloc body, with explicit heap availability/new-handler/errno inputs. It also
executes the original free thunk; the free body remains an explicit checked
effect callback. It requires the allocation to have actually retired on a
successful free callback return. An unexpected failure preserves earlier writes
and publication/rollback effects. FlsSetValue failure makes slot knowledge
unknown: its public BOOL contract does not prove failure atomicity. A later
successful rollback can establish null; a failed rollback cannot.

Primary contracts remain [FlsSetValue](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flssetvalue),
[HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
and [calloc](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/calloc).
The PTD role restrictions describe this checked component domain, not restrictions
on arbitrary Windows FLS values. Backend BOOL/LastError outcomes, initial slot,
module/export acquisition and stationary fiber state are still explicit inputs.

Seventeen allocation/view cases and fifteen connected lazy-path cases cover
success, sentinel failure, allocation failure, publication and rollback failure,
missing/free failure, existing/truncated/unknown allocation returns, alias writes,
foreign tickets, stale slots/fibers/modules, changed guard, unknown word reads,
replay and effects before failure. Every original setter-byte mutation rejects
before emission. The retained-artifact runner additionally compares setter and
both thunk byte strings and fallback imports to the unchanged PE. These are
native component cases, not new original-Windows observations or whole-PE pairs.

The prior pinned workflow failed after its full CRT test suite passed because
the component runner retained an eleven-test assertion after a twelfth test was
added. The replacement requires actual named completion rows and a consistent
successful libtest summary; independent tests reject missing, ignored, failed,
duplicate and inconsistent results. Evidence and the distinct unresolved original
Windows helper timeout are preserved in [ci-db4fc00.json](evidence/ci-db4fc00.json).
A fresh replay verifies the correction; it does not diagnose that timeout.

### Next connected gate and Sol review scope

Sol can review the ticket/view lifecycle, wrapper ABI, actual original control
flow, strict failure assertions and exact commit CI. Inspect the checked effect
boundaries rather than treating their Rust types as proof of external behavior.

Next, carry the lazy producer through the pending-event/common-handler adapter
under explicit allocator and setter contracts. Replace its current cached-only
getter boundary without synthesizing a non-null PTD or known offset32. The new
lazy source is intentionally separate from the existing ordered handler emitter;
the latter still rejects a null slot. Close original free body 0x407d50, allocator
new-handler/errno recursion and required-getter termination 0x4077ff before calling
those paths fully supported. Actual FlsAlloc/fiber initialization, loader effects,
TLS fallback, delivery/record predicates and incoming-chain containment remain
open. No whole-event acquisition certificate or full startup/rcedit admission is
created by this change.

The concrete free-body follow-up is not a guessed unconditional deallocation:
0x407d50..0x407d8a tests null, calls HeapFree through IAT0x415098, and on a false
result calls GetLastError, error mapping 0x407c12 and errno accessor0x407ccd before
returning normally. The current component's checked free callback admits an
actual retirement or rejects; it does not yet admit that normal-return failure
path. Closing it requires an owned HeapFree outcome and justified failure
lifetime/errno effects, not treating function return alone as proof of free.

Validation: 228 CRT tests, 175 root tests, all-target Clippy and formatting pass;
Python discovery runs 60 tests with one existing skip. Final retained-artifact
replay passes five recorded Windows wrapper comparisons and 76 ordered cases,
plus 17 view and 15 lazy-path native cases. The separately generated lazy source
SHA256 is 5df4f407b8576df823ca4181f62eeca656f257d46180ee99672c88e8130428fa;
wrapper Rust SHA256 is c80246b200b7e172221f982424c4e93c627c361866705a426db19b921282fe3d.
The unchanged PE SHA256 remains 1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4.
[Machine-readable evidence](evidence/heap-ptd-view.json) records counts, bindings,
remaining cuts and test-development corrections. No fresh Windows observations
or whole-PE comparisons are added by these local runs.

## Common handler with the live lazy PTD producer

Independent review of 1788a76 found no heap-view identity or stale-count gate
regression. All three workflows completed successfully: 40995444671,
40995440369 and 40995440136. Those results do not diagnose the preserved Windows
timeouts or turn retained component observations into full startup execution.

The shared common-dispatcher lowering now supports a checked whole-PTD producer
at its original call boundary. It requires a completed protected child return,
the exact returned EAX value, and a live published PTD root before the original
PTD reads execute. The original prefix, dispatcher, metadata and context checks
are reused. Cached-only and generic-lookup modes retain their existing contracts.

A 24-case native composition starts from null FLS and executes the original lazy
getter, setter wrappers, allocation/free thunks, common dispatcher and return.
Success requires a newly published heap Buffer capability distinct from the
old supplied ThreadData object. Its actual offset32 value drives the dispatcher;
the cases include both known values and an unknown-bit rejection. Negative cases
cover stale slot/module/context/allocation, cross-fiber access, changed guard,
failed publication, premature provider return, mismatched return values, replay
and retirement between production and consumption. The allocator availability
and zeroing and the setter/free outcomes remain explicit component API effects;
the separate existing lazy-producer test executes the original calloc body.
This component path does not change the pending-event ordered-search adapter.

The shared fixture initially retained a cached-mode replay signature and an
incorrect LastError expectation for a lazy failure before the restore call.
Both test issues were corrected; the runtime's failure ordering was preserved.
The runner now requires the new named test and records 24 native cases separately
from the five retained Windows wrapper comparisons. No new Windows or whole-PE
translation pair is claimed.

HeapFree failure remains a concrete effect-model gate. `Space::heap_free` models
successful retirement or an out-of-domain error; it has no independently supplied
FALSE/LastError outcome. Original free 0x407d50 instead returns normally after
FALSE, GetLastError, error mapping 0x407c12 and errno 0x407ccd. The current lazy
component requires retirement after the free callback and therefore rejects that
unclosed normal-return failure. Removing this check would manufacture cleanup
success. A bounded semantic pass must define live/uncertain allocation authority
for a failed HeapFree, preserve alias and errno effects in original order, and
connect the original body before changing that gate. No failure atomicity follows
from the BOOL result alone. Actual delivery/capture acquisition, incoming-handler
containment, termination and full formatter/exit remain open.

Validation for this connection: 229 CRT tests pass with the observation-dependent
case passing separately in retained-artifact replay; 60 Python tests pass with
one existing skip; all-target Clippy and formatting pass. The unchanged PE hash
remains 1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4.
Final replay passes five recorded wrapper comparisons, 76 ordered cases and the
new 24 common-handler cases. Wrapper Rust SHA256 is
aedf1f817e42f95331861e73866590152796db03de12f68fe597b19af8f63e26.
[Review, component hashes and independent original free inventory](evidence/common-lazy-ptd.json)
record the exact boundary and inputs. Full startup/rcedit remains unsupported.

## Original free failure and pending-event lazy acquisition

This connected component supersedes the preceding cached-only ordered-adapter
checkpoint. It does **not** establish complete startup or rcedit admission.

### Failure ownership and original errno writes

The pinned free body at `0x407d50` executes through the shared checked CPU/memory
emitter. NULL skips HeapFree. Non-NULL requires the exact live Buffer allocation
root, matching process heap, flags zero, and the explicit no-heap-exception
policy. The API outcome is still a supplied component input, not an observed
Windows failure or a native implementation of every Windows heap condition.

[Microsoft's HeapFree contract](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree)
specifies nonzero success, zero failure and GetLastError, but supplies no
unchanged-content/lifetime guarantee for a failed block. Therefore:

- Success retires the allocation and every alias through the existing kernel.
- Failure revokes all CRT dereference/view authority for that allocation while
  retaining the underlying charged allocation. It neither frees/reuses the
  address nor asserts that Windows retained usable bytes. Pointer transport does
  not renew access. This is conservative proof state, not a Windows allocator
  implementation or a claim that its entire heap metadata effect is closed.
- Failure is distinct from out-of-domain rejection. Original instructions call
  GetLastError, the proved original mapper/search with its original table, and
  the original errno router, then write the actual selected owned errno cell.
  UCRT PTD lookup remains an explicit callback here; no shadow errno is created.
- The mapper uses the existing complete instruction/algorithm proof. Its 68-byte
  private scratch extent must be owned and cannot overlap protected activation
  words. Facts in that scratch are forgotten conservatively; later reads cannot
  observe preserved values which the original helper could have overwritten.
- A single-use observation can authorize normal cleanup completion only after
  the original free body finishes its checked return. Unknown LastError,
  interrupted errno acquisition, or a stale errno owner rejects at that point,
  retaining earlier API/errno effects and leaving no completion receipt.
- The lazy caller consumes completion for the same allocation after its own
  protected CALL returns. A prior, different-runtime/thread, wrong-allocation,
  or already-consumed failure cannot satisfy that call. Existing missing-free
  rejection remains; merely returning without a free effect does not pass.

Eighteen native free-body scenarios and ten receipt/ownership scenarios include
NULL, noncanonical true BOOL, error 5/87/UINT_MAX, unknown LastError, stale/interior
pointers, cross-runtime/thread completion, failed/malformed errno lookup,
protected scratch and prior-write preservation. Five additional lazy-producer
scenarios execute publication rollback → original free → original errno write
or rejection. They do not constitute fresh Windows HeapFree failure observations.

### Same pending event, actual original producer

The ordered adapter can now execute its selected C++ handler using the original
lazy getter, setter and allocation/free thunk instructions under the same live
child-delivery lease. It cannot substitute an arbitrary whole-PTD return: the
adapter invokes `cxx_lazy_ptd_required` itself. Backend inputs remain restricted
to resolver/API, setter outcomes and allocation/free effects. Generated names
separate this call graph from the retained cached path; original bytes and targets
are unchanged and checked by the reproduction harness.

Eight additional ordered cases bring that component to 84. They cover actual
fresh publication and single-use handler completion, failed publication plus
HeapFree FALSE/errno, unknown PTD reads, cross-fiber authority, capture retirement
during allocation, errno failure after a prior write, a freed allocator result,
and a changed event before receipt consumption. The interrupted registers remain
unchanged. A failed child cannot issue a success receipt or authorize advancement.
The no-read CONTEXT lease still never supplies captured bytes.

### Remaining executable gate and review

Sol can independently review the failure receipt, uncertainty isolation, stack
scratch effect, hard-wired original pending-event producer and exact CI evidence.
Next replace the pending adapter's allocation and UCRT errno lookup callbacks
with their actual original producers. The earlier calloc component currently
requires startup-exclusive initialization authority; it cannot simply reuse an
expired token during a suspended call. Separate justified live-heap allocation
authority from startup-only descriptor construction before composing it here.
Preserve new-handler/recursive errno and required-getter termination rejection.
The lazy-delivery variant deliberately rejects its unbound unwind call; the
existing cached unwind path remains separately supported under its contract.

Actual OS delivery acquisition, incoming-chain containment, collided unwind,
loader/FLS creation, complete formatting/exit and whole unchanged-binary startup
remain unproved. Historical Windows timeouts are not diagnosed by passing CI.

## Reviewed live-heap calloc connection

Sol review of `3c02eff` found the checked failure/quarantine and original errno
store paths consistent with the stated component cuts. Success/failure assertions
remain strict, including rejected allocator results and failed event completion.
The live pending-event allocator now executes the original `0x407cf0` calloc
body and mode getter instead of directly allocating and returning a fabricated
callee result. Shared lowering retains the original arithmetic, overflow check,
retry/new-handler call, HeapAlloc arguments, errno branch and checked return.

`live_heap_alloc_result` requires the established runtime-owned process heap,
known no-exception policy, flags 8 and a nonzero request. It creates only Buffer
allocations. It accepts no initialization token and cannot construct descriptors
or change heap policy. Existing startup-only allocation retains its old token
checks. The generated live calloc also checks the expected heap identity and
rejects descriptor requests before execution. API availability and new-handler
results remain explicit component inputs.

Nine independent native cases exercise success after startup authority ends,
allocation failure, one successful retry, refused retry, arithmetic overflow,
zero request, foreign heap, forbidden descriptor role and missing errno owner.
The ordered component now has 85 cases. Its additional allocation-failure case
reaches the original errno call, rejects with
`pending calloc errno acquisition requires original UCRT producer`, preserves
the FLS sentinel and issues no handler receipt or shadow errno. Existing eight
lazy-event scenarios now run the original calloc body at their thunk target.

### Exact remaining errno producer integration

The UCRT getter at `0x40a332` has a distinct FLS index/global (`0x41c170` versus
C++ dispatcher `0x41c060`) and its own prolog/epilog. `crt_ptd::source` currently
calls `ptd_prolog`/`ptd_epilog`, whose `CrtPtdFrame::write_fs` updates a local view.
That is insufficient during suspended-call delivery, where the child registry
owns the canonical ordered thread chain. Supplying a new root token or reusing
the C++ slot would invent authority.

Next bind that original getter's actual registration and retirement to the live
child epoch and canonical head, then route the original errno accessor through
it. Preserve the checked parent suspension and captured/delivery distinction.
Acceptance must execute cached UCRT PTD lookup and its original epilog on the
same event, verify restored head/stack/errno cell, and reject wrong FLS owner,
stale capture, malformed record, replay and failures after registration without
rollback of prior writes. Null UCRT PTD, dynamic backend and recursive allocation
remain explicit rejection until their producers are connected. This is a bounded
Astra ownership question; routine verification/review can remain Sol.

These are connected component results, with no added Windows observations or
whole-PE pairs. Full startup/rcedit remains unsupported; historical Windows
process timeouts are still unexplained.

### Registered UCRT errno acquisition

The original getter at `0x40a332` now has a registered lowering. It executes the
same decoded getter, FLS thunk, prolog and epilog; FS writes update the live
`NormalCallEpoch` through `CrtCxxChainBinding`. The adapter obtains its predecessor
from the canonical registry, retains the delivery lease, installs the actual
stack record and retires it only after the original epilog. No synthetic root or
C++ FLS slot supplies UCRT authority. The legacy standalone getter remains an
explicit component interface.

The original pending allocator and free failure paths now call the original
errno router and this getter. Allocation failure writes 12 to the actual UCRT
PTD field, then the original lazy producer resets its C++ FLS sentinel to zero
and reaches the still-unbound required-PTD termination call. Failed HeapFree
executes the original mapping and writes 13 through the same getter. Quarantined
allocation identity and prior effects are preserved. The subsequent setter
invalidates cached errno authority; it does not undo the actual field write or
create a shadow errno. These failures issue no handler success receipt.

The allocator callback now receives the existing delivery epoch by mutable
reference through the original dispatcher/provider path. It cannot create an
epoch or substitute a returned whole-handler result. UCRT global `0x41c170`
and slot 4 in the conformance inputs remain distinct from C++ global `0x41c060`
and slot 3. The numeric test indices are input examples, not implementation
constants; slot identity and the original module-cell index must agree.

The connected execution exposed ordinary pointer data left in a reused stack
word by an earlier completed call. Registered zero-local prologs may overwrite
ordinary data only after checking the complete new extent against canonical live
frames, delivery bounds and predecessor order. Every reused word is written by
the original prolog before use. Protected returns, saved opaque state and thread
head tokens still reject; legacy standalone helpers retain their stricter empty
storage check. No unknown byte is initialized by this preflight.

Sixteen independent native cases cover successful errno routing, retired/reused
slots, cross-fiber access, retired PTD storage, wrong index, null PTD, stale epoch
and event lease, protected-word collision, ordinary data reuse, interior aliases,
prior writes followed by lazy failure, record corruption, replay, nested frames
and stale nested owners. Getter-byte mutations and truncation reject at lowering.
The replay harness requires named successful test completions and a consistent
summary for this and the existing delivery tests.

Remaining supplied inputs: initial UCRT PTD allocation/initialization and FLS
binding, loader/module effects, physical API outcomes and actual Windows delivery.
A null UCRT slot still reaches unbound `0x40a1ee`; dynamic FlsGetValue2 remains
unbound. Required C++ PTD termination at `0x4077ff`, new-handler/recursive errno,
exceptional lazy unwind and whole startup remain separate gates. The next
connected executable boundary is the original required-PTD termination path,
with signal/lock/exit effects explicitly proved or rejected. Sol can independently
review this integration and inventory that path before any further escalation.

Validation and hashes are recorded in [registered UCRT evidence](evidence/registered-ucrt.json).
All new cases are native component checks, with no new Windows observations or
whole-PE pairs. Full startup/rcedit remains unsupported and historical Windows
timeouts remain unresolved.

### Reviewed registry and connected abort caller

Independent review of `7f206c2` checked canonical-head preparation before data
reuse, actual prolog/epilog effects, epoch forwarding and all sixteen strict
ownership cases. No defect was found in the admitted cached UCRT lookup domain.
Its initial PTD/FLS state and Windows delivery remain supplied. All three
`abb3744` workflows completed successfully; the `7f206c2` original-Windows jobs
passed while its Linux jobs were still running at this checkpoint.

Pending required-PTD failure now executes the original CALL at `0x4077ff` and
complete signal-query caller `0x40cbcf..0x40cbf6`. These bytes are checked against
the retained unchanged PE before replay. At `0x40cbef` the caller passes two
initialized lock-index words (both 3), a pointer to a genuinely unknown byte,
and ECX pointing to that byte. The callee uses RET 12. Original LEAVE/RET and
protected CALL handling retain the observed argument cleanup and saved state.
No unknown byte or callback address is replaced by zero.

The connected pending path rejects at the actual target `0x40cafd`. Eight native
component scenarios independently exercise zero, nonzero and unknown query
results, prior writes before failure, protected-frame corruption, wrong RET
cleanup, missing protected return and the real entry-to-query rejection. Positive
cases require actual return and saved-state restoration; failures require exact
errors and preserved prior byte writes. Query outcomes in these standalone cases
are explicitly supplied test callbacks, not an implementation of the locked
query. The production pending adapter supplies only a rejecting query boundary.
Entry/query byte mutations reject; no generic decoder policy was expanded.

The next connected helper is now precisely `0x40cafd`: original EH4 registration
(allocation 12, scope `0x41b740`), global lock acquire `0x40bdcf` with index 3,
module cookie and encoded signal cell `0x41d2d8`, ROR decoding, finally/unlock
`0x40cb59` → `0x40be17`, and original RET 12. The initialized lock words are not
proof that the lock ran. After that, signal dispatch `0x40cc14`, abort flags
`0x41c128`, processor-feature/fast-fail/reporting and exit status 3/mode 2 still
need explicit contracts. No POSIX signal or normal flush behavior is substituted.
Sol can inspect/implement the bounded registration/lock/query path; escalate only
a demonstrated ownership or exception-effect uncertainty.

This adds no Windows observations or whole-PE pairs. Full startup/rcedit remains
unsupported; historical process timeouts remain unresolved. See
[review and abort caller evidence](evidence/abort-query-review.json).

Code-level prerequisite for that one cohesive helper: instruction `D3 CE` at
`0x40cb31` is ROR ESI,CL. The current scalar IR/emitter has no rotate operation.
Add reusable x86 rotate semantics (masked count, count-zero flag preservation,
CF and count-one OF rules), with independent bit-pattern/count tests, alongside
the helper's checked lock/EH4 lifetime. Decoded numeric bits alone must not grant
function-pointer authority. This is a bounded Sol implementation question; it
needs Astra only if a concrete ownership/exception composition uncertainty arises.

### Connected locked signal query

The pending required-PTD path now executes original helper `0x40cafd` through its
EH4 prolog, indexed global lock 3, cookie/encoded signal-cell reads, ROR ESI,CL,
original finally/unlock caller, registered epilog and RET 12. The original caller
then returns to abort at `0x407804`. The abort TEST/branches, signal dispatch,
reporting/fast-fail and exit remain an explicit rejection; this is not completed
termination or whole-startup support. Initial module, lock and encoded-cell state
remain independently supplied component inputs, not proven startup producers.

Reusable ROR r32,CL lowering reads only the masked five-bit count, preserves
flags for count zero, updates CF, defines OF only for count one, and preserves
SF/ZF. Unknown result bits remain unknown. Numeric decoding creates no pointer or
function capability. Thirty-five bit/count truth-table cases, partial knowledge
and unknown-count rejection accompany the actual ESI use. ESP destinations remain
rejected. Contract reference: Intel SDM volume 2, ROR instruction
(https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).

Twelve independent registered-query cases cover null/nonzero/unknown decoded
values, missing or aliased lock storage, unknown cookie, failure after a finally
write, stale storage, changed scope bytes, nested lock order and a thread change
during cleanup. Earlier writes remain visible; failed cleanup does not retire
the frame or release an unowned lock. Scope bytes are rechecked across body calls.
An unknown-data/proof rejection does not stand in for Windows exception delivery
or automatically run a finally action that the original instructions have not
reached. Those exceptional compositions remain admission gates.

The new thread-change case reproduced a shared global-lock defect: the old
release guard checked token/storage/order but omitted current runtime/thread
identity. A mutant of the old guard released the lock before a later frame check
rejected the context. The corrected guard rejects before release, retaining the
prior write and held lock. The native mutant fails specifically with zero held
locks where one must remain; the current case passes. This fix also covers the
same shared validation used by existing global-lock consumers.

The predecessor PR run `41004981995` has a separately retained original-Windows
`untaken` fixture timeout at job `123897726848`. The log shows a 15-second
`process.wait` timeout, not output/termination success. Imported-launch artifact
`12955196422` has ZIP SHA256
`a1911ff7c4d7c42a5f7fef5eeff78eaf83e88a6e52760f2f0c61610359876f31`.
No root cause or timeout fix is claimed. No retry masks this failure.

Next execute abort's original TEST and branch policy from `0x407804`, proving
signal `0x16` dispatch (`0x40cc14`), encoded callback authority and lock/exception
effects before extending feature/report/exit behavior. Keep nonreturning effects
explicit. Sol review can verify this connected helper and attempt that scope;
Astra is only needed for a demonstrated ownership/exception contract question.
Full startup/rcedit and all historical timeout causes remain unresolved.
See [locked-query evidence](evidence/abort-locked-review.json).

### Original abort branches and exit wrapper

The registered path now executes the original abort TEST/branches from407804.
A nonzero decoded query result pushes signal22 and rejects at actual dispatch
40cc14. A zero result tests the actual module flag byte41c128: bit1 clear reaches
the original exit wrapper407004, while bit1 set pushes feature23 and rejects at
IAT41501c. Unknown query ZF or the relevant flag bit rejects; unrelated unknown
flag bits do not become zero or prevent an otherwise justified decision.

The full exit wrapper executes its original prolog and pushes status3, mode2 and
zero before the unbound shared-exit CALL406e69. No host termination, flush policy,
signal callback or API result replaces that missing contract. The INT29/report
instructions are not lifted as supported execution: the preceding unbound
feature API call terminates this proof domain before either can execute. Each
pruned call always rejects, including the exit wrapper's shared-call boundary.

Thirteen independent native cases check null/nonzero/unknown query results,
known/partial/unknown flags, stale flag storage, a query failure after writes,
missing protected return, thread/process owner changes and closed runtime state.
Original argument words22/23 and3/2/0 are independently asserted. Runtime anchor,
thread, owner and active-call state are rechecked across decisions. Rejection
preserves earlier writes and creates no normal-return or termination receipt.
These standalone branch cases use explicit query callbacks; the connected
pending path continues to use the original registered query producer.

Independent predecessor review reran the old lock-guard mutant, which again
released a live lock before rejecting the changed thread. The corrected twelve
registered-query cases and strict pending cases remain part of replay. A local
test correction handles retirement accurately: after the runtime closes,
ordinary reads reject, so the test inspects retained backing bytes to verify the
prior write. The earlier failed test/replay logs are retained locally.

Next executable gaps are distinct: signal dispatch40cc14 needs its original EH4,
selector, lock/decode and callback/default/ignore behavior; shared exit406e69
needs its own FS frame, lock and exit policy before process effects are bound.
The retained exit inventory shows FS installation, calls401d51/406f55/406cfa/
40be53/40be2e and conditional return/termination paths. That static inventory is
not proof all calls execute in mode2. Freeze the mode2 reachable graph and API
arguments before implementing a process termination backend. Sol can review and
advance that bounded policy/frame scope; escalate only a concrete nonlocal
exception or callback-ownership question. Initial abort flags/module state,
actual Windows delivery and full startup remain unproved.

No new Windows observations or whole-PE pairs are claimed. Full startup/rcedit
remains unsupported and original-Windows timeout causes remain unresolved.
[Branch review evidence](evidence/abort-branches-review.json).

A concrete ownership distinction emerged in the full shared-exit inventory:
406e69 builds an inline FS record at EBP-12 with handler414af3, an explicit
try-level word, 24 local bytes and a cookie, rather than using the proven EH4
helper or the saved-register layout of CrtPtdFrame. Its conditional return
unlinks FS, while the nonreturning process path does not execute that epilog.
Do not relabel this as the existing414ad6/EH4 frame. A bounded Astra pass is
justified if the next step composes this distinct record with the canonical
registry: establish declarative inline-frame ownership, byte image, permitted
return versus terminal lifetime and failure effects, using independent return,
nonreturn and stale-owner cases. Mode2 policy and physical exit effects still
need their own contracts; the inventory alone closes neither.

## Inline shared-exit record and return lifetime

The original abort exit wrapper now calls `0x406e69` under its live pending-event
registry. Mechanical lowering executes the original inline prolog: saved EBP,
level -1, handler `0x414af3`, canonical predecessor, 24 local bytes and the cookie
word. The common 12-byte chain prefix is compatible with registry traversal;
this does **not** identify its handler as `0x414ad6` or grant an EH4 handler proof.
The record is at EBP-12 and the lowest live word at EBP-40, with no helper-style
EBX/ESI/EDI slots. Function, thread, fiber, epoch and delivery-child ownership are
checked at the original FS publication and subsequent effects.

The connected status3/mode2/zero path now reaches the actual managed-runtime query
call `0x401d51`. That call remains an explicit rejection. A separately supplied
nonzero return-mode input executes the other original front branch, initializes
its local pointer tuple and lock arguments, and rejects at manager `0x406cfa`.
Neither missing call returns a fabricated success. Rejection retains the live
registration, protected return and all earlier writes; it is not process exit or
exception cleanup. Original signal22 and feature/reporting paths remain unbound.

The unchanged epilog `0x406f09..0x406f16` is independently executed as a component:
original FS unlink, cookie POP, LEAVE and RET. Retirement requires that RET has
consumed its unique protected token, restored stack/callee state and retained the
same event/owner; a Boolean completion flag is insufficient. Normal epilog does
not check the popped cookie, and the implementation does not invent such a check.
Its tests deliberately mutate that word and still require the original return.
**The body-to-epilog path is not connected yet.** There is no termination receipt
or supported host-exit mapping, and unproved handler/termination effects reject.

Independent coverage contains 20 inline-frame cases and four delivery-child
cases: actual byte layout, nested LIFO returns, original front arguments, unknown
level, changed handler, stale storage/epoch, cross-thread/fiber/process access,
wrong stack, premature/fabricated retirement, replay, and failure after unlink.
The connected pending lazy-PTD cases additionally require the actual live
`0x414af3` registration before their rejection, not merely an expected error string.
All 131 one-byte mutations of the three bound instruction regions reject.
The replay verifies these bytes against the unchanged PE and keeps the five
recorded Windows comparisons separate from native component cases. No new
Windows observation or whole-PE translation is claimed.

Review corrected a transient local continuation literal by deriving the shared
exit CALL's resume address (`0x407015`) from its decoded site. It also strengthened
retirement against a forged `returned` flag with the original token still live.
A generated-test variable typo and missing test-only module gate caused local
compile failures; the retained logs identify them separately from Windows failures.

### Next executable gate

`0x401d51` calls the actual IAT `0x415008`, bound to
`kernel32.dll!GetModuleHandleW`, with NULL. It then reads MZ, e_lfanew, PE signature,
PE32 magic, NumberOfRvaAndSizes and the CLR directory RVA before deriving AL.
The next bounded step needs the main-module handle's checked image-view authority,
header bounds and lifetime, followed by original query execution. Do not substitute
"this fixture is native" for these reads or fabricate an image pointer from a
numeric module handle. Test absent/invalid/truncated headers and stale/foreign
module authority independently. If AL is nonzero, `0x406f55` remains another
loader/managed-termination contract. If zero, the next cut is manager `0x406cfa`.
Actual manager cleanup, exit policy, process termination and handler `0x414af3`
remain open. Sol can review this boundary and inventory the existing module view;
Astra is only warranted if module acquisition/view authority needs a new contract.

A generated-native adversarial mutant removing only the live-return-token check
was compiled and run: the fabricated-return case incorrectly retired successfully
(`Ok(())`) instead of rejecting `inline exit incomplete return`. The corrected
implementation rejects it; the retained mutant log and source hashes are recorded
in [the review evidence](evidence/inline-exit-review.json).

## Checked module-image query component

The original `0x401d51..0x401d93` query is mechanically lowered, including
`GetModuleHandleW(NULL)`, MZ/e_lfanew/PE/PE32/directory checks and AL selection.
A checked image binding requires an existing live executable-module capability,
its full mapped Module root at the same base, process ownership and initialization
authority. Numeric handles, interior pointers and arbitrary subranges cannot
manufacture a view. Every subsequent original instruction revalidates module
and storage lifetime; unload/reload generations and released mappings reject.
Existing memory bounds govern all header reads, including malformed offsets.
Header values remain live reads rather than a cached native/managed Boolean.

The API result is still a **modeled component input**: `Some(view)` selects an
already justified main-image result; `None` models a NULL result. Both applied
results leave LastError unknown because success preservation is not established.
Success borrows existing ownership;
it neither acquires a module reference nor invents loader/TLS effects. The view
constructor does not prove that this module is the process main module. Actual
startup must provide that role and its image mapping before this input cut closes.
The default connected pending path still rejects missing main-image authority.

With an explicit image view, the exit front now executes the query and its actual
AL-dependent caller instructions. Native headers reach manager `0x406cfa` with
original pointer/lock arguments. Managed headers push the actual status and reject
managed termination `0x406f55`. Neither missing callee returns success. Fifteen
independent query cases cover both classifications, malformed/truncated headers,
unknown directory data, NULL results, interior alias, foreign runtime, unload,
reload and released storage. Two additional inline-exit cases exercise both caller
branches while retaining the live registration. All 66 changed query bytes reject.
The replay checks the unchanged PE region and GetModuleHandleW IAT identity.

Lifting required the reusable `CMP r/m16,r16` form alongside the existing word
compare forms. Twenty-four independent native truth cases vary four register
choices and include equality, unsigned borrow and signed overflow, checking that
upper register bits remain unchanged. Local test development corrected a ModRM
literal and an expected unknown-value rejection class; those were test defects,
not reasons to relax the runtime checks.

Next executable gap: establish the startup-owned main-module/image producer so
the pending path can pass this checked view without a supplied role. Then connect
manager `0x406cfa` and its lock/cleanup/error effects. Managed termination,
handler414af3, signal dispatch, physical exit and the full entry-to-exit domain
remain unsupported. This component does not add a Windows observation or a whole
PE comparison. Historical Windows timeout causes remain unresolved.

Contract references: [GetModuleHandleW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew)
(NULL names the calling process executable; the returned handle does not add a
reference) and [PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
The current runtime module model represents owned acquisitions. Actual bootstrap
therefore still needs a distinct process-owned main-module lifetime and mapped
image authority, rather than a fabricated LoadLibrary acquisition. That ownership
extension is a concrete bounded Astra question after Sol reviews this component.

## Canonical process-owned main image

Runtime bootstrap now creates one canonical process-image mapping and capability.
`bootstrap_main_image` requires live initialization authority, maps the supplied
input-image bytes, and publishes the process identity only after mapping succeeds.
Duplicate issuance, overlap, invalid extents and stale initialization reject.
The canonical runtime field owns the mapping; image views retain its exact identity
and bounds rather than copying bytes or borrowing an acquired-module reference.

The main-image lifetime is process-wide. Thread/fiber changes and nested delivery
retain it; process closure, foreign owners, released storage, changed generations
and altered view ranges reject. Ordinary acquired references at the same base have
separate receipt lifetimes: releasing them cannot retire the process image. A
GetModuleHandleW query borrows this authority without adding a reference. This bounded bootstrap maps an immutable readable image: writes reject; writable
PE sections still require separate ownership composition. The existing LastError
knowledge/failure-order contract is preserved.

The default shared-exit front now selects the canonical process image when bootstrap
has installed it. Native and managed header cases reach their original manager and
managed-termination boundaries without a separately supplied image-view argument.
The four pending-delivery lifetime cases also retain process authority across child
completion or failed event ownership, while stale child authority still rejects.
Twelve new native cases exercise issuance, overlap failure, duplicate publication,
thread/fiber changes, acquired-reference release, closure, foreign owners, released
storage, aliasing, changed headers and generation replay. This is component evidence;
the bootstrap input is a mapped image supplied by initialization, not proof of a
complete Windows loader or actual entry-to-exit execution.

The remaining executable integration is to feed the validated original PE mapping
into bootstrap before existing CRT module/record mappings, without overlapping or
replacing their capabilities. Current generic pending fixtures without that startup
producer still reject missing main-image authority. Original manager406cfa,
managed-termination406f55, handler414af3, signal and physical exit effects remain
unbound. Sol can review the canonical lifetime and tests, then inventory the mapping
composition before changing startup emission. Historical Windows timeout causes and
full startup/rcedit support remain unresolved.

## Section-backed PE32 bootstrap

The checked storage kernel now maps raw PE32 input at its declared preferred
base, then the runtime publishes canonical process-image authority. Headers are
read-only, code is read/execute, read-only data rejects writes, and writable data
retains its own capability. Raw bytes and defined zero tails are installed once;
gaps and accesses crossing capabilities reject. Every image region participates
in lifetime validation, so releasing a section invalidates the image view.
Temporary acquired references remain independent.

This is a bounded **initial storage** contract, not a Windows loader or converter
admission certificate. It accepts x86 executable images with standard 224-byte
PE32 optional headers, GUI/console subsystem, 4 KiB section alignment, 512-byte
file alignment, at most 16 sections and the existing 1 MiB storage budget. It
rejects overlapping file ranges/pages, malformed/truncated extents, unsupported
permissions, writable executable sections and COFF relocation metadata. Ordinary
PE directories remain opaque: no import, TLS, relocation, load-config or startup
effect is inferred. Discardable sections have initial backing; retention after a
Windows loader discard is unproved. Padding outside declared mapped extents is
not admitted. All new regions roll back if any mapping fails; prior mappings and
canonical image authority remain unchanged.

`bootstrap_pe32` integrates this map with the process-image issuer, while
`process_image_pointer` resolves section-backed storage under that live identity.
The original `0x401d51` header query executes against independently authored
multi-section inputs. An optional recorded-input regression also maps the unchanged
authored `unwind.exe`, verifies the query's actual 66 instruction bytes and executes
those instructions against the mapped original headers. Its cookie cell is read
and written through the actual writable section, with duplicate mapping rejected.
These are native component executions; there is no new Windows observation or
whole-binary translation.

Reproduce recorded-input mapping with `W2L_PE_MAPPING_INPUT=/path/to/unwind.exe`
and `cargo test --locked --example crt_stream pe32_sections`. Without that variable,
the independent 29 mapping scenarios and two transaction resource failures still
run. Tests cover partial mappings, permissions, unknown unsupported layouts,
process/thread/fiber/reference lifetime, stale sections, foreign identities,
source mutation after mapping, zero-filled data and preservation of prior writes.
Rollback-removal and writable-code mutants must fail the independent assertions.

The next composition gap is the runtime's FILE array anchor: it is currently
created as a separate mapping before PE bootstrap. A FILE address inside the
original `.data` section therefore correctly rejects overlap. Replace that input
boundary with a checked FILE view of the canonical mapped section, retaining the
same capability and owner; do not remap or copy `.data`. Then migrate cookie and
record initializers to checked section views and execute manager `0x406cfa` and
managed termination `0x406f55` only when their effects are justified. The recorded
mapping regression currently uses a separate test FILE address; it does not close
that startup boundary. Full startup/rcedit remains unsupported.

[Review counts, hashes, mutant evidence and retained limitations](evidence/pe32-section-review.json).

## FILE anchor adopts canonical image storage

`new_initializing_pe32` now creates the checked image mapping before selecting the
FILE array. Its FILE view is bounded to a single writable section, shares that
section's capability and bytes, and becomes the runtime anchor without a second
mapping or copied `.data`. The process-image root remains the original header
mapping. No constructor grants lock construction, descriptor handles, locale
initialization or successful CRT startup.

The FILE role is checked separately from the underlying section role. Scalar
reads/writes through either alias obey the same record bounds, lock requirements,
opaque critical-section protection and typed pointer fields. Otherwise a module
alias could bypass the FILE policy. Image identity/lifetime validation uses range
identity rather than pretending to access all FILE bytes under a lock. Separate
legacy FILE mappings retain their existing lifecycle; initialization may validate
an array's extent without performing a cross-record scalar access.

Twenty native scenarios exercise constructor failures for read-only/code/header
storage, incomplete/unaligned/wrapping arrays, invalid counts, stale/replaced or
foreign mappings, cross-thread initialization, closure, narrowed/one-past views,
failed/partial lock construction, alias writes and lock lifetime. A successful
unmodified baseline precedes alias-bypass and stale-initialization mutants, which
must fail the corresponding assertions. The full suite caught two regressions in
the first implementation (separate FILE maps and initialization extent checking);
those failures are retained locally and the corrected full suite passes.

The recorded authored PE now also uses its actual FILE address `0x41c080`, three
records, and its existing writable section. A field write is visible through both
roles and the original header query returns after initialization ends. This is a
native component check, not original-Windows FILE/startup execution or a new whole
PE translation. The standard replay invokes both the raw mapping test and FILE
view regression with strict named completions.

This closes the separately mapped FILE anchor input described above. Next migrate
the cookie and startup record producers onto canonical section views, preserving
original writes and lock/API effects instead of overlaying mapped bytes. The
original manager `0x406cfa`, managed termination `0x406f55`, actual delivery and
physical exit still need justified effects and connected execution. Full startup/
rcedit remains unsupported. [Review evidence](evidence/image-file-anchor-review.json).

## Cookie stores and original record initialization share mapped data

The new cookie component lowers the original 75 bytes at `0x401b71` with the
shared instruction emitter. Entry checks validate active return authority, the
canonical process image and actual live code bytes. Existing nondefault cookies
with a nonzero high word follow the original branch and write their complement
to `0x41c040`, separately from the cookie at `0x41c000`. No adjacent-word assumption
or copied cookie state is introduced. Unknown cookie bits reject; returned
activations reject before executing the body again.

The default-cookie and zero-high-word paths reach the actual direct call to
`0x401b24` and reject as **cookie entropy producer unbound**. No entropy value or
successful API result is substituted. The retained failure state includes the
original pushes of ESI/EDI and leaves cookie/complement writes unapplied. This is
an unresolved-call component boundary, not a supported original execution result.

A connected recorded-input regression uses the unchanged authored PE, actual FILE
array and canonical data section, then follows the original normal record helper
and checked epilog against the same cookie cell. The successful path deliberately
supplies an independently established cookie; it does not claim its entropy
producer ran. Corrupt cookie/guard values and released storage reject with exact
expected errors; normal retirement makes the record authority stale. Seventy-five
single-byte code mutants reject at proof construction. Eight connected scenarios
and eight independent input classes retain unknown/default rejection, complement
writes, relevant arithmetic flags and replay protection. Two full-suite tests
require recorded artifacts and run separately in replay; the ordinary suite does
not silently count them as executed.

The standard replay binds the cookie initializer bytes to the original PE and
compares their hash across hosts. Five retained Windows comparisons remain wrapper
component observations, not new Windows cookie/startup executions or whole-PE
pairs. A successful current native baseline precedes a removed-entry-check mutant;
that mutant fails at a late repeated-return error instead of the required entry
rejection. [Review evidence and hashes](evidence/cookie-record-review.json).

This advances actual storage composition: FILE, cookie, complement and original
stack records now coexist with one mapped image rather than overlaying cookie
maps. It does not connect all original process entry instructions. The next
executable gate is the 77-byte entropy helper `0x401b24`: XORPS/MOVLPD zero the local
FILETIME, then imports at `0x41502c` (GetSystemTimeAsFileTime), `0x415028`
(GetCurrentThreadId), `0x415024` (GetCurrentProcessId), and `0x415020`
(QueryPerformanceCounter) contribute actual outputs and a guest stack address.
Close output-buffer initialization, return/error effects, logical guest versus
host identity and nondeterministic acquisition contracts before binding that call.
Do not replace them with recorded entropy. Original startup `0x40161f`, manager
`0x406cfa`, managed termination and delivery/exit gates remain. A bounded Astra
semantic pass is useful for those acquisition/identity contracts; routine review
and CI can stay on Sol. Full startup/rcedit is still unsupported.

## Default cookie helper executes under explicit acquisition inputs

The 77 original bytes at `0x401b24..0x401b70` now lower through the shared graph,
CALL/RET machinery and canonical mapped stack/image storage. The connected
initializer calls this body, executes its XOR/mixing instructions and repair
branches, then writes the original cookie and complement cells. Each successful component
case feeds those same bytes into the original registered normal-frame prolog,
checked epilog and retirement; it does not replace the cookie before that cycle.
No expected
cookie, observed process result, or helper-answer callback is emitted.

The bounded SIMD addition is legacy same-register XORPS and memory-store MOVLPD.
XORPS defines all 128 bits without changing flags; MOVLPD writes the low 64 bits
and leaves the register unchanged. Unknown XMM bits stay unknown, calls carry
actual XMM state, and bound external API calls clobber volatile XMM state. This
execution cut presumes enabled SSE/SSE2 and committed, fault-free owned stack;
it does not certify OS exception behavior for a disabled SIMD facility. Complete
range, permission, tag and ownership preflight precedes either 32-bit word write.
The store cannot overwrite a protected word in the upper half after changing the
lower half, or carry pointer authority through vector bits.

The API adapter validates a live initialization token, canonical process image,
process/thread owner and complete local output range before requesting data.
FILETIME and counter outputs must be eight-byte scalar pairs below the original
saved EBP and above the active call arguments/return. A callback cannot turn an
invalid output pointer into a successful observation. The original saved EBP,
callee-saved registers, return token and stack cleanup still have to validate.

The four import identities are extracted from the unchanged PE, compared to the
bound targets, and included in cross-host provenance. Primary Microsoft contracts
were read on 2026-10-30:

* [GetSystemTimeAsFileTime](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime): writes a FILETIME UTC value; no return value.
* [GetCurrentThreadId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid): thread identifier remains unique system-wide during that thread's lifetime.
* [GetCurrentProcessId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid): corresponding process-lifetime uniqueness.
* [QueryPerformanceCounter](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter): writes the counter on success and returns nonzero; documented XP-or-later valid-parameter calls always succeed. This is a contract premise, not XP compatibility evidence.

The QPC contract does **not** promise the exact BOOL value 1. Its return bits stay
unknown in this domain; the original helper overwrites EAX before reading it.
The API's undocumented LastError effects also stay unknown. An acquisition error
rejects this bounded component; it is not an emulation of Windows FALSE with an
invented initialized counter. Earlier original writes remain visible: FILETIME
is zeroed by original MOVLPD before time acquisition, and a later counter failure
retains the time and mixed-ID local while the counter words remain uninitialized.

**Acquisition remains an explicit input boundary.** `CrtEntropyInputs` validates
ownership of supplied numeric process/thread IDs, but does not prove their OS
provenance or system-wide uniqueness. The backend supplies individual FILETIME
and counter observations; no native clock/ID producer or fresh Windows entropy
observation is claimed. This closes the connected original helper execution and
buffer effects, not the actual production acquisition contract. The earlier
unbound entry still rejects default-cookie initialization; only the explicitly
parameterized component can execute this path. Full startup/rcedit remains
unsupported.

Validation adds 16 original-helper/initializer cases, nine output API boundary
cases, and 33 independent vector-register/payload/permission/partial-initialization cases.
Every one of the 77 helper bytes and twelve import identity mutations rejects.
Inputs cover both cookie repair branches, multiple stack addresses, upper/lower
64-bit contributions, acquisition failures, cross-runtime/thread identity,
expired initialization, released storage, replay and argument aliasing. Five
recorded Windows wrapper comparisons remain component evidence; there are no new
Windows entropy observations or whole-PE pairs.

The existing nonlocal context certificates do not include SIMD state; these new
instructions do not grant exception-path or SIMD context-restoration admission.

Next establish an actual runtime process/thread ID binding and runtime time/counter
acquisition, with independent conformance evidence and a declared target profile.
Do not cast internal capability IDs to Windows identifiers or hard-code samples.
Then connect startup `0x40161f` to this producer and the registered manager. Actual
loader, delivery/collided-unwind and physical-exit contracts remain open. Sol can
review this slice and its checks; producer identity/clock provenance is the next
bounded semantic question if escalation is needed.

Independent mutation removed complete-pair preflight while preserving the later
word-store checks. The baseline rejected without changing the low word; the
mutant rejected only after changing it, and the independent nonmutation assertion
failed. Logs and source hashes are retained in cookie-entropy review evidence.

## Native Linux cookie acquisition connected

`CrtNativeEntropy::acquire` now obtains the host PID from `std::process::id` and
TID from the calling thread's `/proc/thread-self` link. It binds both to the live
initialization token, canonical image/anchor, logical owner/thread and Rust host
thread identity. Every bound API call validates the binding, live initialization,
current PID/TID and current Rust thread before observing clocks or returning IDs.
Reusing a backend on another runtime, host thread, after initialization, or with
changed numeric inputs rejects. Supplied-input tests still use their explicitly
named backend; they are not counted as runtime acquisition.

The supported profile is one guest process executed in one native Linux process,
with a trusted mounted procfs exposing `/proc/thread-self` (Linux3.17 or later),
stable PID namespace, and an OS/Rust monotonic clock. IDs are native namespace
IDs, not internal capabilities cast to numbers. This does not define guest
process spawning, fibers, cross-process sharing or Windows system-wide numeric
identity. No Windows host implementation is provided by this producer.

SystemTime is converted to FILETIME using the1601-to-1970 epoch offset, checked
100ns arithmetic and truncation of sub100ns precision. Times before1970 and
numeric overflow reject this bounded profile. The performance-counter input is
elapsed nanoseconds from a single process-local OnceLock Instant origin. It is
only admitted as an entropy input: no generic QueryPerformanceFrequency,
Windows boot-epoch, cross-process timing or suspend-equivalence claim follows.
Clock reversal or range overflow rejects. Wall time may move backwards and the
tests deliberately do not require it to be monotonic. No entropy-strength or
cryptographic unpredictability claim is made.

Primary references checked2026-10-30:

* [Linux proc thread-self](https://man7.org/linux/man-pages/man5/proc_thread-self.5.html).
* [FILETIME units and epoch](https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime).
* [Rust Instant guarantees and limitations](https://doc.rust-lang.org/std/time/struct.Instant.html).

The original77-byte helper and initializer execute with these actual acquisitions,
then their resulting cookie feeds the original registered-record prolog/epilog
on the same mapped bytes. A future-origin clock fault injection rejects at the
actual counter call after earlier original effects; it leaves the default cookie
unchanged. Cross-thread use, cross-runtime reuse, changed IDs and expired
initialization reject. Independent tests cover UTC epoch conversion, sub100ns
truncation, overflow and malformed/mismatched procfs identities. Existing checked
buffer/partial-write/failure tests still apply before backend observations.

This is Linux native component execution using unchanged authored PE slices, not
an unchanged-binary entry-to-exit result or a new Windows entropy comparison.
Replay reports one native runtime cycle on Linux and zero on Windows explicitly;
those counts are not compared as Windows/ELF pairs. The generated Rust remains
deterministic even though its runtime observations vary. Next connect the actual
startup40161f call sequence to the acquired producer and existing canonical
manager/locale/FILE state; loader, actual delivery and physical exit remain open.

## Original entry through startup processor query

The ten original entry bytes at4017a4 now execute CALL401b71 and JMP40161f through
shared emitted control flow. `startup_connected` verifies the mapped PE's actual
entry RVA, executes the connected cookie producer, and binds startup's original
20-byte EH4 allocation and scope41b238. Its actual PUSH/PUSH/CALL sequence runs
original helper401e60 and publishes the record in the canonical live registry.
It then executes PUSH1/CALL401945, that initializer's own saved-EBP/argument
branch, and CALL401ea5 with separate protected activations.

The executed CPU-initializer prefix ORs bit0 of canonical41c058 and writes0 to
41ccb8, then PUSHes10 and reaches the actual indirect API call at401ebe. Import
41501c is independently bound from the PE to KERNEL32!IsProcessorFeaturePresent.
This call remains explicitly unbound and returns an error with the original call
slot/arguments, installed startup record and earlier writes retained. No API
result, CPUID register values or successful initializer return is supplied.

The entry-shim return is a **component cut at40161f**, with the root CPU still
active. It is not a program return. A separate connected case executes both
regions without externally changing registers between them; Linux uses actual
native entropy acquisition there, while Windows uses the explicitly scripted
backend. Both stop at the same unbound query. The root activation/committed
stack and incoming thread chain remain fixture premises. Full loader/startup,
exception containment and unchanged-binary entry-to-exit are not established.

All four emitted regions bind their original bytes at compile time and recheck
live canonical code before execution. The prolog helper has its own live byte
check at the original CALL, after earlier argument pushes. A changed helper in
a separately mutated negative input rejects there. The validated image is never
copied into a shadow cookie or frame region. Exact fragments have explicit end
cuts; they are not passed off as closed function proofs. No decoder policy was
weakened to make a fallthrough become a successful return.

Nine cases cover retained original writes, acquisition failure, expired
initialization, stale mapped storage, unknown cookie, actual connected entry,
zero-argument initializer semantics and changed live helper bytes. All81 bytes
of the four regions are independently mutated and rejected by source binding.
Earlier initial test failures revealed an incorrectly constructed closed graph
and two incorrect expected earliest-error classes; those were corrected without
loosening the decoder or lifetime gates. Strict Clippy found a test-only raw-byte
helper dependency in the non-test build; the production source now parses its
own bound literal. Failure logs are retained.

Next close a coherent guest CPU/OS-feature contract for the original401ea5 graph,
not just a success response for the first API. Inventory shows five CPUID sites,
one XGETBV site and multiple scalar feature-cache writes through4021be. Selecting
feature paths must agree with enabled guest SIMD/OS state and supported emitted
instructions. Sol can review this integration; a bounded Astra pass is useful
if the feature model/OS-state relationship needs deeper reasoning. No full
startup/rcedit claim; historical timeout causes remain unresolved.

Primary ABI reference for the unbound boundary:
[IsProcessorFeaturePresent](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)
accepts one DWORD and returns BOOL. This justifies argument transport/cleanup,
not any supplied feature result or proof that the remaining CPU graph is closed.

## CPU classifier observation scope

The next connected boundary is now original CALL40195a to4024ca. The actual
401ea5..4021be classifier executes with coherent checked CPUID/XGETBV observations,
canonical mapped writes and its original RET. See [CPU-FEATURES.md](CPU-FEATURES.md)
for the narrow contract: host observations grant no SIMD instruction admission,
and the production converter still rejects full startup. The prior no-contract
401ebe rejection remains a tested case. Fresh native Linux CPU observations and
native cookie acquisition execute together in one component case; synthetic
feature combinations and five older Windows comparisons are labeled separately.

Review added supported-XSTATE mask validation and explicit code execute-permission
checks. An early generated test used the wrong owner type for a released mapping;
that compile failure is retained. A strict negative expectation was corrected
from the later XCR dependency check to the earlier unsupported-state check;
no production check was weakened. Final evidence records the verified counts,
hashes and limitations. Historical Windows timeout causes remain unresolved.
