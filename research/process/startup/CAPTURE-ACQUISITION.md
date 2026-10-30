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
