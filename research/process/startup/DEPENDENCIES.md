# Remaining entry-to-exit dependencies

Target: the retained, unchanged authored MSVC `unwind.exe` used by
[ENTRY-TO-EXIT.md](ENTRY-TO-EXIT.md), PE SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
This map records connected instruction paths and their supplied contracts.
It is not whole-image conversion evidence. rcedit remains a later independent gate.

| Path | Executed original instructions | Remaining supplied contract / next gate |
| --- | --- | --- |
| Entry and module/thread startup | Selected initialization components | Actual header-entry composition, loader effects, incoming thread/handler chain, module and FLS producers |
| Main, RaiseException, delivery | Main/handler/restore slices and owned activation machinery | Original delivery/context acquisition and incoming-chain containment; no replacement of saved exception context by call registers |
| Normal C++ handler | Prefix414ad6, common403002, thunk403e78, dispatcher403d76, checked context/guard, dynamic PTD/FLS getter and normal epilog form one component path | Bound module/function, live fiber/index/slot and captured delivery inputs. Normal return is ContinueSearch1, not resumed guest execution |
| C++ unwind | Wrapper4041a4/body4041bc register their original EH4 frame, execute state helpers, counter and traversal, and retire normally for state-1; pending actions reach original bridge/notification writes | Original cached PTD getter/FLS is connected; module/export/fiber/slot acquisition remain supplied. A scoped child grant now supports the original body during a pending component exception without unsuspending its parent. Original common dispatcher call403de2 is connected under child authority; original prefix414ad6 is connected under the same child authority; a same-event invocation/receipt now binds supplied captured objects through result consumption; actual Windows delivery/registration selection and exceptional funclets remain unbound; action4026fc reaches unbound terminate40770c. See [component contract](CXX-UNWIND.md) |
| Required-PTD / terminate / abort | Static targets and original normal getter null/sentinel branches are bound | Required-PTD null reaches4077ff. This needs signal query40cbcf/40cafd, lock/EH4 effects, encoded signal callback, flags41c128, signal22, fast-fail/debug and exit effects; never substitute successful cleanup |
| printf and output | Wrapper/accessors, owned FILE/lock, low-I/O and writer components | Actual locale/FILE initialization, complete formatter driver/parser/destruction, callback/exception paths and physical stream composition |
| Return and exit | Main report/epilog and shutdown components | Original exit registrations, flush/close/error/status and process termination from the same live entry state |

## Current acceptance evidence

The common-handler path removes its synthetic PTD backend callback: fixed Cached
access reaches the actual getter and checked FLS slot without an initialization
lease or loader callback. Twenty native cases exercise normal dispositions and
ownership/failure rejection. The retained Windows wrapper comparisons remain
component boundaries. New state helpers add twelve native cases (eight owned
read/write cases and four independent signed-byte/full-word boundaries), with no
new original-Windows observations or whole-PE pairs.

State404406 is written *before* the action in the original loop. A next-state
write is not proof that its action ran. The adapter returns the original register
result only and issues no cleanup, dispatch, restoration or shutdown receipt.
The loop controller must retain the pending old index/action/owner across that
write, then consume it only after justified callback execution or terminal effect.
The current unwind path remains rejected; reading state-1 after a manual helper
step cannot authorize resumption.

## Next cohesive implementation gate

The registered unwind component now has24 independent native scenarios and
original bridge/notification writes. It preserves pending action ownership across
the pre-action state write and rejects at terminate40770c. Empty-state returns
balance the counter and retire the original frame. No cleanup receipt follows
an unexecuted action. Details and supplied-state limits are in
[CXX-UNWIND.md](CXX-UNWIND.md).

The original cached PTD getter is connected with14 native cases. A separate
scoped delivery-child grant now supports its registered body while the interrupted
frame remains suspended (14 ownership cases and four connected original-body
cases). No nested exception or restoration is authorized by child completion.
The actual common dispatcher call403de2 → wrapper4041a4 is connected with eight
additional native cases. The original handler prefix now carries the same child
authority through guard and metadata production (14 more native cases). The
component supplies Windows delivery/registration selection and captured state.
The supplied invocation is now bound to the same pending event and owner, with
full object bounds and lease-bound result consumption (30 native cases).
Close terminate40770c's PTD+12 callback/guard and abort4077ff signal/lock/exit
effects; retain rejection for exceptional funclets until their delivery and
cleanup are justified. Actual delivery acquisition and incoming-chain containment
remain separate gates. This is not whole-PE translation evidence.

The legacy split-head boundary remains reproduced in [THREAD-CHAIN.md](THREAD-CHAIN.md).
The new registered original PTD helper shares the canonical EH4 head, typed
predecessors, full frame bounds and child-lease lifetime. Twenty-four native cases
cover mixed and directly nested registrations, stale/replayed authority, failed
writes and pending delivery. Shared-head success does not derive a selected
handler: existing result receipts identify the interrupted event but not the
executing chain node. Next, bind original handler execution and disposition to
that node before any single-use cursor advance. Keep actual capture/flags,
C++ source activation, borrowed-chain containment and collided delivery explicit.
No whole-image conversion or new Windows observation is claimed.

## Objective whole-program acceptance

One normal converter invocation on the unchanged PE, from its header entry,
must produce deterministic Rust/ELF with no supplied state/result vectors or
skipped startup. Require matching original Windows and Linux stdout, stderr and
exit, artifact/source/toolchain hashes, failure-path checks, and independent
lifetime/alias/unknown-state/cleanup negatives. Passing individual rows does not
establish their entry-to-exit composition.

## CI evidence

The reviewed predecessor `8efaffc` completed all three workflows successfully:
Rust PR40965890530, Rust push40965882528 and pinned startup40965882457.
The earlier `f5cbd05` also completed all three successfully:
40964376142, 40964368746 and 40964368751. These are predecessor results;
new shared-head changes require their own final-head checks.

At the preceding checkpoint, fe0d0dc push run40949077644 attempt1 failed artifact
creation with ECONNRESET, leaving later comparisons skipped. Its exact job/steps
remain in [upload-reset-fe0d0dc.json](evidence/upload-reset-fe0d0dc.json).
Only failed job123714769651 was explicitly retried through GitHub's normal API;
Run attempt2 completed successfully, including rerun Linux job123720191590. This is a labeled infrastructure retry of the *old* commit. It neither
erases attempt1 nor validates newer heads. Historical original-Windows process
exit timeouts remain separate and unexplained.

The executed C++ component receipt now retains proved handler/metadata/dispatch
identity and live owner/frame through single-use consumption (34 invocation
cases). Ordered advancement remains blocked at the earlier EH4 source: the
original empty-scope Search proof returns ContinueSearch, but the native search
emitter requires a GlobalUnwind action. THREAD-CHAIN.md records the exact
reproducer and return-path integration, with no supplied success receipt.

Independent Sol review of214d585 additionally confirmed that generic proved-path
lowering requires a terminal CALL and explicitly rejects RET. The owned-search
CALL cut uses a different storage/lifetime authority from pending normal delivery.
Return-only support therefore needs a verified terminal RET contract and live
normal-frame adapter together, preserving the interrupted source's suspension;
removing the GlobalUnwind check alone is insufficient. See THREAD-CHAIN.md.

## Current return/advance integration

The earlier return-only emitter gate is now implemented as a separate RET
contract and live pending-event adapter. The original EH4 empty-scope search runs
its prefix/helpers/epilog and produces an actual ContinueSearch result. A receipt
bound to that normal registration permits exactly one checked advance to the
predecessor; source suspension and physical thread head remain intact. Twenty-one
cursor cases plus a standalone native return case cover execution and rejection.
See [THREAD-CHAIN.md](THREAD-CHAIN.md) for contracts and limitations.

Next connected gate: invoke the selected C++ registration with its own live owner
and the same search event. The current C++ component invocation accepts a supplied
owner and unwind flags; it must not be relabeled a search-selection certificate.
Actual captured-state acquisition, loader/FLS producers, incoming/collided
semantics and termination stay separate unresolved prerequisites. New evidence
is component execution from retained original bytes, not whole-PE translation.

Validation for the return/advance checkpoint: 223 CRT tests passed (one retained
observation test run separately), 175 root tests passed, and all-target Clippy
passed with warnings denied. The retained-artifact checker passed, including five
recorded Windows wrapper comparisons and all new native cases. It retained PE
SHA256 `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`
and generated harness SHA256
`fe270f49ba9a37241c585bafbc6d6c837e01696a55b3c72effd3da6eeb5256c8`.
These are local component/replay results, with zero new Windows observations and
zero whole-PE pairs. Independent Sol review and new-commit CI remain required.

All three workflows for both reviewed predecessors completed successfully:
214d585: 40971700846, 40971694667, 40971694772;
cfaa71f: 40972514039, 40972507526, 40972507509.
Their success does not explain or erase the historical Windows timeouts.

The selected C++ predecessor is now connected for the tested search domain:
registration/owner/record authority comes from the same canonical chain, normal
captured ESP is refined against the live stack without modifying CONTEXT bytes,
and actual original prefix/common/PTD/RET execution precedes a distinct single-use
selected-node receipt. The 31-case selector includes ten new selected-C++ cases.
See THREAD-CHAIN.md. Remaining producers are actual delivery/capture, module/FLS
acquisition and incoming-chain containment; unbound C++ search backend, other
search dispositions, noncontinuable/nested/collided paths and termination remain
explicit rejections. This closes a connected component path, not whole-PE startup.

Selected-search validation: all 223 CRT tests passed (one observation-dependent
case separately passed), all-target Clippy passed with warnings denied, and the
retained artifact checker passed all 31 ordered cases and five recorded wrapper
comparisons. PE hash is unchanged; current harness hash is in the evidence JSON.
There are zero new Windows observations and zero whole-PE pairs. Review of
4a44eca confirmed eight jobs passed in each Rust workflow, final Linux jobs
123803368463/123803467001 still active, and pinned startup40975183290 passed.
These conclusions do not validate the new changed head or diagnose old timeouts.

Pending-call acquisition now produces record code/flags/zero parameter count from
validated RaiseException arguments on fresh checked storage; all other record and
CONTEXT fields retain unknown/supplied status. The34-case ordered selector checks
producer replay, stale event, initialized storage rejection, unknown-byte retention
and replacement of the produced record. Incoming Owned nodes must still be live
and linked; borrowed or unbound source shapes reject. Registry validation alone
does not acquire incoming handler storage or effects. See THREAD-CHAIN.md for the
remaining nonempty EH4 selection/containment and actual captured-context gate.

| Delivery input | Current producer or remaining assumption |
| --- | --- |
| Record storage | Supplied fresh checked 80-byte region; allocation not acquired here |
| Record code, parameter count | Produced once from the live validated zero-parameter RaiseException CALL |
| Noncontinuable flag bit | Produced from dwExceptionFlags; all reserved/system bits stay unknown until a separate delivered-flags contract |
| Nested-record link | Explicit supplied null input for the existing non-nested domain |
| Exception address, unused information | Unknown; never filled with zero or guessed from CALL PC |
| Saved CONTEXT / ESP | Supplied captured object; exact value/known-mask and identity/lifetime validated. Numeric or unambiguous masked bound observations; no acquisition claim |
| Saved general registers / flags | Never copied from raised-call registers as a substitute for capture |
| Incoming owned predecessor | Must be a live linked registration; handler storage/effects still need composition |
| Borrowed root / dispatcher | Reject without containment proof; no default incoming handler or empty-chain assumption |

Capture-boundary checkpoint validation passed223 CRT tests, all-target Clippy and
retained-artifact replay, including34 ordered cases and five recorded wrapper
comparisons. The observation-dependent case passed separately. Current source
hashes are in the evidence JSON; there are zero fresh Windows observations and
zero whole-PE pairs. The reviewed05fc38c Rust jobs each had eight successes and
final Linux jobs123807523849/123807819719 pending; pinned original-probes job
123806170041 was pending at inspection. Historical timeouts remain undiagnosed.

Epoch-root binding now closes another incoming ownership check: cursor creation
retains the established root, every subsequent transition rechecks epoch previous
head and selected identity, and the predecessor walk must reach that exact live
linked root. The37-case selector adds changed epoch head/selection and retired
incoming owner, retaining record/capture/code/lifetime cases. This is root
attribution, not authorization to run an unknown incoming handler.

The live capture representation now preserves partial known bits and derives only
unambiguous stack comparisons. Normal EH4 and selected C++ original paths share
that view; partial values carry no numeric stack pointer and cannot satisfy the
numeric unwind contract. The source event, object lifetime and exact value/mask
remain checked before effects and receipt consumption. The 47 ordered cases and
independent exhaustive small-bit oracle are described in THREAD-CHAIN.md.

Actual capture acquisition remains open: even the new partial high-bit knowledge
is a supplied component input. The older opaque OwnedEvent predicates have a
different source/lifetime contract. Connecting them requires a same-event,
code/effect observation certificate, not selecting a numeric witness or asserting
unknown high bits. A wholly unknown capture, raw numerical extraction, changed
capture and stale storage still reject. Full startup/rcedit stays unsupported.

Review correction: the argument producer's full ExceptionFlags mask was not
justified. It now produces only known bit0; reserved/system bits stay unknown.
The component explicitly supplies delivered flags0 only after testing that the
partial record cannot bind as a fully known delivery. Code/count production is
unchanged. Compiled proof mutations independently demonstrate detection of both
a removed root guard and the old full-known flag store. Complete flag delivery
and capture remain open effects; no whole-PE compatibility is inferred.

Current review validation passed223 CRT tests, all-target Clippy and full retained
artifact replay, including37 ordered cases and five recorded wrapper comparisons.
The observation-dependent case passed separately. Both independently compiled
mutants were caught by their exact expected assertions. The evidence JSON retains
PE/harness/mutant hashes. New Windows observations and whole-PE pairs remain zero.
Reviewed12e0e22 pinned jobs passed; Rust runs40977516921/40977509102 each had eight
passed jobs and final Linux123811087881/123810696537 still active at inspection.
No failure was observed; passing checks do not explain historical timeouts.

The reviewed 36eeb34 completed all three workflows successfully:
40979161128,40979155479 and40979155599. These are exact predecessor conclusions,
not validation of this changed capture-view head or a diagnosis of old timeouts.

Capture-view validation passed all 223 CRT tests, all 175 root tests, all-target
Clippy and the retained-artifact checker. The observation-dependent test passed
separately. The checker retained five recorded Windows wrapper comparisons and
executed all 47 ordered cases; zero fresh Windows observations and zero whole-PE
pairs are claimed. The compiled upper-bound mutant was caught by the intended
unexpected-admission assertion. Current PE, harness, unwind and mutation hashes
are retained in evidence/cxx-unwind-component.json. No historical timeout cause
was established.

Independent review of 2cc9c77 found no runtime authority defect. Two added strict
cases cover knowledge-mask-only changes and the narrower C++ stack region, raising
the ordered selector to 49 cases. The precise producer/certificate/lifecycle work
needed to remove supplied capture knowledge is specified in
[CAPTURE-ACQUISITION.md](CAPTURE-ACQUISITION.md). Bit-range predicates alone do not
provide that authority; unknown raw capture and unproved effects still reject.

Sol review reproduced six context-proof tests, all 49 ordered native cases and
the full retained-artifact replay with five recorded wrapper comparisons. The
updated capture mutant compiled and failed its intended assertion. There are
zero fresh Windows observations or whole-PE pairs. The reviewed base's 223 CRT
and 175 root tests remain base evidence; this review changes tests and documents,
not runtime semantics. Current harness and mutant hashes are in the evidence JSON.

Acquisition-certificate implementation uncovered and fixed erased pre-selector
CONTEXT/TEB reads in the context-helper proof. Per-path observation validation now
rejects them; the previous decision tree alone was not a no-observation proof.
A separately compiled guard-removal mutant confirms the counterexample. See
CAPTURE-ACQUISITION.md. Whole-event observation composition and the same-event
capture lifetime issuer remain unimplemented; no supplied value gained authority.

Independent review of 72974f0 adds shared-return CONTEXT/FS read regressions and a
compiled bypass-permission-leak mutant; no further runtime defect was found.
Related filter/normalizer/prefix inspection is bounded and grants no whole-event
capture certificate. The original Windows output-probe timed out after 15 seconds
in run40983904709/job123830245636. The diagnostic artifact was uploaded as
12945762783; available logs do not establish original stdout/stderr or root cause.
The evidence metadata is retained in evidence/windows-output-probe-72974f0.json.
No retry or timeout relaxation was used. Historical failures remain unresolved.

Review validation passed all 225 CRT tests, including eight context-proof tests
and the existing 49 ordered cases, plus all-target Clippy. The observation-dependent
test remains separately verified at 72974f0; this test/documentation-only review
adds no generated runtime change or new Windows/whole-PE comparison.

## Connected unknown-context checkpoint

The no-read selector path now executes both original ordered handlers with all
716 context bytes unknown (69 ordered cases, including 20 new lease scenarios).
The event-issued lease binds source CALL, registry/epoch, frame/event generations,
storage capability and exact helper proof. Raw reads/writes reject through aliases;
no numeric ESP or captured-stack predicate is created. Event/epoch failure and
receipt consumption revoke the lease without rolling back previous effects.
See [capture contract and exact remaining gate](CAPTURE-ACQUISITION.md#connected-no-read-lease-current-implementation).

This removes supplied capture **values** from the component path, not its supplied
delivery flags/nested link, incoming root, module/PTD/FLS initialization or complete
API-effect assumptions. A static whole-event observation/producer certificate is
still missing; runtime rejection is not whole-program equivalence. Full startup
and rcedit remain rejected. No fresh Windows observation or whole-PE pair follows
from the 20 new native scenarios.

Reviewed baseline 5615c2b completed Rust40984728593/40984721250 and
pinned40984721318 successfully. For72974f0, push40983899668 and pinned40983899745
passed; PR40983904709 failed the preserved original-Windows output-probe timeout
(job123830245636). That difference does not establish a cause or erase the failure.
The changed lease implementation requires its own exact-head CI.
