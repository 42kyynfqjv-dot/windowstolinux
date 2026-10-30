# Remaining entry-to-exit dependencies

## Current executable checkpoint: protected second-resolver publication

Under the explicitly enabled `w2l-native-second-fiber-20348-2398cc6a-v1`
extension, unchanged entry now executes indexed lock CALL `0x407e92 -> 0x40bdcf`,
original VirtualProtect RW, cache XCHG `0x407ec8`, RO restoration and matching
release `0x407ede -> 0x40be17`. Logical lock14 resolves by its checked address to
owned slot15 in this entry; independent permuted storage resolves it to slot5.
No slot number is substituted into guest registers or original address arithmetic.

The selector returns, its original flag store executes, and the original allocation
wrapper allocates **second process FLS index1**, callback `0x40a100`, publishing
index1 to `0x41c170`. The earlier index0/value remain intact. The exact next stop
is CALL `0x40a428 -> 0x40a332`, registered PTD acquisition context unbound, before
producing its PTD or completing callback7. `0x41e00c` is the original missing-export
sentinel `0xffffffff`, its page is read-only, and the cache lock is released.

[Contract, failure ordering and independent cases](CACHE-PUBLICATION.md).
Default admission still rejects `0x402b00`; no new Windows/ELF or whole-PE pair.
Next connect the actual registered PTD getter using the live startup registry and
existing lazy producer, retaining process-slot/fiber-value/allocation identities.
Sol can review and attempt this connection; escalate only a reproduced ownership
or continuation ambiguity. Older checkpoints below retain historical evidence.

Current checkpoint: explicit extension `w2l-native-second-fiber-20348-2398cc6a-v1`
uses verified x86 KernelBase identity and missing FlsGetValue2/error127. Unchanged
entry publishes the owned module and executes lookup, then rejects indexed lock
CALL `0x407e92 -> 0x40bdcf`. No second index, feature-flag result or function-cache
publication is claimed. Older profile/default admission remain blocked.
[Versioned contract, Windows provenance and tests](SECOND-FLS-PROFILE.md).

Current checkpoint: original callback `0x40a407`, selector and second resolver
execute to `LoadLibraryExW` at `0x407f1d`, first candidate
`api-ms-win-core-fibers-l1-1-2` while resolving `FlsGetValue2`. The explicit native
profile rejects that unproved mapping. Unchanged entry has not allocated its
second FLS index. Seeded cache conformance cases reach actual native allocation
and then reject the registered PTD context boundary.
[Original execution, independent tests and remaining integrated gate](SECOND-FLS-INITIALIZER.md).
Default admission/full startup/rcedit remain unproved.

Current checkpoint: original process-heap callback `0x40c8f0` publishes the same
canonical Space-owned heap proof to `0x41d2c8` and returns AL1. Its original
cleanup clears that cell without destroying the heap. Entry next selects index7
/ `0x40a407`, whose body remains unbound. Allocation policy stays unknown unless
independently established. [Identity, ordering and cleanup](HEAP-INITIALIZER.md).
Default admission/full startup/rcedit remain unproved.

Current checkpoint: original callback `0x401bd5`, the fifteen-record lock loop
`0x40bd8e`, its original tail thunk and checked native synchronization execute.
The next selected callback is `0x40c8f0` (GetProcessHeap via IAT `0x4150f8`),
whose body remains unbound. Count 15 and all locks remain live at rejection.
[Original execution, rollback tests and CI harness repair](LOCK-INITIALIZERS.md).
Default admission/full startup/rcedit remain unproved.

Current checkpoint: the explicit native profile executes original callback
`0x408113`, its `VirtualProtect` call at `0x408129`, original zero/nonzero result
handling and protected return. `.fptable` becomes read-only with canonical mapping
identity; old protection is written to the original stack local. Prior callback,
FLS and lock effects survive. The original loop next selects index 3 / `0x401bd5`
and rejects its unbound body. See [page contract and exact next scope](VIRTUAL-PROTECT.md).
Default admission, full startup/rcedit and Windows failure equivalence remain open.
The checkpoints below retain earlier evidence and are superseded where stated.


Current checkpoint: original16-entry initialization/rollback loop executes with
index/phase/owner-bound callback receipts. Two original callbacks and all five
scalar-store callees execute; the third reaches VirtualProtect408129 with checked
original arguments. No permission/output effect is admitted. Prior FLS, lock and
callback writes remain live. Default admission is unchanged. See
[ordering, negative tests and page-permission architecture gate](INITIALIZER-TABLE.md).

Current checkpoint: original FLS setter/resolver/guard/indirect stdcall8 executes.
The explicit native FLS service publishes opaque41ccc4 for the current stationary
fiber and retains its real process-index/callback identity. Retrieving the value
grants no pointer/PTD authority. Original module initialization returns; the next
explicit boundary is startup initializer continuation40195f, with next inventoried
CALL401967 ->407653. Default admission is unchanged. See
[setter contract, recovery and regression evidence](FLS-SETTER.md).

Current executable checkpoint: with an explicitly enabled native FLS service,
original allocation wrapper/resolver/guard/indirect call and index store execute.
Entry allocates a process index and retains callback ownership, then rejects at
setter `0x402981 -> 0x402bef` before publishing a fiber value. Default admission
remains blocked. [Contract, reproduced stack regression and next gate](FLS-ALLOCATION-WRAPPER.md).
Earlier boundaries below are historical.

Latest follow-up: a real bounded native FLS process-index producer and checked
stdcall adapter now exist, with no supplied allocation outcome. Original entry
executes the FLS initializer through CALL `0x402968 -> 0x402b3e`; its allocation
wrapper/export binding still rejects, so entry has allocated/published no FLS
index. Prior lock/count effects remain. Default admission is unchanged. See
[producer, tests and exact wrapper connection](NATIVE-FLS-PRODUCER.md).

## Latest executable checkpoint: native-profile lock construction

The explicit native profile executes the original guard, indirect synchronization
call, constructor RET and lock-count publication. The mapped lock remains live
with count1 when original FLS acquisition `0x4024d6 -> 0x402963` rejects. Default
admission remains blocked at `0x402b00`. Native fixed storage and checked ABI are
implemented; arbitrary Windows resource-failure correspondence is still unproved.
This is component execution, not whole-PE support. See
[contract, review defect and next scope](PROFILE-SYNC-CALL.md).

The entries below retain earlier checkpoints and remaining independent paths;
older exact stopping addresses are historical, superseded by this checkpoint.

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
716 context bytes unknown (70 ordered cases, including 21 new lease scenarios).
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

Sol review of c3be6ab found no further runtime defect and adds a strict failure
inside the original handler, after a retained write. The same lease is revoked;
no completed receipt or capture value is produced. The next executable gate is
the closed ContinueSearch observation/call summary described in
[the review](CAPTURE-ACQUISITION.md#sol-review-of-c3be6ab), followed by its producer
and API/import provenance obligations. Runtime success does not issue that proof.

## Bound helper composition; concrete producer barrier

The ordered EH4 emitter now composes the actual normalizer, guard/security and
context proofs by target, byte extent, event domain, cookie and scope header,
and emits the callbacks from those proofs. Changed live helper bytes reject.
This closes a source-binding gap, not complete capture acquisition or a
whole-event effect proof. See [the contract and counterexamples](CAPTURE-ACQUISITION.md#callercallee-composition-and-the-remaining-ptd-producer).

With the first handler completed, unknown PTD[32] rejects at original CMP 0x403d9c;
a null FLS slot reaches unbound CALL 0x402906→0x402bef. The next cohesive gate is
that C++ lazy producer's setter/sentinel, allocation/publication/rollback/free,
LastError and termination effects, using the actual module/fiber/slot ownership.
A 40-byte zeroed object must come from the proven allocator. Supplied initialization
and a successful component run cannot discharge those obligations. Full startup,
rcedit and historical timeout causes remain unresolved.

Independent Sol review of 5c9d4c2 found no helper-composition defect. The actual
setter is resolver index 3/FlsSetValue with a distinct TlsSetValue fallback, not
the getter's index 2 contract. A new allocation regression identifies the next
code-level blocker: heap Buffer capability versus rooted ThreadData role. Keep
the same heap identity and aliases through a checked PTD view derived from the
allocator effect; copying/retagging must not create authority. Connect that view
to setter publication/rollback, free and slot/fiber lifetime. See the review in
CAPTURE-ACQUISITION.md and evidence/ptd-setter-review.json. No runtime semantics or
admission expanded in this review.

### Heap PTD allocation/view and lazy setter checkpoint

The allocator's Buffer identity now survives a checked, single-use PTD object
view; aliases share the same storage and lifetime. The native component executes
original getter/setter control flow, allocator/free thunks, the decoded calloc
body under explicit backend contracts, publication/rollback and LastError restore.
Free-body effects remain checked callback inputs. FLS failure leaves value
knowledge unknown, and cleanup failure preserves earlier effects.

The ordered common handler still uses its cached-only getter. Connect the lazy
producer through that pending-event adapter next, retaining explicit heap,
new-handler/errno, setter outcome and module/fiber/slot contracts. Required-getter
termination, free body, actual acquisition and incoming-chain containment remain
unclosed. This checkpoint adds no whole-PE acceptance. See
[the view contract and review gate](CAPTURE-ACQUISITION.md#heap-ptd-view-and-original-setter-connection)
and [preserved predecessor CI failures](evidence/ci-db4fc00.json).

### Checked common-handler lazy producer composition

The original common dispatcher can now call the live lazy PTD producer through
its protected call boundary, validate the actual completed child result and
published root, then execute original PTD reads and return. Twenty-four native
cases cover the composition; initial module/fiber/slot and API effects remain
explicit inputs. The pending-event ordered adapter is still cached-only.

Next close the original free body's normal-return HeapFree failure path with an
owned API outcome and justified alias/lifetime/errno effects. The existing memory
kernel has successful retirement and explicit rejection, not a Windows FALSE
outcome. Do not remove the missing-free check or infer atomicity. Then carry the
producer through the pending-event delivery lease. Details and the predecessor
CI conclusions are in [the common-handler contract](CAPTURE-ACQUISITION.md#common-handler-with-the-live-lazy-ptd-producer).

### HeapFree failure and ordered lazy producer

The original free body, error mapper/search/table, errno router and owned errno
store now compose on declared heap/API/UCRT PTD inputs. FALSE revokes allocation
access knowledge without claiming successful release or unchanged memory; a
normal cleanup receipt requires the actual checked return. Earlier effects
remain when a later step rejects. The ordered C++ handler now invokes the
original lazy producer within its pending-event child lease (84 ordered cases,
eight new); actual delivery is still supplied. No whole-PE acceptance is added.

Next integrate the actual calloc and UCRT PTD producers into that pending adapter.
Its current allocator/errno callbacks are explicit cuts. The existing calloc
component's initialization token is not general live-heap authority; do not pass
an expired startup token through exception delivery. New-handler, recursive errno,
required-getter termination, and lazy-path unwind remain rejected. See
[the connected contract](CAPTURE-ACQUISITION.md#original-free-failure-and-pending-event-lazy-acquisition).

### Original calloc under live heap authority

The ordered lazy path now executes original calloc and its mode getter under a
separate live process-heap contract; no expired initialization token or descriptor
authority is used. Nine independent calloc cases and 85 ordered cases exercise
success, retry/error and rejected ownership. Original HeapAlloc outcomes and
new-handler results remain declared inputs. Allocation failure in the pending
path explicitly rejects at original UCRT errno acquisition, retaining its FLS
sentinel and issuing no success receipt.

Next connect UCRT getter 0x40a332's prolog/epilog to the canonical delivery-child
registry head. Its current local FS view cannot stand in for that ownership;
UCRT and C++ FLS slots remain distinct. Then route both calloc and free errno
access through this producer. See [the exact gate](CAPTURE-ACQUISITION.md#exact-remaining-errno-producer-integration).

## Registered UCRT errno producer (current)

The earlier canonical-registry gate is now connected for a live, already bound
UCRT PTD/FLS slot. Original calloc/free failure → errno router → getter/prolog →
FLS lookup → epilog → field store execute under the same delivery child epoch.
The suspended parent, predecessor order and actual allocation identity survive.
The allocation-failure path now proceeds through sentinel reset to the explicit
required-PTD termination rejection, rather than stopping at an errno callback.
Initial UCRT PTD/FLS creation, null-slot lazy initialization, dynamic getter,
actual OS delivery and termination effects are still supplied or unbound.
See [contract and remaining executable gate](CAPTURE-ACQUISITION.md#registered-ucrt-errno-acquisition)
and [evidence](evidence/registered-ucrt.json). This adds no whole-image support.

## Connected required-PTD abort entry

The null-PTD failure now follows original abort entry4077ff → signal-query caller
40cbcf → explicit rejection at locked helper40cafd. Complete original caller
arguments and RET12 semantics are executed; query results are supplied only in
separately labeled conformance tests. Next bind helper40cafd's actual EH4 frame,
lock3, encoded signal cell/cookie and finally unlock before extending dispatch,
fast-fail/reporting or exit. This is component progress, with no new whole-PE
acceptance. [Evidence and exact next gate](CAPTURE-ACQUISITION.md#reviewed-registry-and-connected-abort-caller).

## Locked query now executed

Required-PTD → abort entry/query → helper40cafd now executes the actual registered
EH4 frame, lock3, decoded signal-cell value and finally/unlock, retiring through
original RET12. Current rejection moves to abort407804's TEST/dispatch/report/exit
continuation. Initial encoded-cell/module/lock state is still supplied, and
proof rejection does not simulate exceptional finally execution. Twelve negative/
normal cases and an old-guard mutant protect ownership and prior effects.
[Current contract and next gate](CAPTURE-ACQUISITION.md#connected-locked-signal-query).

## Abort branches now executed

Original407804 query decision and flags41c128 choose actual unbound signal22
call40cc14, feature23 import41501c or exit wrapper407004. The exit wrapper's
original pushes now reach shared exit406e69 with3/2/0; shared exit itself remains
unbound. Unknown conditions reject, no missing call supplies success, and owner/
lifetime checks preserve prior effects. Next establish the original mode2 exit
policy/FS frame and separate signal dispatch contracts.
[Current branch/exit evidence](CAPTURE-ACQUISITION.md#original-abort-branches-and-exit-wrapper).

## Inline shared exit now reached

Abort's original exit wrapper → `0x406e69` now installs the distinct inline record
under canonical thread/event ownership, then rejects at actual managed-runtime
query `0x401d51` (GetModuleHandleW plus checked PE-header reads). A supplied return
mode reaches manager `0x406cfa` and rejects. The original unlink/LEAVE/RET has
separate native component coverage; body-to-return and process termination are
not connected. Missing effects retain live frames, not successful cleanup.
[Current lifetime boundary and next executable gate](CAPTURE-ACQUISITION.md#inline-shared-exit-record-and-return-lifetime).

## Checked image query available with explicit main-image authority

Original401d51 now executes against a lifetime-bound module image and original
header reads. Supplying the independently modeled main-image role lets shared
exit reach manager406cfa (native) or managed termination406f55; both remain rejected.
The default pending path still lacks the actual startup main-image producer.
[Current checked-image contract](CAPTURE-ACQUISITION.md#checked-module-image-query-component).

The remaining main-image issuer must derive identity and mapping from the loaded
input PE/process bootstrap, bind the complete mapping once per process, and survive
ordinary thread/fiber changes while expiring at process teardown. It must not issue
an owned LoadLibrary reference or permit ordinary FreeLibrary receipt replay to
retire the process identity. Adversarial acceptance should cover duplicate issuers,
foreign/replaced mappings, process teardown, fake main-role assignment and concurrent
owned references to the same module. This is the concrete next ownership contract;
current supplied image inputs do not establish it.

## Canonical process-image ownership implemented

Bootstrap now owns the main-image mapping once per runtime, independently of
acquired-module references. The exit front retrieves that canonical authority;
thread/fiber/event transitions retain it and process closure expires it. The next
input cut is composition of the validated original PE mapping with existing CRT
module/record maps before bootstrap emission, followed by manager406cfa and the
remaining termination effects. [Contract and evidence limits](CAPTURE-ACQUISITION.md#canonical-process-owned-main-image).

## Raw PE sections now compose with process-image authority

`bootstrap_pe32` installs validated initial headers/sections, preserves their
permissions and publishes the canonical process image only after the mapping
transaction succeeds. The original managed query executes against those headers;
recorded authored input also maps without rewriting its bytes. No loader effects
or converter admission are granted. Next replace the separately mapped FILE-array
anchor with a view into the existing writable image section, then migrate cookie/
record views before connecting the remaining manager/termination effects.
[Contract, executable boundary and reproduction](CAPTURE-ACQUISITION.md#section-backed-pe32-bootstrap).

## FILE anchor now shares mapped data identity

The raw-PE constructor now adopts a bounded FILE view inside the existing writable
section; the section capability is also the runtime anchor. The original header
query executes after initialization ends, while FILE/module aliases retain the
same lock, opaque-byte and typed-field policy. No lock or CRT initialization is
inferred from mapped bytes. This closes the separate FILE mapping gap in the
preceding section. Next migrate cookie/startup-record producers to section views
and connect the manager/termination effects. [Contract and rejection boundary](CAPTURE-ACQUISITION.md#file-anchor-adopts-canonical-image-storage).

## Original cookie/record storage composition connected

The original cookie initializer's existing-cookie path now writes the complement
in canonical `.data`; the original record prolog and checked epilog use that same
cookie, mapped FILE anchor and live stack. Successful cases supply an established
cookie explicitly. Actual default input still rejects at entropy helper401b24,
whose four OS acquisition effects and stack-local identity are not implemented.
The next gate is that real producer, followed by startup40161f; no recorded entropy
or initializer success is inferred. [Exact evidence and next contract](CAPTURE-ACQUISITION.md#cookie-stores-and-original-record-initialization-share-mapped-data).

### Default-cookie helper execution connected; acquisition still supplied

The original 77-byte helper401b24 now executes through shared SIMD/scalar lowering,
protected calls, checked eight-byte local writes and original cookie repair/stores.
Successful cases feed the produced cookie into the original registered normal
record lifecycle without overwriting the produced value.
Actual PE bytes/imports bind the component. 16 helper/initializer cases and nine
API boundary cases check strict results; 33 independent vector cases check flags,
unknown bits, register choices and whole-store preflight. Numeric process/thread
IDs and individual time/counter observations remain supplied contract inputs.
No native acquisition, fresh Windows entropy pair or full startup is claimed.
Next replace those inputs with justified live producers and connect40161f; see
[contract and primary sources](CAPTURE-ACQUISITION.md#default-cookie-helper-executes-under-explicit-acquisition-inputs).

### Bounded native Linux identity/clock producer connected

The cookie component can now acquire actual namespace PID/TID and UTC/monotonic
clock observations under a live canonical initialization binding. It executes
original helper/initializer/registered-record instructions with that producer.
Cross-thread/runtime use, changed IDs, stale initialization, malformed procfs
identity and clock range/reversal reject. This closes supplied acquisition for
the declared single-process Linux entropy domain, not general QPC/Windows ID
semantics. Next connect startup40161f's actual caller sequence and remaining
manager/locale/FILE initialization. No new Windows or whole-PE pair.

Original-entry inspection for the next gate: PE AddressOfEntryPoint is4017a4.
Its ten unchanged bytes are `e8c8030000e971feffff`: CALL401b71 then JMP40161f.
The latter starts with PUSH14/PUSH41b238/CALL401e60 (existing normal prolog),
then PUSH1/CALL401945 and tests AL before later startup work. Lift the entry
shim and bind this first initializer outcome from actual code, including its
failure edge40178e; do not jump directly to Main. Root activation, incoming
thread state and remaining initializer effects stay proof prerequisites. This
is a concrete Sol implementation/review scope; escalate a reproduced ownership
or external-effect uncertainty, not routine CI work.

### Entry4017a4 now reaches the original processor-feature call

A connected bounded native path runs the original entry CALL/JMP, cookie producer,
startup EH4 prolog, initializer401945 and CPU-prefix writes. Its first unsupported
operation is the actual IsProcessorFeaturePresent(10) call at401ebe/IAT41501c.
No injected success passes that boundary. Canonical41c058 bit0 and41ccb8=0 writes
survive the rejection. Root activation/incoming chain remain component inputs;
there is no full unchanged-binary entry-to-exit result. Nine cases and81 byte
mutants protect binding/lifetime/failure behavior. Next unify CPUID (five sites),
XGETBV (one site), enabled OS/SIMD state and scalar feature-cache semantics for
401ea5..4021be before binding feature-query results. Full utility support remains
blocked by later initializer, loader, delivery and exit gates.

### CPU observation and classifier return to40195a

- Executed: original entry/cookie/EH4 startup/401945/401ea5, all reachable scalar
  CPUID/XGETBV classifier branches and original RET under checked observations.
- Actual producers: Linux x86-64 CPU/OS queries and prior native IDs/clocks in a
  connected component case. Synthetic CPU profiles remain independently labeled.
- Support boundary: observations are confined to this closed classifier. They
  cannot enable unsupported instructions or authorize later feature-selected
  library paths. Default emitters still reject CPU-query effects without binding.
- First unsupported call:40195a→4024ca, before its lock construction4029b4 and
  FLS acquisition/publication402963. Preserve count/slot/cleanup order when
  connecting these existing ownership components to actual startup producers.
- Still supplied/unproved: root activation/incoming chain, OS delivery and
  containment, later locale/FILE initialization, full formatting and physical
  exit. No full startup/rcedit claim. See [CPU-FEATURES.md](CPU-FEATURES.md).

### Startup module dispatcher and lock resolver prefix

Original entry now reaches402c42→402a53 through4024ca/4029b4/402c2d, retaining
prior cookie/classifier writes and active original frames. No lock constructor
or FLS allocation outcome is supplied on that connected entry path. Separate
component cases execute module/lock/FLS control with explicit observations and
stop before unsupported publication authority. Next: shared dynamic constructor
and FlsAlloc resolver bindings, followed by module-backed bootstrap object41ccc4
and callback4028a7 lifecycle. This object must be distinguished from the recursive
FFFFFFFF marker. See [STARTUP-MODULES.md](STARTUP-MODULES.md).

### Mapped resolver and process-wide FLS index

Original entry now executes402c42→402a53→402af3 and stops at the actual
LoadLibraryExW call402b00/IAT415074. Live code, canonical mapped arguments,
module/export lifetime and cache publication use the shared resolver. Actual
load/API-set/DllMain/TLS effects remain unbound. Component allocation outcomes
now issue a process index distinct from the current fiber value lease; the
original control cases preserve global publication and failure order. There
is no actual FlsAlloc/FlsSetValue producer or bootstrap-PTD publication yet.
See [STARTUP-RESOLVER.md](STARTUP-RESOLVER.md) for evidence, stationary-fiber
limits and the next loader/constructor/bootstrap-object gates. Full startup
and rcedit remain unsupported.

### Resident ordinary-DLL acquisition

Original load helper402af3 now executes its LoadLibraryExW call through a
checked resident-module backend when an explicit initialized ordinary-DLL
process environment is supplied. Reference acquisition and lifetime are real
runtime transitions; missing authority/search/API-set cases reject. The default
original entry still stops at402b00 because api-ms-win-core-synch-l1-2-0 mapping
and initialization effects are not established. Next: justify the system-module
namespace and native export contracts, then constructor/FLS effects. See
[RESIDENT-LOADER.md](RESIDENT-LOADER.md). No new whole-PE support.

### API-set namespace and provider initialization

The default entry remains at LoadLibraryExW402b00. A frozen x86 Server2022/20348
observer now measures contract→load-host→export-host identity and reference
survival, independently of the converter. Missing/ambiguous evidence rejects;
no observation issues native initialization authority. Next: a process-owned,
initialized lock provider with documented ABI/effects and failure-atomic export
publication, then dynamic FLS. See [API-SET-BOUNDARY.md](API-SET-BOUNDARY.md).
This is a measurement gate, not actual acquisition or new PE/ELF evidence.

### Native provider ownership prerequisite

The emitted runtime now constructs a process-owned native provider registry,
separates process roots from acquired references, and keeps load/source ownership
distinct from the target borrowed by a forwarded export descriptor. Pending,
failed, replayed and stale lifetimes reject. Descriptors cannot become callable
or enter a function cache without an implementation issuer; actual native API
semantics and original entry mapping at402b00 remain open. See
[PROVIDER-OWNERSHIP.md](PROVIDER-OWNERSHIP.md). No Windows initialization or new
whole-PE execution follows from registry construction.

### Native synchronization operation

A specific implementation issuer now binds InitializeCriticalSectionEx to actual
owned global-lock construction and a checked RET12 adapter. Native tracking
allocation, opaque object storage, recursive thread ownership, deletion ordering
and provider lifetime are tested. Resource-failure BOOL/LastError effects and
full API-set/system-provider initialization remain unclosed at402b00. See
[NATIVE-SYNCHRONIZATION.md](NATIVE-SYNCHRONIZATION.md); no new Windows pairs or
whole-image admission follow from these component tests.

### Independent critical-section conformance gate

A frozen authored x86 Windows observer and native operation trace now cover two
spin configurations, recursion, deletion/reinitialization and adjacent bytes.
Fresh Windows/native component comparison is a separate CI gate; no runtime
support widening occurs. It cannot close allocation-failure error behavior or
API-set initialization at402b00. See [SYNC-CONFORMANCE.md](SYNC-CONFORMANCE.md)
for the explicit resource-contract decision required before admission.

## Synchronization resource checkpoint

The native global-object map, tracking vector and recursive lease vector now use
fixed 32-slot storage; checked argument/return reads no longer allocate temporary
tag vectors. Allocation-denial and partial-construction tests cover the actual
stdcall operation and failure ordering. This closes native per-call bookkeeping,
not Windows Ex BOOL-zero/LastError equivalence or provider initial state. Original
entry still rejects LoadLibraryExW at0x402b00. See [SYNC-RESOURCES.md](SYNC-RESOURCES.md)
for the exact resource contract and next external-effect decision; no API-set
admission follows merely from fixed storage.

Provider initialization failure evidence is now frozen independently using an
authored rejecting DllMain and accepting control, in a separate Windows job.
This closes no execution gate until measured; failed-load namespace rollback is
separate from rollback of arbitrary initializer effects. Original entry remains
0x402b00. See [PROVIDER-FAILURE.md](PROVIDER-FAILURE.md).

Original ordinary-DLL attach failure is now measured: Windows job124049912153
returned1114 twice with no acquirable failed module; the accepting control
retained/unloaded exactly across its two owned releases. This is evidence-only
progress. No detach/effect trace or system API-set initialization proof was issued;
original entry still rejects0x402b00. See PROVIDER-FAILURE.md and its JSON evidence.

The native synchronization replacement now has a connected construction/cleanup
transaction and actual owned-reference acquisition/release, executing only its
implemented export. This is native component progress; original entry remains
blocked at0x402b00. Windows DLL initialization, error1114 and ordinary final-release
unloading are not substituted by the process-owned native root policy. See
[NATIVE-PROVIDER-INITIALIZATION.md](NATIVE-PROVIDER-INITIALIZATION.md).

### Explicit native synchronization profile reaches the original export lookup

The versioned opt-in `w2l-native-sync-20348-v1` component environment now prepares
its actual process-owned replacement provider before entry. Original instructions
execute LoadLibraryExW402b00, helper return and cache publication41cd0c, reaching
GetProcAddress402ae0/IAT415070. Default admission still rejects402b00. Reference
bookkeeping and loader validation use fixed storage; capacity rejection is an
internal bound, never a fabricated Windows null/error. Future synchronization
failure behavior is a separate API gate rather than a prerequisite for acquisition.
Next bind named export lookup and original function-cache publication under live
source/target authority. See [minimum predicates and scope](NATIVE-PLATFORM-PROFILE.md).
No fresh Windows or whole-PE pair; complete environment/resource proof is still open.

### Named native export and function cache now execute

Under the explicit native profile, original GetProcAddress402ae0 now returns the
unique live implemented export, and original XCHG402aef publishes function41cd24.
Execution stops explicitly at constructor tail402c47, before guard/indirect API
invocation; default entry still rejects402b00. Lookup validates complete source
publication and actual target lifetime without creating call authority. Next lift
402c47..402c73 with actual arguments, guard, dynamic call and fallback semantics.
See [NAMED-NATIVE-EXPORT.md](NAMED-NATIVE-EXPORT.md). No new whole-PE pairs.

### Constructor tail reaches its checked indirect API call

Explicit-profile entry now executes original402c47..402c61 including resolver
argument cleanup, target preservation, guard stub and protected stdcall call
setup. The live function/source/target and object argument are validated; no lock
is constructed. The exact boundary is InitializeCriticalSectionEx failure/resource
contract at402c61. Default admission still rejects402b00. Next resolve that API
relation, then original constructor RET/count publication and FLS. See
[CONSTRUCTOR-TAIL.md](CONSTRUCTOR-TAIL.md). No new whole-PE pairs.
