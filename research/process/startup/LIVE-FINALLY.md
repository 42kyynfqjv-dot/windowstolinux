# Original finally effects in live owned storage

This component connects Inner's original initializer, local-unwind loop,
notification, both finally funclets, Dispatch and CleanupA/B to the same checked
runtime storage. It does not admit a whole PE, finish RtlUnwind, retire a source
frame or authorize saved-context restoration. PR45 remains a draft.

## Instruction and ownership binding

The existing funclet and dispatcher proof walks now emit a second body through
`LiveFinallyEffects`. Each original read and store calls checked storage at its
instruction position. This is generated alongside the existing array-backed
body from the same decoded instructions, without rewriting emitted strings.
Dispatch's original private two-word callback pair remains private. A failed
cleanup does not fabricate the subsequent trace/local/cursor stores. A later
store failure retains every earlier store that actually ran.

`CrtFinallyFields` captures the runtime, registry, frame, registration and event
identities. Every operation revalidates the live source and protected slots,
initialized scalar roles, module capabilities and exact bound code/table bytes.
Local and cursor words must be distinct ordinary words. Module outputs cannot
alias each other, the cookie, or the bound original instructions and metadata.
A failed operation poisons this field authority; restoration is never issued.
The enclosing proof must provide the complete immutable ranges and scalar image
bindings; a caller-supplied address alone is not an execution certificate.

The composition uses the actual Inner prolog at `0x4010c0` and next 28 initializer
bytes: local `[EBP-28]=100`, cursor `[EBP-32]=0`, EH4 TryLevel transitions through
0 to 1. Main's `[EBP-28]` is a guard and fails both the frame-role proof and
ordinary-field eligibility. These frame layouts are not interchangeable.
The original Dispatch table is `[(1,CleanupA),(-1,CleanupB),(-1,CleanupC)]`;
Inner's second dispatch therefore ends at cursor **-1**, independently of the
EH4 scope traversal ending at TryLevel **-2**.

At the explicit component entry, trace 5 becomes 1298, local 100 becomes 118,
and the original finally-0 stores 118 and `0xffffffff` into the two image output
words. Starting trace `0xffffffff` instead yields `0xffffff12`, exercising
wrapping arithmetic. These expectations come from the authored instruction
arithmetic and fixed original data, not the emitted Rust.

## Evidence and failure boundaries

Twenty-six native component scenarios cover three complete ordinary cleanup/guard paths and
23 rejected/failing paths: changed finally/Dispatch-table/cleanup bytes; failure
after trace, first image output or private callback writes; pointer-as-local,
unknown cursor, protected scratch, corrupt guard, stale event, duplicate outputs,
code/metadata/cookie aliases, aliased local/cursor, protected frame offset and
foreign runtime capability. Failed paths retain reached effects and cannot
produce completion or restoration. Two additional test functions exercise the
live emitter on independently authored register/frame layouts and check failure
ordering and post-call live reads.

The full CRT target has 154 passing tests and one vector-dependent ignored test.
Compared with the previous 143, this includes eight inherited dispatch/funclet
tests exposed in this target and three new test functions; these are not eleven
new independent proofs. The evidence checker explicitly runs the ignored test
against five recorded original Windows observations. It additionally executes
all 26 finally scenarios on each host and compares extracted PE-region and
emitted-Rust hashes. Those scenarios are component executions, **zero new
Windows-versus-ELF whole-program pairs**.

Local evidence uses unchanged PE SHA-256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
Reproduction: `check_normal_wrapper.py ORIGINAL OBSERVATION NEW_OUTPUT`, then
`check_projection_boundary.py NEW_OUTPUT/normal-wrapper.rs NEW_OUTPUT/projection`.
The checker extracts the original initializer, funclets, Dispatch and both tables;
no binary edits or expected-output replacement are used.

## Remaining connected gate

The supplied source entry CPU, initial trace, closed ordinary callback domain and
private callback scratch are explicit component cuts. Dispatch's private pair is
materialized in checked component scratch for the original Cleanup instructions;
it does not yet establish the complete original helper call-stack allocation.
The new live fields remove final-copy-back divergence, but do not prove the
original exception dispatcher acquired this event or initialized all older frames.

Next connect the original guard/epilog instructions and source retirement to this
completed cleanup path, checking saved registers, protected return, FS predecessor
and storage invalidation. Completion of these funclets alone is insufficient to
retire the frame or resume Main. Nested/collided exception delivery, the unbound
RtlUnwind continuation and full entry-to-exit/startup proof remain separate gates.
Full rcedit, ordinary CRT and XP/7 compatibility remain unsupported.

## Prior CI failure retained

All three workflows for `f8eb14840264fbc01345065632daa6fe123c856e` passed:
40801830704, 40801824608 and 40801824625.
For notification checkpoint `7321f366ec47b7cbf6d3fbdf3f0e5e65af138149`, full run
40803339567 and startup run 40803334289 passed. Full run 40803334313 failed its
original-Windows launch diagnostic; the other eight jobs passed. This was
`corpus14`, reused executable path, repetition 0, with stdout `C14`, empty stderr
and a process still alive after 15 seconds. It was killed and reaped with exit 1.
The fixed 18-sample diagnostic retained that failure (17 samples passed), and both
independent host exit controls passed. Later samples and the parallel green run
do not establish a fix.

Artifact 12866169284 (`windows-launch-diagnosis`) has ZIP SHA-256
`300075fb375b3dd5b937b736ec8f60af340cb6969724d856381ed799ee9e696a`.
The observer verified process identity, 0.015625 CPU seconds, 62 handles and one
thread node (`object_type=8`, `object_status=2`, no reported wait-chain cycle).
That is diagnostic state, not a demonstrated cause. The PE SHA-256 is
`5406895aa3d7208e10967e09eba072b72a72ffb30f6edb31bcc9634765ef5f2f`.
The failure and earlier original-process/compiler-build timeouts remain unresolved;
no retries were hidden or timeout thresholds changed.


## Connected post-cleanup guard review

The original guard validator and security-check instruction proofs now run after
successful Inner local cleanup, against its live table header and -48 guard.
The shared guard emitter supports an owned ordinary call as well as the deferred
prefix-call form. The guard call's root CPU is still an explicit component
entry; this does not prove the original handler reached this call site.

Four additional cases corrupt the guard after cleanup, change security-check
code, alias the active root protected return, or expire that return. All retain
the completed trace/local/output writes and TryLevel -2, while preventing handler
completion. The alias case initially reproduced acceptance: CrtOwnedFrameView's
call boundary checked the root value but not its unique occurrence. Both that
boundary and bridge preflight now reject duplicate return tokens.

The original Inner normal-return epilog at 0x40115c restores FS and returns to its
normal caller. Its inventory explicitly excludes exceptional cleanup; executing
it here would misrepresent the nonlocal unwind. The remaining gate is the actual
exception-handler epilog/dispatch completion and justified source-frame retirement,
with captured/delivery context and predecessor ownership intact. No normal RET is
used as exceptional retirement authority. Routine review and CI can remain on Sol.

Two additional nested-call cases execute the same original guard through a live
child activation and reject an aliased child return, respectively. These exercise
shared call ownership; they do not claim nested Windows exception delivery.

## Original handler tail and checked retirement

The connected component now executes the original handler save block
`[0x402210,0x40221c)`, original disposition initializer
`[0x402222,0x402229)`, and original return epilog
`[0x4022e0,0x4022ea)`. POPs and frame teardown restore the values actually saved
by the original save instructions. A checked straight-line instruction-cut API
returns to its component boundary without executing RET or consuming a protected
continuation; complete-function graph decoding retains its closed-edge rules.
A regression rejects return, jump, call, FS and malformed cuts.

The initializer/cleanup/guard/epilog assembly still has explicit intervening-body
and entry cuts. It is not execution of every original handler instruction.
The epilog's disposition and protected return must be valid before the assembly
issues a non-Clone `CrtHandlerExit`. Completion of a callback alone cannot replace
this executed-tail authority.

`CrtOwnedStorage::retire_completed` requires matching event/runtime/registration,
the live single-use handler-completion receipt, disposition ContinueSearch (1),
TryLevel -2 and a completed younger-frame machine boundary. It validates physical
source words, unlinks and retires the registry frame, retires the matching machine
frame, and consumes the abandoned frame's initialized words and protected tags.
A failure poisons the registry. The selected frame cannot be retired.

The corpus now has 36 native component scenarios (4 successful and 32 rejected or
failing). Added cases corrupt the saved ESI, epilog bytes, disposition knowledge
or value, and root return identity; exercise successful younger retirement and
stale-event/wrong-disposition/wrong-machine/wrong-completion-generation rejection; and verify the abandoned
CPU cannot use its old protected return. The younger-frame case supplies an
independently located older registration as an explicit entry cut: it does not
prove acquisition or initialization of original Main's live storage. Existing
nested guard cases retain their component-only meaning. There are 155 CRT tests
passing plus the separately executed vector-dependent test; one new test function
checks fragment boundaries. No new whole-PE Windows/ELF pairs.

Next bind the actual dispatch caller state and exception-handler control path
across the intervening instructions, with original older-frame acquisition and
captured/delivery ownership, before treating the component exit as a complete
original handler. The normal-return Inner epilog is still excluded from exceptional
retirement. RtlUnwind completion, selected continuation and full startup/rcedit
remain unsupported.

The exit token also binds the immediately ensuing registry completion generation.
An exit from an earlier handler invocation cannot authorize a later completion on
the same frame/event. Both exit and completion are consumed by retirement.

CI reconciliation: all three aa6a9d4b workflows succeeded. For 16951511 startup
40807719740 succeeded; full 40807728976 failed imported-output original Windows
`hello` execution (job 123230560030), with stdout Hello, empty stderr, alive after
15 seconds, then killed/reaped1. Artifact12868966896 SHA256
`8d423144595dbc8b33a7ecd02b06e56b02f9b1c11272b78d631f11004abb66f8`
preserves the launch and observer evidence. The same PE is
`30a0afa2dba23697256b96df129e62a9cc7c099edf68bfcb87eaf125fc3757e3`.
This cause remains unresolved; the parallel run's result does not erase it.

## Live caller across cleanup

The original handler save block and disposition initialization now precede local
cleanup, and the same caller CPU remains live through notification/finally calls,
guards and the original epilog. This closes the earlier assembly gap that created
a new caller only after cleanup. `CrtCpu::validate_active` checks the actual live
stack range, same issued capability, unique protected root return and unreturned
state at callback boundaries without inventing saved register/flag knowledge.

Composition exposed a scratch collision: the notification fixture's old 0x9800
entry was also the now-live handler root. Its explicit fixture scratch moves to
0x9400, disjoint from handler saves, original cleanup scratch and the registration
record. No production address or original artifact changes. Notification still
has an explicit private caller cut; it does not claim the original local helper's
entire physical call stack has been executed.

Two new cases expire or alias the handler root return after the first finally.
The next callback boundary rejects completion, retaining trace81/local107/cursor1
and the still-live source registration. The complete component corpus is now38
scenarios (4 success/34 failure), with no additional test functions or whole-PE
pairs. Original dispatcher branches, captured/delivery context acquisition and
intervening body effects remain explicit integration gates. See
[AUDIT-69b844fd.md](AUDIT-69b844fd.md) for the independent routine-audit review.


## Owned delivery prefix and the remaining target-frame boundary

The same original prefix proof now emits an owned unwind route through its real
normalizer, guard and context calls, ending at the taken JNE target0x4022bd.
It stops before the search-only installer. Search still requires flags0; the
separately scoped delivery lease requires flags2 and retains the original mask
check. No arbitrary nonzero flags are interpreted as unwind delivery.

`CrtOwnedDeliveryPrefix` borrows the active delivery lease and checks its epoch,
serial, callback arguments, return identity and unchanged delivery snapshot.
Context helper arguments and stack validation use the delivery CONTEXT and its
ESP, while session validation preserves the distinct saved search CONTEXT.
The full instruction-derived temporary extent is checked before prefix execution.
The existing delivery regressions now execute this prefix instead of only its
initial six-byte prolog. They check the original branch address, complete saved
stack shape and unchanged source exception-pointer pair/context binding.

This is still same-frame component evidence. The concrete remaining Inner gate
is `CrtOwnedUnwind::validate`: it validates the suspended search source against
`frame.storage`; `with_delivery` also derives the establisher from that storage.
Changing the view to Inner would therefore correctly fail source identity checks.
Removing those checks would conflate target and search ownership.

The next bounded architecture change needs separately validated search-source and
delivery-target frame storage in one live registry/runtime, with the delivery
argument packet, callbacks and retirement bound to the target. Shared captured
context checks must stay bound to the source. Independent two-frame, stale-source,
wrong-target, nested-delivery and failed-cleanup cases are required. That ownership
refactor warrants a focused Astra High pass; routine artifact checks remain on Sol
or a bounded reviewed Terra task. No Inner/startup/rcedit admission is claimed.

Prefix integration also exposed a nested stack-boundary gap: delivery previously
reserved only its initial32-byte prolog cut. The session now retains the maximum
instruction-proved prefix extent per active lease. Nested callback arguments must
end below that live extent, including when saved values happen to be scalar.
A close nested entry that would fit the old32-byte boundary now rejects at the
specific callback-stack check before its body executes. The existing owned-frame
corpus grows from74 to75 cases; delivery-lifetime cases grow17 to18, without a new
test function. Local `/tmp` exhaustion interrupted one validation attempt; only
old generated native harnesses were removed, workspace evidence was preserved,
and affected checks were rerun successfully. This is distinct from historical
original-Windows process timeouts, whose causes remain unresolved.

## Separate search source and delivery target

The live unwind view now borrows the selected search storage separately from the
mutable delivery target. The source validation still checks Main's real guarded
bytes, installed exception-pointer pair, captured CONTEXT, callback return and
wrapper lifetime. The delivery lease also binds its target registration ID, so
changing a lease's target cannot reuse another frame's authority. Nested pure
helper calls preserve both views. Neither view is a copied storage snapshot.

Search and unwind authority are explicit: selected search execution validates the
registry target against the Machine selected index; delivery execution requires
the next registry callback. A target switch requires a younger, disjoint frame
in the same runtime/thread/stack, and fails if either live storage identity has
expired. A delivery callback's arguments must fit below both its enclosing call's
reserved stack extent and its target frame. The full prefix extent remains live
across nested deliveries.

Ordered pre-event acquisition can now initialize both original frame images.
The existing instruction-proved Main prolog/activation and Inner prolog/scalar
initializers produce their own byte-backed storage, oldest to youngest. This
uses explicit initial call CPUs and does not claim to execute the intervening
Main-to-Inner CALL or capture the OS exception context. Event issuance remains
restricted to the youngest frame; acquiring an older image grants no raise or
restoration authority. An independent Machine test covers that distinction,
foreign identities and acquisition after event issuance. The native fixture
also rejects out-of-order acquisition without modifying tags or registrations.

The connected native component now executes Main's search/filter/global wrapper,
then the unchanged unwind prefix and original normalizer, guard and context
helpers against Inner. The compiler binds a guard proof for each admitted frame
layout. The prefix reaches the original unwind branch at 0x4022bd, reads Inner's
TryLevel 1 and owner EBP, and leaves Main's distinct guard/pair/captured context
unchanged. Its following local-unwind call is still an integration boundary.

Fifteen additional native scenarios cover the normal two-frame path, relocated
Main/Inner, a nested delivery, wrong establisher, damaged source and target guards,
expired source return, wrong target binding, changed saved or delivery CONTEXT,
a target local write followed by failure, a nested full-prefix stack collision,
a duplicate target return, a changed source pair and a forged lease target. The
three positive cases reach the intended explicit unimplemented API completion
barrier; negative cases fail earlier. The failed-write case retains 0xface in
Inner's ordinary local while no restoration receipt is issued.

The aggregate counts are 90 owned-frame scenarios, including 33 delivery-lifetime
scenarios and 15 cross-frame scenarios (these counts overlap). The separate
finally corpus remains 38 scenarios. Local recorded-observation replay still has
five wrapper comparisons and zero whole-PE comparisons; new target cases are
native component executions, not fresh Windows differential pairs. Local evidence
uses unchanged PE SHA-256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`
and generated Rust SHA-256
`95144770ead5a4f0f630e2c6ca0bc7fc1479509ecbaa544f8b2245a9dc353126`.

Next, connect the original branch's local-unwind call to the already tested live
cleanup adapter while retaining both storage views. The registry must be lent
mutably for ordered handler/temporary-record effects, then revalidated before
issuing completion and retiring Inner. Current `CrtOwnedFrameView` lends it
immutably, so callback completion cannot yet perform that transition. Sol can
review this boundary and attempt the scoped registry handoff; a further Astra
pass is justified only by a concrete unresolved ownership transition. Initial
OS delivery, API completion, selected continuation and full entry-to-exit proof
remain gates. Full startup/rcedit stays rejected. Historical Windows timeouts
remain unresolved.

## Connected delivery cleanup and retirement

Review of the separate-frame checkpoint confirmed source guard/pair/context
validation remains live and the delivery token binds its target registration.
The runtime frame view now lends the registry mutably. `with_handler_target`
checks both owners and callback order, reborrows the selected source for the
handler scope, propagates nested call usage and revalidates the source before
allowing the registry to issue completion. A completed scope still needs the
separate original epilog exit token before retirement.

Seven native cases connect Main's original search/global wrapper and Inner's
original prefix to the existing local-unwind adapter, original notification and
finally bodies, post-cleanup guard and original handler epilog. The successful
case validates the matching completion/exit receipts and retires only Inner:
the registry becomes ready for Main, Inner's storage expires and Main's guarded
storage remains live. Trace1298/local118 are independent expectations. The source
captured CONTEXT is retained separately throughout. Negative cases cover failure
after the first callback writes, damaged target guard after cleanup, stale exit
completion generation, changed delivery context, damaged source guard and a
second copy of the handler return identity. Failed callbacks leave the original
first trace81 write and live registration; they issue no completion. A stale
completion rejects retirement before unlinking.

The original branch-to-local-helper caller instructions and local helper's full
physical call stack remain explicit cuts. The handler epilog runs after the
scoped delivery body ends; ending that scope itself issues no completion or
restoration authority. The connected assembly is native component evidence, not
an admitted whole-handler or whole-PE translation. Next lift the actual unwind
branch/caller sequence and its arguments to replace that cut, preserving the
checked registry lending interface and matching completion/retirement gates.
No further architectural escalation is presently required for that attempt.

Counts now overlap as follows:97 owned-frame scenarios,40 delivery-lifetime,
22 cross-frame and7 connected cleanup/retirement scenarios. The separate finally
corpus remains38. Five existing recorded Windows wrapper observations still
have their own differential check; the new seven cases add zero Windows or
whole-PE comparison pairs. Prior Windows timeout causes remain unresolved.

## Original unwind caller and RET8 wrapper

The connected component now executes the original caller at0x4022bd through the
pre-epilog boundary0x4022e0 and the complete local wrapper at0x402860. Their bytes
are extracted independently from the unchanged PE. The normal graph emitter
retains CMP/Jcc, PUSH, MOV, CALL and ADD effects. The wrapper's original pushes
supply cookie-address, establisher and stop-level arguments to the body adapter;
all three values are checked before cleanup. The guard consumes the original
caller's pushed table/owner pair. The original ADD instructions reclaim their
own arguments and set flags normally. The epilog still executes separately only
after the delivery scope is validated; the component boundary is checked before
an instruction tick and consumes no return token.

Owned calls now accept explicit checked return cleanup, using the shared CPU
call/return mechanism. The separately proved wrapper binds8bytes; return cleanup
is not inferred from whichever RET happens to run. Three additional negative
cases mutate caller bytes, mutate wrapper bytes or give RET8 a zero-cleanup call
lease. The first two reject before cleanup writes; the last preserves completed
cleanup writes but cannot issue handler completion or retire Inner.

Counts are100 owned-frame cases,43 delivery-lifetime,25 cross-frame and10
connected cleanup/retirement cases, with overlapping subsets. New cases still
add zero Windows differential pairs and zero whole-PE pairs. The remaining body
adapter and private notification/finally scratch are explicit physical-stack
cuts, even though their effects and callback instructions execute. These need
original body instruction/temporary-record stack composition before claiming
complete handler execution. OS delivery and selected-source restoration also
remain gates; full startup/rcedit stays unsupported. Sol can attempt the next
body-stack connection using the existing temporary-record and call machinery.

## Actual local-body stack and temporary record

The connected adapter now derives its local entry from the live body CALL instead
of the fixture address0xb000. After full40-byte scratch preflight, the original
prolog at0x402710–0x402742 executes its saved-register pushes, argument loads,
record pushes, cookie XOR and guarded guest-FS installation. The instruction-proved
FS hooks operate on the guest registry; they do not read host thread memory.
`bind_native` checks the resulting seven actual words against the reserved
registry record, with no fabricated private stores. Handler/cookie immediates
remain exact scalars; establisher/owner values retain stack capabilities.

The existing instruction-derived cleanup effect loop uses that installed record.
Its completion defers restoration to the original exit boundary: the proven
POP FS at0x4027a1 validates/restores the registry head and consumes the actual
head word, then emitted ADD/POP/RET instructions at0x4027a8 restore the stack,
nonvolatile registers and protected body return. The enclosing local wrapper
still executes its own RET8. The adapter has a single-use installation flag;
normal projected test paths retain their separate binding mechanism.

Five new connected cases reject changed body code, damaged temporary guard bytes,
a duplicated body return identity, a changed saved EBX value and a protected
return inside the prolog scratch range. The scratch case rejects before original
pushes; callback-time failures retain the first trace81 write and no completion.
The saved-register failure preserves finished cleanup effects but cannot return
or retire the target. Together with previous nested, context and lifecycle cases,
counts are105 owned-frame,48 delivery-lifetime,30 cross-frame and15 connected
native-local-stack cases (overlapping subsets). New cases add zero Windows pairs
and zero whole-PE comparisons; five recorded wrapper observations remain separate.

The cleanup-loop effects still use the proved adapter rather than its complete
CPU loop. Its volatile register/flag results therefore become unknown before the
actual tail; the earlier prolog values cannot masquerade as loop results. The
loop and notification/finally callback physical scratch remain supplied.
Next connect the loop's original register/table traversal and callback call stacks
while preserving this native temporary record. Captured-context acquisition,
OS delivery and selected restoration remain admission gates. Full startup/rcedit
is still rejected. This next bounded implementation can start on Sol.

## Native loop register/table traversal and protected callbacks

The connected path now emits original instructions0x402742–0x4027a1 from the
unchanged body, including both conditional exit tests, cookie/table decoding,
TryLevel loads, row addressing, filter tests, parent writes and the backedge.
The existing complete body/scope proof and runtime readonly-row checks remain
required. Each visited parent must decrease or equal sentinel-2, and the emitted
loop has an explicit4096-instruction limit. No sampled trace supplies loop state.

The cookie address becomes a module capability only after matching the registry's
bound cookie address; decrypted table bits become a module capability only after
matching the owned image's bound table. Original XOR values/flags are retained.
A new emitter store hook is limited to original MOV memory destinations. For the
proven parent store it checks actual EAX/ECX operands and performs one checked
byte/cache update through the owned storage method. Other existing lowering paths
use their unchanged ordinary stores. The hook neither discards the original MOV
nor fabricates a second write to repair metadata afterward.

Notification/finally calls now have protected transient CALL/RET activations on
the current body stack. The notification's actual pushed reason is checked and
its return consumes4bytes; the finally call consumes none. Callee failure retains
memory effects and cannot supply a completed protected return. Callback volatile
registers/flags remain unknown under the explicit callback contracts; subsequent
original loop loads and comparisons determine the state that is actually known.
The original temporary-record and body epilog remain connected to this loop.

Five added cases inject a nondecreasing table parent, wrong cookie operand,
wrong scope-store destination, duplicate active callback return and changed
native temporary predecessor. They reject before unsafe effects or retain the
first trace81 write as appropriate. Counts overlap:110 owned-frame,53 delivery,
35 cross-frame and20 connected native-loop/stack cases. No additional Windows
comparison or whole-PE pair is claimed; the five recorded wrapper observations
are separately replayed. Root175/CRT155 tests and Clippy pass locally.

Private notification/finally body scratch and bridge instructions still use the
independently checked component providers, despite the newly real parent CALL
stack. Next connect those bodies/bridges to their live child CPU and saved stack,
then preserve complete cleanup/retirement and selected restoration. OS delivery
and full entry-to-exit proof remain gates. Full startup/rcedit remains rejected;
Sol can attempt the next connected callback-body scope. Prior Windows timeout
causes remain unresolved.

## Live notification body and finally bridge

The connected notification now executes its original instructions on the issued
child CPU, including the real saves, argument load, record stores, restores and
RET4. A compiler proof binds the record layout. The module-data capability is
issued after the decoded MOV that establishes its numeric address (rather than
an assumed instruction offset). Every store checks its actual value and exact
record destination. Source owner, target, reason, code bytes, argument word,
stack extent and protected scratch are validated before executing stores.

The finally bridge is independently extracted/proved as original CALL EAX;RET.
It validates the live target/abnormal/owner registers and original bytes, creates
a second protected funclet call on the live stack, and consumes both actual
return identities in order. The notification uses its actual flags/register
results; finally-provider volatile effects remain conservatively unknown.
The private finally function body/dispatcher remains a checked provider, so this
does not claim that its complete nested stack or instructions are already lifted.

Eight new connected cases cover changed notification code, protected notification
scratch, changed reason argument, duplicate notification return, changed bridge
code, changed handler target row, changed finally code and wrong live owner EBP.
They reject before finally effects or retain already executed notification
stores as applicable. Existing nested/source/delivery/temporary lifetime and
failure cases run through the live notification body and bridge as well.
Overlapping counts:118 owned-frame,61 delivery-lifetime,43 cross-frame and28
connected callback/loop/stack cases. They add zero Windows differential pairs or
whole-PE pairs; the existing five recorded wrapper comparisons remain separate.

Next connect the finally funclet and nested dispatcher bodies to this live child
CPU rather than the private effect backend and scratch. The source/captured vs
delivery ownership and validated cleanup/retirement gates stay required, followed
by selected restoration and OS delivery. Full startup/rcedit stays unsupported.
Sol can attempt that next scope; no concrete escalation need is established yet.

## Native funclet and nested dispatcher bodies

The connected finally body now executes both unchanged funclets, the original
bounded dispatcher, and original CleanupA/B/C instructions on the issued child
CPU. Funclet LEA/PUSH/CALL/ADD/RET operations supply real field pointers; the
dispatcher builds its trace/local pair on its own live stack. The nested cleanup
receives that actual pair, and original dispatcher MOV instructions commit its
results before updating the cursor. No fixed0x9500/0x9600 scratch or scalar-effect
copy replaces this connected path. The old effect backend remains only for its
separate tests and explicit older component callers.

An instruction-level indirect-call node and emitter callback bind the actual
register/table operand at the dispatcher CALL. Default whole-graph decoding and
default emission still reject indirect calls. Only the separately proved bounded
dispatch component constructs/lower its node with a checked table target; the
new independent test covers rejection of register and indexed-table calls without
that contract. Unknown targets do not become host pointers or implicit imports.
The dispatcher admits initialized cursors0–2 under the existing independent
three-path proof. Its error/fast-fail path stays outside the admitted domain:
entry and original JA predicates reject invalid cursors before emission effects.

Immutable source/table validation, owner EBP/argument capability checks, bounded
private-stack preflight, exact protected returns and native register restoration
remain live throughout. Nested providers no longer overwrite native results with
shadow register values. Callback failure still retains earlier private or public
writes. Completion/retirement follows the checked handler epilog as before.

Six added cases cover an aliased returned funclet identity, invalid cursor,
changed nested cleanup code, changed dispatch target table, unknown cursor, and
an independently specified alternate entry cut (TryLevel0/cursor2). That last case
executes CleanupC and independently expects trace83/local113 before retirement;
it does not alter the PE or claim an additional Windows observation. Aggregate
counts overlap:124 owned-frame,67 delivery,49 cross-frame and34 connected native
callback/loop/stack cases. Root175 and CRT156 tests pass locally (plus the separately
replayed observation test). Five recorded wrapper pairs remain separate; new
native cases add zero Windows and whole-PE pairs.

The next gate is the original global-unwind API completion/selected continuation.
The explicit delivery provider still supplies captured/delivery entry contexts,
and the original global wrapper rejects after it returns. Cleanup completion
must be bound to an owned, single-use API/continuation receipt and actual wrapper
resumption; it cannot by itself authorize guest restoration. OS delivery, full
startup and rcedit remain unsupported until entry-to-exit evidence establishes
those semantics. Sol can review this native integration and attempt the bounded
completion handoff, escalating only a concrete unresolved semantic question.

## Conditional owned wrapper resumption after retirement

This remains a component continuation-input cut, not an RtlUnwind implementation
or API-effect/admission certificate. The supplied delivery CONTEXT and preserved
API-boundary footprint are explicit assumptions; production API binding still
rejects the original call without its complete effect contract.

The frame view now lends the event Machine mutably as well as registry/storage.
Readonly callback validation uses common shared source/target checks rather than
constructing a second mutable event view. This lets the live pending wrapper
retire Inner using its real handler-completion/epilog receipts before testing
continuation readiness. The prior test retired it only after wrapper rejection.

A non-Clone, single-use continuation-cut token binds runtime/thread/event/source,
unwind epoch, issued ticket, wrapper return, exact argument stack, original
TargetIp and readonly captured-context comparison. Issuance requires no active
delivery/stack leases, all younger registry and Machine frames retired, and the
selected source ready. Applying it rechecks those identities, the full captured
CONTEXT, record fields, original four arguments and actual wrapper save slots.
The ticket is consumed once; the search input stays permanently suspended.

At this explicit cut the four actual API arguments are consumed, EAX receives
original ReturnValue0, ESP becomes the validated continuation stack, and other
working registers/flags become unknown. The unchanged wrapper's real POP/RET
instructions then restore its own saved nonvolatiles and pass ordinary protected
return checks. No saved-context shadow array authorizes guest restoration, and
normal CALL/RET ABI validation is unchanged. Native results are compared to the
wrapper's own entry state, not an earlier handler state.

Eight new cases cover successful connected resumption, wrong TargetIp, changed
saved word, denied duplicate issuance with a still-valid original token, wrong
wrapper identity, expired wrapper return, wrong Machine current frame and
changed captured CONTEXT. The negative cases retain completed cleanup writes and
younger retirement but cannot resume. These are native conditional-cut cases,
not new Windows differential or whole-PE pairs. Counts overlap:132 owned-frame,
75 delivery,57 cross-frame,42 connected native callback/loop/stack,8 resume-cut.
Five existing recorded wrapper comparisons remain separate.

Next establish the global API footprint/continuation certificate against the
original delivery and saved-state acquisition contract, including independent
multi-frame original evidence. Conditional context/footprint inputs cannot be
silently promoted to that certificate. Selected handler cleanup/transfer and OS
entry-to-exit composition remain gates; full startup/rcedit stays unsupported.

## Selected caller after the returned global wrapper

Applying the conditional resume cut now leaves a phase marker. After the actual
wrapper RET, `CrtOwnedPostUnwind::bind` consumes it once and checks that the wrapper
return identity is gone, the original handler return remains live, captured
objects still match, younger frames are retired and selected-source state is
ready. It also checks the actual saved table/owner packet and the selected row
pointer. The old search token stays suspended; post-return access uses distinct
phase authority and a single-use ticket.

The compiler lowers the original selected caller after GlobalUnwind through its
existing independent dispatch proof. Original branch predicates are checked
against that proof. For the frozen Main path, equal TryLevel skips the local
unwind call; any proof requiring a new local effect still rejects emission until
bound. Original PUSH/MOV/CALL/ADD instructions then disable the selected scope,
run the guard with real arguments and load the landing target from the bound row.
The protected TryLevel MOV updates bytes and metadata once via the existing store
hook. The path stops at the actual selected-transfer CALL, not an executed jump
or guest restoration. Machine remains in Cleanup and the handler return is live.

Nine added cases cover normal caller execution, changed code, resurrected wrapper
return, expired handler return, changed landing metadata, wrong selected scope,
wrong owner save, consumed phase replay and a counterfeit row object containing
the correct numeric landing address. That last case requires the original table
capability/offset rather than accepting equal numbers. Compile-time changed
caller bytes also reject. Negative paths preserve completed younger cleanup;
post-store replay leaves the original-2write intact without another store.
Counts overlap:141 owned-frame,84 delivery,66 cross-frame,51 connected native
callback/loop/stack,17 conditional-resume and9 selected-caller scenarios. Five
recorded wrapper observations remain separate; no new Windows or whole-PE pair.

The next instruction boundary is selected transfer/landing. API admission still
needs the separate real delivery/context and effect contract below; conditional
phase success does not close it.

### Opaque delivery identity and collided-path rejection

The delivery packet can now carry a callback-scoped opaque dispatcher token
instead of requiring scalar zero. Its arena/thread/epoch/callback identity is
checked on each use; scope exit revokes aliases even after a failed callback.
Normal original cleanup, wrapper POP/RET and the selected caller execute through
the still-unexecuted transfer boundary with that token. No numeric address,
object contents or API-effect certificate is fabricated.

The independent original-byte audit found the nested handler's actual collided
store through the fourth argument at 0x4027ee. A generated negative case executes
its original loads/store and rejects the opaque dereference, preserving previous
cleanup effects. The retained Windows observer has zero nested-handler hits;
its injected observer-cleanup failure is not guest unwind evidence. The exact
remaining contract and next evidence gate are in [DISPATCHER-EFFECTS.md](DISPATCHER-EFFECTS.md).

Local validation: root 175 passed; CRT 158 passed/one separately replayed original
observation test; artifact-bound normal wrapper and projection checks passed.
There are 151 owned-frame scenarios, including 10 new opaque-dispatcher scenarios.
Subgroup counts overlap (94 delivery,76 cross-frame,61 callback/loop,19 conditional
resume,11 post-global caller). The 38 finally cases and five recorded original
wrapper observations remain separate. These add zero Windows differential pairs
and zero whole-PE pairs. Local unchanged PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
generated Rust is `d9a314efb61009a4524f3462902f1130bd72b37cab718abe6704d23ab4d9ae89`.

All three prior-checkpoint 9ca97bb2 workflows passed:40826135827,40826128227,
40826128242. That success does not resolve retained Windows process-exit timeouts.
Fresh publication CI must be checked separately. Full startup/rcedit is unsupported.

### Selected bridge execution to the owned landing boundary

The post-caller cut now records a single-use ticket tied to the original handler
activation and actual ESP. The original selected bridge executes its register
moves, PUSH 1, actual notification CALL/RET 4, XORs and checked indirect-jump
outcome. Notification uses the existing original-body lowering against live
module storage, under a separate selected-frame caller binding. It reports
reason 1 and the actual selected owner/target. The nonreturning CALL's protected
slot remains live in a private jump receipt; no ordinary RET, Machine restore,
stack abandonment or landing body is fabricated.

Seven connected cases cover success, changed bridge/notification bytes, wrong
owner, missing ticket, replay and shifted caller ESP. Review tightened the ticket
to the issuing CPU activation and ESP so another call on the same frame cannot
borrow it. Altered notification targets and jump registers reject during proof.
The full unchanged 25-byte bridge is extracted from the same PE by the checker.
The landing is currently only a checked target range, not executed instructions.

Root175 and CRT158/one separately replayed observation test pass, as do Clippy,
format, artifact-bound wrapper and projection checks. There are158 owned scenarios;
seven selected-bridge scenarios overlap the existing groups. No new Windows
comparison or whole-PE translation is claimed. Local PE remains1e96cb39...;
generated Rust SHA256 is
`c785416d9550238ad554239650487cefb27a5f7c938bec44be31ecf3966a2e54`.

The next executable gate is original landing `MOV ESP,[EBP-24]`: bind the actual
Main saved-ESP word and complete stack extent, then explicitly retire abandoned
handler/selected CALL roots under the nonlocal transition. The jump receipt alone
must not authorize arbitrary ESP or CONTEXT writes. Original landing/context-store
proofs can then be bound to live owned slots. Sol can implement/review that bounded
scope; actual delivery acquisition/collided effects remain independent API gates.

Previous head fe4e1678: startup40828206690 and full40828213392 passed. Full run
40828206749 contains failed authored-windows-fixture job123296040130; its Linux job
was still running when reviewed. Original corpus case23, SHA256
`6c4846a95a41aecc55d122576c091538094902940315a7463aff56b707949ab5`,
produced the expected 64 Z bytes and empty stderr but remained alive after15s,
then was killed/reaped with exit1. Server2025 build26100 runner
win25-vs2026/20261021.278.1. Identity-checked PID3344/creation134377282006476144,
CPU0s, one WCT thread7920, cyclefalse/type8/status2/wait9285ms. This is evidence,
not a root-cause diagnosis. Artifact12877700855 ZIP SHA256
`063cf2a50fdd59c8e6fbad9552279d52b52a7aeed37375e1e9cd2ebf69ad4a12`
is preserved locally alongside the failure JSON/process state. The independent
exit controls and 18 launch samples passed earlier. No retry/threshold change
was made and parallel success does not resolve this timeout.

### Saved-ESP landing pivot and abandoned-call retirement

The selected jump receipt now binds the issuing process anchor, owned frame,
event, activation, entry registers and single-use protected CALL identity.  The
first original landing instruction at VA `0x40135c`, `MOV ESP,[EBP-24]`, executes
only after the expanded original Main prolog proves that `[EBP-24]` is the typed
saved ESP for this frame.  A scalar with the same numeric value is rejected.

Before the pivot, the adapter validates the original handler's saved EBX/EBP/ESI/
EDI words, unique handler and selected-bridge return identities, unchanged
landing bytes, complete stack bounds and all protected control words in the
abandoned interval.  It rejects changed code, consumed saved words, duplicated
or foreign returns, replayed jump receipts, and pointer escapes into live Main
or external storage.  After those checks, the abandoned handler and selected
CALL bytes are forgotten, the ended exception-pair borrow is stripped, and the
original instruction loads ESP.  Completed lower delivery callback scratch is
not treated as a live Main alias; an explicit live-Main alias and an external
result-region alias both reject.

Ten landing-pivot cases overlap 17 selected-bridge cases in 168 owned-frame
native scenarios.  Root tests are 175 passed; CRT tests are 158 passed plus one
separately replayed original observation; Clippy, formatting, the artifact-bound
wrapper checker and projection checker pass.  The unchanged PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
the generated Rust SHA256 is
`0387414071df8c43bdcab9b696b9709dbaa49e7f77f96509aea7103144757c1e`.
This is checked component execution with zero new Windows differential pairs
and zero whole-PE translation pairs.

All three selected-bridge head `de5bbaa1` workflows passed: startup
`40829869997`, push CI `40829870000`, and PR CI `40829877570`.  Fresh landing
head CI remains required after publication.  Existing Windows timeout artifacts
and their unresolved process-exit cause are unchanged.

The next connected instructions write the handled marker and build the original
restoration CONTEXT before the call at VA `0x401250`.  They need owned field
provenance and a validated restoration transition; this landing receipt does not
authorize arbitrary context stores or guest resumption.  Actual delivery
acquisition and collided-unwind effects remain separate unresolved API gates.
Full startup and rcedit conversion remain unsupported.

### Original landing CONTEXT construction (2026-10-29)

Review of `9001109` found that completed lower callback scratch could retain a
typed pointer into the abandoned handler interval. The pivot now revokes those
tags while preserving their numerical bytes. Live Main and external aliases
still reject before retirement. The regression checks that no dereference
authority into the retired interval survives, including lower scratch.

The connected path now executes the original 57 bytes at `0x40135f` through the
shared instruction decoder/emitter: handled marker, repeated scope disable,
CONTEXT address calculation, and EAX/ESP/EBP/EIP stores. It does not substitute
observed output. A single-use receipt from the checked saved-ESP pivot binds the
process, event, registration, frame and saved stack pointer. Each written word
must be within live ordinary Main storage, outside the guard/protected slots,
and free of overlapping typed authority. Source bytes are checked at execution.

Independent assertions check scalar EAX 77 and typed ESP/EBP/EIP at the Windows
x86 CONTEXT offsets 176/196/180/184. Other context bytes remain unknown; the
guard and flags are unchanged. Stale-event, changed-code, typed-field collision,
scalar-forged ESP and receipt replay reject. There are 172 owned-frame native
scenarios, including five context scenarios; these overlap the existing cleanup,
selected-bridge and pivot scenarios and must not be added as disjoint totals.

Local verification: 175 root tests and 158 CRT tests passed, with the one
observation-dependent CRT test separately replayed by `check_normal_wrapper.py`.
Formatting, Clippy and the projection regression checker passed. The unchanged
PE SHA256 is `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
the extracted context block SHA256 is
`988ea57d977dd3965f777c5ee431dc1a17c2320956c2200ec4cae3f06b483e94`;
generated Rust SHA256 is
`7b71b8025bbb2b9b8d142b27ab6d3b1109af950c277c96e61212ea6b835504b4`.
The five wrapper observations replay prior recorded Windows evidence. They are
not five new original-Windows executions or context-restoration comparisons.

The boundary remains before `PUSH ECX; CALL 0x401250`. The existing handler CPU
cannot validate its active CALL after that CALL root was retired, and the test
requires that rejection. A prepared context is not permission to resume guest
execution. Only the context fields written by the original instructions are
initialized; this is not a captured complete Windows CONTEXT. The selected
target is bound as an image pointer, not yet certified as an executed continuation.

The next connected gate is a normal-frame continuation bound to Main's still-live
original protected return and saved state, followed by the original Restore
argument/CALL/load/indirect-JMP instructions. It must consume the prepared receipt
once, retire its abandoned CALL/argument words, validate the actual continuation
bytes, and preserve the untouched registers/flags and unknown fields. Reusing the
retired handler's `return_id`, manufacturing a successful RET, or copying the
older projected `FrameMemory` result into live storage is not an acceptable bridge.
Sol can review this checkpoint and implement the bounded continuation binding;
escalate only an identified ownership-transition uncertainty.

All three predecessor `9001109` workflows completed successfully:
startup `40873570540`, full push `40873570612`, full PR `40873578922`.
Historical original-Windows process-exit timeouts remain unresolved. This change
adds component execution only: zero new Windows differential pairs and zero
whole-PE translations. Actual delivery acquisition and collided-unwind effects
remain independent unresolved contracts; full startup and rcedit stay rejected.

### Original Restore transfer and observation continuation (2026-10-29)

The owned landing now connects original `PUSH ECX; CALL 0x401250` to Restore's
context loads and indirect jump at `0x401266`, then executes the original three
observation stores at `0x4013a5`. The shared Restore instruction validator was
extracted without changing its policy so both the existing unwind proof and the
live-storage emitter use it. Actual MOV loads/stores use the shared decoder and
emitter; the validated terminal jump reads its typed target from live context.

A separate single-use prepared-context token binds the registration, event and
pivot. Before effects, the adapter checks unchanged caller/Restore/landing bytes,
context pointer identity and EAX/ESP/EBP/EIP fields, the unique still-live Main
return root, empty eight-byte call scratch, and ordinary destination ownership.
The original PUSH/CALL effects allocate a fresh protected call identity. The
nonreturning jump consumes that exact identity and argument word; it never
reports a successful RET. Replay rejects. It does not revive the retired
handler's entry snapshot or manufacture a normal Main return.

Seven transfer scenarios overlap 178 owned-frame scenarios: normal execution,
stale event, scalar-forged EIP, changed Restore bytes, occupied protected scratch,
changed destination bytes and missing receipt. Additional assertions cover
single-use replay, flags and unchanged registers, exact observed restored values,
and rejected active-call validation on the old handler. Compile-time mutations
cover context argument, field offsets and indirect target binding. These are
component checks; five prior Windows wrapper observations are separately replayed.
There are zero new Windows differential pairs and zero new whole-PE admissions.

Local root tests (175), CRT tests (158 plus the separately replayed observation),
Clippy, formatting and artifact/projection checkers pass. Predecessor e5d4ff0's
startup run 40876551200 passed; both full workflows 40876551080 and 40876558358
have eight completed successful jobs and the final compiler-native-linux job
still running at the review checkpoint. No failure was hidden or retried.

Next is to bind this checked transfer result to the normal-source activation and
Machine event completion, then execute Main's continuation reporting and epilog.
The returned receipt records component execution only and cannot independently
complete Machine restoration. Actual OS delivery acquisition and collided-unwind
API effects remain unresolved, as do the retained original-Windows process-exit
timeouts. Full startup and rcedit stay unsupported. Sol can continue this bounded
normal-frame/event-completion integration; a particular conflicting ownership
invariant would justify a narrowly scoped Astra review.

Artifact replay provenance: unchanged PE SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
Restore block SHA256
`e238bcd04d8b025e87cefed2b36fd842431c052c11bd8ff6fb274225e3f69666`;
continuation stores SHA256
`06481e5466a0c6e04e96b89dbdd6fba40646f5af3373f2a55f16ebc917800590`;
generated Rust SHA256
`271b757b15ba5f57a7118c3b084d67d1ac5e509adbd80270bbdd90438b08bb69`.

### Validated completion of the live restoration (2026-10-29)

Independent review of a0e3527 found no live frame latch for its returned transfer
receipt. The executed Restore transfer now records its fresh CALL generation in
owned storage. Completion consumes that matching latch once and checks the
process/event/registration, live CPU registers, selected ownership, Main return
root and the three original continuation writes before changing Machine phase.
Younger frames must already be retired, selected scopes disabled and all prior
input/jump/context-preparation authority consumed.

The adapter uses `finish_selected_dispatch` and `restore_owned`, binding the
existing selected storage lease. Its projection comes from the instruction-derived
registers and target. Unknown captured nonvolatile registers stay unknown;
a known captured value that disagrees with the live register rejects. It does not
restore ECX/EDX/flags from an invented capture. Six completion scenarios overlap
183 owned-frame scenarios: success, stale event, changed live register, changed
continuation write, missing storage latch and saved-register disagreement. A
reconstructed replay rejects, and rejected preflight cases leave Cleanup phase
and cannot mint normal-call authority.

Crucially, Machine `Done` is restoration bookkeeping, not a finished
`OwnedExceptionEvent`. The adapter deliberately does not call
`mint_finished_event`. The original event's shared `CapturedContext` lifetime must
still perform Live -> Restoring -> Finished, with matching original raise-site
identity, before `NormalReturnSession` can take its normal-call permit. The tests
assert that no such permit is created by this component.

The concrete remaining connector is between the checked live `CrtNormalRaiseSite`
/ captured input and `OwnedExceptionEvent::from_raise`, which currently consumes
an initialized `FrameImage` at the original raise boundary. The owned dispatch
fixture currently issues `Machine::issue_owned_event` directly and supplies the
delivery context as a cut. Creating an event after that issue, editing its lifetime
to Finished, or treating the restoration receipt as its substitute would bypass
its issuance and capture checks. A shared live-storage issuance adapter needs to
prove the actual four RaiseException argument words and CALL slot, own one event
lifetime across nested dispatch, call begin-restoration at the selected boundary,
and call finish after the validated transfer. Only then can the existing normal
reporting/return/flush machinery consume the event. Actual OS delivery and
collided-unwind effects remain separate acceptance gates. No new Windows pairs,
whole-PE translations or full startup/rcedit admission are claimed.

Local verification: 175 root and 158 CRT tests passed; one recorded-observation
test is separately replayed. Formatting/Clippy and artifact/projection checks passed. Historical Windows
timeout diagnostics remain intact. Generated Rust SHA256: `4774b4c88150ef243f930b3b17249480c40de315088fa570925d7d572780a684`.

### Original initial RaiseException event reaches the normal-return gate

The initial event adapter now consumes a `RaiseCallProof` for the complete
original Inner prolog, initializers and four argument pushes, followed by the
actual indirect CALL at `0x401117`. The generated caller registers and known flag
bits come from that instruction proof, not the supplied exception CONTEXT. Live
frame identity, initialized arguments, unchanged CALL bytes, slot extent and fresh
return identity are checked before event issuance. The artifact checker verifies
that the original IAT cell binds kernel32!RaiseException. IAT/code values are
compiler bindings, not application-name/hash dispatch.

The adapter issues the existing `OwnedExceptionEvent` once and retains the
suspended API CALL as source-owned storage. The connected experiment exposed an
unretired API CALL token: Main's pivot correctly rejected it as foreign abandoned
control state. Retirement now validates that exact source slot and unique return
identity and consumes it only after the source's original cleanup/handler epilog
and registry retirement succeed. The pivot rejection was not relaxed.

One connected path now carries that same event through the existing live dispatch,
cleanup, original Restore and continuation stores. At the selected restoration
boundary the adapter calls `begin_restoration`, executes checked Machine
restoration and calls `finish`. This invalidates captured aliases and mints the
existing single-use normal-call permit. `NormalReturnSession` accepts the event
and original Main frame. The test deliberately stops at that linked normal-return
session; dropping the unfinished session blocks the machine/registry. No reporting,
normal epilog, CRT exit or process termination success is inferred from that cut.

A second connected case expires the captured lifetime before restoration and must
reject without minting a permit. Six independent issue negatives cover changed
CALL bytes, unknown argument bytes, a protected CALL-slot collision, returned CPU,
changed entry registers and a pointer in the null argument-array word. They leave
event issuance, CPU registers and generation unchanged. Premature restoration,
premature finish, repeated issuance, stale captured aliases and permit replay
checks accompany the connected path. These overlap 185 owned-frame scenarios;
the six issue negatives run separately. The original normal-return plan is tested
as a gate, not claimed as newly executed epilog instructions.

Local verification: 175 root and 158 CRT tests passed, plus the separately replayed
recorded observation; formatting, Clippy and artifact/projection checkers passed.
The initial artifact replay failed when /tmp filled: linker signal 7 and then
ENOSPC, including sandbox startup failure. Sources/logs were preserved; only
100 rebuildable numbered task test binaries were removed to recover 887010360
bytes. Final checks used TMPDIR=/workspace/w2l-build-tmp and passed. This diagnosed
local capacity failure does not explain historical Windows process-exit timeouts.
Unchanged PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
generated Rust SHA256 is
`760df4891509e69d9af5188a80397f0b691f41e7d783389486e5d25e533d5f99`.
Zero new Windows differential pairs and zero whole-PE translations.

The concrete next scope is Main's original pre-call initialization and post-restore
report/epilog on this live storage. The current Main initializer covers its prolog
and saved ESP, while the original path additionally initializes CONTEXT through
0x402370, stores GetModuleHandleW(NULL), invokes its nested source, then reports
at 0x401466 and returns through 0x401500–0x40151b. Those live words and API effects
must be initialized/proved rather than supplied expected report arguments. Keep
all actual Windows delivery, incoming-handler containment and collided-unwind
assumptions explicit. This component event represents the bounded closed,
same-thread delivery contract; it is not OS-captured-register acquisition. Full
startup/rcedit and ordinary third-party compatibility remain unsupported.

### Live Main initialization and original-root continuation binding

The existing `frame_init` certificate is now emitted against canonical CRT byte
storage. It proves the original caller at 0x4012b9–0x401316, all bounded fill-helper
feature/alignment paths, initialized range and current-module API arguments. The
adapter writes ordinary scalar words, fills the 716 context bytes and writes a
typed current-module pointer directly to live storage. TryLevel changes update
both the protected live word and registry image metadata through `scope_store`.
No detached ordinary scalar image becomes a second source of truth. Runtime
checks retain original caller/helper bytes, protected-word exclusion, complete
byte bounds, typed aliases, scratch ownership and the pre-event phase.

The artifact checker extracts the original helper and verifies the
GetModuleHandleW IAT identity. Local tests without retained code use the existing
independently authored scalar-fill encoding; retained-artifact replay proves the
actual optimized original helper, including its initialized-but-unknown feature
words. The bounded current-module, valid stack, DF-clear, flat-ES and instruction
availability assumptions from CONNECTED.md remain explicit.

Five initialization negatives exercise changed code, a pointer inside the fill
range, occupied protected scratch, invalid module identity and replay. Earlier
writes survive a later fill/API-domain rejection; the guard stays unchanged.
The connected event path now observes actual zero-filled untouched context bytes;
other component paths continue rejecting unknown untouched bytes. No unknown
value was replaced by zero without an original initialization proof.

After the same event finishes, `bind_main_continuation` validates the restored
register projection and target, the unique live Main return, and all four original
saved-register tags. It binds CPU entry state to those existing tags and root,
without changing the live registers/flags or consuming a return. The old retired
handler remains invalid; the resulting Main CPU passes ordinary active-call
validation and repeated binding rejects. `NormalReturnSession` still stops before
reporting/epilog in this test; abandoning it must block rather than produce a
return receipt. No new output, process exit or whole-PE comparison is claimed.

Verification: 175 root tests, 165 CRT tests and one separately replayed recorded
observation passed; formatting, Clippy, original-artifact wrapper and projection
checkers passed using TMPDIR=/workspace/w2l-build-tmp. Five Main-init negatives
and one connected continuation binding overlap earlier component scenarios.
Original PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
initializer SHA256 `a35583ed76b1854b7121e1a48b12c5280ff185cf3df7b72360258f38225d3d3f`;
fill helper SHA256 `3586be7f6dac27b94938fabc1acb198c1d5ef385a43c4ec5abf110bfd81b8a97`;
generated Rust SHA256
`27b635946e338d07deee5e85a08328df783b685a9d3d8e50adc9e78fa351f8be`.
All predecessor 55b680a workflows passed:40882025279,40882015998,40882016170.
Historical Windows process-exit timeouts remain unresolved and preserved.

The remaining report/epilog integration is a concrete emitter boundary:
`main_completion` accesses `memory.image.words` for protected metadata and uses
separate `memory`, `printf` and `effects` mutable interfaces. The native formatter
needs the same live runtime while memory holds it; the effect callbacks must
also consume live POP/RET tags in the original order. The next coherent change
should give completion, formatter and return effects one live owner with scoped
reborrows (or emit through shared typed CPU operations), rather than copying
ordinary bytes into FrameMemory and accepting a projected success. Preserve
writes and output if a later flush/guard/RET fails. Cover original report bytes,
nonzero/error return paths, short output, stale capture and corrupted saved words.
A bounded Astra design pass is appropriate if this shared-ownership interface
cannot be resolved on Sol. Full startup/rcedit stays unsupported until unchanged
entry-to-exit behavior is demonstrated; actual OS delivery and collided-unwind
assumptions remain separate gates.

Tracker reconciliation: the last Linear write returned an error, but its wrapper
retained only `isError` and discarded the response text. Exact failure/denial
classification cannot be recovered from the available tools. Readback shows
SUB-579 still begins at 16ec19c and its description has 248170 characters; the
proposed prepend would grow it further. A size limit is plausible, not established.
No write retry, alternate write route or denied optional PR comment was attempted.
These pushed records preserve both the 55b680a and current results. A concise,
reviewed description reconciliation should preserve history through repository
links; do not claim it succeeded without readback.

### Shared owner executes Main reporting and protected epilog

`main_completion::prove_owned` now uses the same instruction analysis as the
existing completion compiler while emitting calls to one mutable host. The
legacy compiler remains tested. Protected predecessor/saved/return reads use
explicit methods rather than direct emitter access to image words. The new host
owns canonical CRT memory, the live CPU, `NormalReturnSession` and a scoped native
callee binding. No memory borrow survives across the callee or effect calls.

Original argument PUSHes and cleanup act on the actual guest stack at their
instruction points. Known register writes are reflected in the live CPU before
callee entry; unknown flags remain unknown. Global and ordinary reads use live
bytes, while saved/predecessor/guard reads validate original metadata against
actual protected tags. The original security helper is separately proved and
executed through a fresh protected CALL; its safe CMP/conditional-RET path checks
runtime bytes and cookie identity. Unproved security failure remains rejection.
Original POPs, FS predecessor restoration and RET update live storage/control
state together with the return session. A successful RET consumes Main's existing
root once and issues the existing normal-return receipt.

The connected event test now executes the actual 357 Main completion bytes from
0x4013b7 through 0x40151b. It verifies all17 variadic words and independent original
address offsets, plus EAX/ECX/EDX at native callee entry. Its component state returns
1, not an assumed zero exit. A native callee return of -1 is ignored by original
Main and yields the same return. Eight negative paths reject a failing callee
cut after an observable effect, corrupted guard after the call, unknown global,
changed Main code, scalar-forged module pointer, changed format, changed security
code and duplicate Main return authority. Earlier output-boundary observations,
register writes, pushes and POPs are preserved on later failure; no normal return
receipt is produced for a failed path. These are overlapping native component
scenarios, not new whole-program comparisons.

Two explicit cuts remain in this connected test. The native callee callback
records the actual arguments and performs a protected RET; it does NOT execute
the original printf wrapper/formatter or assert physical stdout bytes. Three
outer-frame globals missing from this two-frame fixture are initialized zero as
an entry premise; original Outer effects are not inferred or replaced by expected
report values. Other cleanup state and report arguments come from the connected
live execution. Consequently the two Main returns and eight failures establish
owner/control composition, not unchanged-binary entry-to-exit equivalence.

Verification passed:175 root,176 frame/unwind and168 CRT tests, one separately
replayed prior recorded observation, formatting,Clippy, original-artifact wrapper
and projection checks.194 owned-frame scenarios overlap the new two returns and
eight failures. The unchanged PE SHA256 is
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
Main completion SHA256
`560d19417b61b35507c2dfda962493687a1749a2a942b39c70fe99b35dc2d1ec`;
generated Rust SHA256
`fbcc4ba4344f9915a3cbff73e929d41c7a6f62d1dfba58d1fe3751af83cffebc`.
All996647c CI passed:40885458557,40885447321,40885447371. No new Windows differential
or whole-PE translation pairs are claimed. Historical Windows timeouts remain
unresolved; no retries/threshold changes were used to hide them.

Next bind the actual original printf wrapper/formatter to the host's native
callee interface, including its nested frame/lock/FILE effects and buffering,
short-write,error/flush behavior. Then connect the remaining original outer-frame
invocation and module/thread entry conditions. Preserve actual event acquisition,
incoming-handler and collided-unwind barriers; do not admit a program merely
because this callback/entry-state component passes. The one-owner interface now
allows these native components to share the same runtime without snapshots or
simultaneous mutable borrows. A focused Sol review can audit this boundary before
the formatter's larger control/lifetime integration; use bounded Astra only for a
specific unresolved effect/ownership question. PR45 stays draft; full startup and
rcedit remain unsupported.

Tracker reconciliation completed separately: the previous248170-character
SUB-579 description was preserved verbatim in SUB-579-HISTORY.md at533558e and
pushed before replacement. A concise description with durable evidence links,
acceptance criteria and unresolved blockers was accepted and read back. This
resolves the tracker write; the discarded earlier response still prevents an
exact retrospective error/denial diagnosis. No denied optional PR comment was
retried or sent through another route.

### Original printf routing and measured formatter-state barrier

`crt_printf` binds the existing wrapper/accessor certificate to shared native
instruction emission. The original44-byte printf wrapper,16-byte iob accessor and
6-byte options accessor execute with actual protected CALL/RET and original
stack routing. Their numeric results acquire typed authority only from the
instruction-proved FILE/options binding plus live object validation. FILE object
identity is distinct from field/lock initialization. Code mutations, unknown
options, typed vararg corruption and retired FILE storage reject.

Two new connected cases pass all17 runtime arguments through these original
bodies and return Main's original status1 when the separately supplied formatter
result is0 or-1. They replace the printf-wrapper callback in these cases, but the
stdio-common formatter return remains an explicit callback. No text bytes are
fabricated or claimed as an original formatter result. Existing direct-boundary
cases remain separate regressions. Basic options[0,0] and FILE-array storage are
component entry premises; no whole CRT initialization is asserted.

The original formatter-entry prefix and complete locale-context constructor also
execute. The experiment reaches the unknown branch word at0x41ce7c and returns
exactly `CRT unknown scalar bits observed`. Independent assertions check that
the original object pointer/flags were zeroed before the error, the global stays
unknown and no successful formatter or Main return occurs. The FILE read guard
still rejects stdout field access without its constructed lock. The missing word
and possible pointer objects behind0x41c230/0x41c234 require initialization,
identity/lifetime and mutation evidence, not an assumption that image zeros or
sampled C-locale execution describe all startup behavior.

The concise current inventory is REMAINING-CALLBACKS.md. It distinguishes original
body execution, full-body callbacks, component entry state and unresolved API /
exception effects, including the separate integer C++ record. The next scope is
the complete live formatter domain/driver/parser/integer/output/cleanup composition,
not another per-accessor behavior stub. The constructor-state rejection is a
specific observed gate and is retained rather than converted into defaults.

Verification:175 root,176 frame/unwind,172 CRT tests passed; one observation test
was separately replayed. Formatting,Clippy,artifact wrapper and projection checks
passed.202 overlapping owned-frame scenarios include two original-printf returns,
six new rejection scenarios and one formatter locale-state rejection (overlapping
those six). Zero new Windows differential or whole-PE translation pairs.
PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
printf wrapper SHA256
`f7b8a4414c8d6e6c6168380445137bd5af31ad9d2f07ba897f02ff77d73dd874`;
formatter entry SHA256
`24e55c2bc2dfde4db26e4dc075aeb0d063ead5f95894ea2507a161c7bfd0cba0`;
constructor SHA256
`5f419899435ee3eaa1f775c62db5d720afa6772c45dd679ddaad9f197edd5cb6`;
generated Rust SHA256
`b08d034d74d533bf355ebb77c88f286864acba4e309b8b9d4891e18b0eb3f09f`.
All adc3c85 CI passed:40891737061,40891728505,40891728829. New-head CI remains
required. PR45 stays draft. Full startup/rcedit remains unsupported and historical
Windows process-exit timeout artifacts remain preserved and unexplained.

### Runtime-bound locale identity and original mutation evidence

Independent review of `dbb3edd` reproduced a concrete locale-token collision:
two runtimes with identical numeric owner/thread/FILE address and first locale
generation accepted each other's bare generation. `CrtLocale` now includes the
unique guest-memory anchor, thread and generation. Validation also rejects a
closed runtime. The new native regression first failed on the old implementation
and now checks cross-runtime use/retirement, wrong thread, stale generation,
expired FILE lock, exhausted generation and shutdown. Failed checks preserve
the valid local token. A checked token leaves an unrelated unknown module word
unknown: it is a lifecycle identity, not locale data initialization or formatter
admission authority.

All three `dbb3edd` workflows completed successfully:
`40897169559`, `40897152314`, `40897152286`. Local verification of this review
passed 175 root,177 frame/unwind and 173 CRT tests (one observation test is ignored
in the default CRT suite and separately replayed by the artifact checker),
Clippy and formatting. The startup Python suite passed 55 tests with one separate
skip. The added evidence regression distinguishes file-backed pointer cells from
virtual zero fill and rejects changed mutation edges/stores. Existing owned
scenarios remain 202, not an additional202 independent Windows comparisons.

`formatter_binding.py` and the cross-host wrapper report now retain
`locale_state_evidence`, with `runtime_state_proven=false` and
`emission_allowed=false`. Exact original instructions show the conditional
branch-word mutation and multibyte-info store described in
`REMAINING-CALLBACKS.md`. These are possible static effects, not proof of startup
reachability, an exhaustive effect inventory or dynamic observations. The
constructor's unknown-state rejection remains unchanged. Original FILE table
storage, a valid lifecycle token and the existing stream-initializer certificate
do not establish live locale data, FILE fields or unbound callee effects.

The unchanged PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
Generated wrapper Rust SHA256 is
`15f3b88828d72c78819fd47f493ffd4c2b100a7b2367fef332bc79a0cefc8dc7`.
The artifact checker replays the five existing recorded Windows boundary
comparisons; this review adds zero fresh Windows observations, zero full
formatter-output comparisons and zero whole-PE translation pairs. Full formatter
integration is blocked by the specific producer/effect obligations in the
inventory, not by approval or tooling. PR45 stays draft and SUB-579 In Progress;
full startup/rcedit and historical timeout causes remain unproved.

The local projection checker retained a separate failure: its `owned` batch hit
the unchanged 15-second limit. The traceback and generated source/binary remain
under the local `live-dispatch/locale-identity-20261029/projection` evidence. A
separately instrumented diagnostic run completed all 202 cases in 12.896 seconds;
no case exceeded 0.2 seconds in that diagnostic. This suggests aggregate timing
margin needs attention, but does not identify why the first run exceeded its
limit or turn the failed check into a pass. No retry, timeout increase or result
suppression was added. This Linux component timing observation is distinct from
the historical original-Windows process-alive failures. New exact-head CI is
still required; the review does not claim every local gate passed.

Reproduction (with the documented Rust/Z3 environment and a writable TMPDIR):

```sh
cargo test --offline --locked --example crt_stream locale_identity_rejects_another_runtime
python3 -m unittest discover -s research/process/startup -p test_formatter_binding.py -v
python3 research/process/startup/formatter_binding.py ORIGINAL_DIR EVIDENCE_DIR
python3 research/process/startup/check_normal_wrapper.py ORIGINAL_DIR OBSERVED_DIR NATIVE_DIR
python3 research/process/startup/check_projection_boundary.py NATIVE_DIR/normal-wrapper.rs PROJECTION_DIR
```

### FILE construction results and opaque critical-section storage

Review of the runtime-bound locale identity fix found no new identity escape.
The next connected FILE transition now consumes an explicit
`InitializeCriticalSectionEx` result. The original initializer calls the thunk at
`408079`, whose complete bytes tail-jump through IAT `4150ac`; the retained PE
binds that slot to `kernel32.dll!InitializeCriticalSectionEx`. The artifact
checker verifies both identities. The original initializer ignores the Boolean
return, so its next use cannot itself prove construction succeeded.

The shared runtime's result adapter requires exclusive initialization authority,
the exact live FILE lock range (offset 32, 24 bytes in this admitted x86 layout),
flags zero, no existing constructed lock and no typed aliases in that range.
Any nonzero API result creates lock ownership; zero does not. The result remains
an external effect input, not a fabricated OS success. Because the API object
representation and last-error value are not established by the result alone,
the adapter invalidates those byte/value facts. It preserves earlier FILE fields
and table writes. Subsequent ordinary loads/stores into a constructed critical
section reject even while initialization authority or a FILE lock is held.

This follows Microsoft's [InitializeCriticalSectionEx contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex):
nonzero success, zero failure, initialization before use, no reinitialization
without deletion, and logically opaque object storage. This is a bounded
exclusive component domain; concurrent scheduling, arbitrary object layouts and
all flag modes are not implemented by this adapter.

The existing emitted original initializer/fallback/teardown test now calls this
result adapter. Independent values 0, 1, 7 and UINT32_MAX distinguish failure from
all nonzero successes. Tests cover foreign runtime authority, narrowed or shifted
ranges, duplicate construction, unsupported flags, typed aliases, overlapping
byte writes and opaque reads. Failure on the second lock preserves the first
lock/table entry and leaves the second table entry untouched and its lock
unusable. This reduces the construction-result obligation; it does not close
allocator, low-I/O, locale producers or execute the full formatter.

Local checks passed 175 root,178 frame/unwind and 174 CRT tests, with the existing
observation case separate from the default CRT suite. Formatting and Clippy
passed. The prior head 6b38b38 startup workflow 40902148938 passed; both full
workflows 40902159730/40902148774 had eight passing jobs with only
compiler-native-linux still running at review. The earlier local projection
15-second timeout and historical Windows process timeouts remain distinct and
unresolved. No timeout/retry policy changed and no new whole-PE pair is claimed.

Next: bind original locale object producers/mutations and FILE low-I/O state to
the shared live owner, then connect the formatter driver and its ordered cleanup.
The full formatter callback remains explicit. Sol can review this bounded result
adapter and verify CI; the remaining original startup/locale effect composition
still needs a focused semantic pass. PR45 remains draft.

Artifact replay and the projection check passed on this changed implementation.
The five Windows comparisons reuse the retained observations; no fresh Windows
run or whole-binary conversion is counted. PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
generated Rust SHA256 is
`ab536c87b5e3a0876361bed1ca9d60d4e715947d886e4aa80ca1a386b65b222a`.
The construction-thunk hash is
`01565efe983e9c4227f23d12a585198bbaed33e7ed2081e0d04fe375ba1bd5ad`.
The previous implementation's local projection timeout remains retained; this
changed-head pass does not establish its cause.

### Original standard-handle initializer execution

Independent review of `1ca0c21` found no new escape in successful lock ownership,
opaque-byte protection or preservation of writes before a later failed lock.
Its startup inventory workflow 40905043369 passed; full workflows 40905052442 and
40905045688 were still running at this checkpoint.

The next low-I/O dependency now executes the complete original 176-byte graph at
`4085e7..408697` through the shared decoder, typed storage and native emitter in
`crt_standard_handles_tests.rs`. The artifact checker binds every fixture byte
and both actual IAT slots (`GetStdHandle`, `GetFileType`) to the retained PE.
This is test-only component execution with explicit API outcomes and pre-owned
records, not new production admission or a Windows API replacement.

Five independent positive cases cover disk, character, pipe, an adversarial
high-bit scalar return and zero type. The original code tests the full result
for zero before selecting on AL; it marks character and pipe flags differently.
It preserves a preexisting inherited handle and does not query it. A null handle
from GetStdHandle skips GetFileType, sets the detached sentinel and updates the
corresponding FILE field through the actual typed table. Zero GetFileType can
mean a valid unknown type or an API error: [Microsoft documents both](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype).
This original body treats both alike without querying GetLastError; the tests do
not invent an error code. The high-bit case is adversarial arithmetic evidence,
not a claim of a current OS return or platform support.

Four negative classes, each executed across the five schedules, cover unknown type information,
a scalar replacing table-pointer authority, a foreign-runtime handle and a
truncated table target. Later rejection preserves earlier detached-handle/FILE
writes and the original flags store; it cannot promote unknown information into
an initialized descriptor. The tests also check callee-saved registers and
protected stdcall cleanup. Repeated early failures do not add distinct coverage. The five positive plus 20 negative runs are 25 native
component executions, with zero fresh Windows observations or whole-PE pairs.

Default CRT verification passed 175 tests with one recorded-observation test
separate; formatting and Clippy passed. Root and frame behavior is unchanged
from the reviewed 175/178 checks. This component still assumes block allocation,
inherited-handle input and initialized table ownership. Next connect the actual
preceding allocation/inheritance producers and bind the resulting records to
FILE initialization on the same owner; retain handle lifetime/alias/failure
contracts and the separate locale producer gate. The full formatter callback
remains explicit. Both timeout histories remain preserved and unresolved.

### Inherited startup records feed standard-handle initialization

The original 176-byte inherited-record parser at 408537 now executes before the
original standard-handle initializer on the same typed owner in a connected
native component test. The artifact checker binds both bodies and the actual
GetStartupInfoW/GetFileType import slots to the unchanged PE. The supplied API
output initializes only the fields actually read; a zero reserved-data length
exits without reading the unknown pointer field. An initialized serialized count,
flags and typed handles feed the actual parser stores, after which the original
standard initializer queries only the remaining missing handle.

The shared IR/emitter now admits exactly word-memory CMP with sign-extended
imm8, and 32-bit signed CMOVL/CMOVG forms. Independent literal boundary vectors
cover 16-bit carry/sign/overflow, negative immediates, signed 32-bit extrema,
equality, unknown flags and mandatory memory-source evaluation on an untaken
CMOV. Other operand/segment/address overrides and 16-bit register forms remain
rejected. The new forms do not grant startup or general graph admission.

Seven inherited-path executions cover the connected success path, empty reserved
data, truncated serialized bytes, unknown count, scalar handle fabrication,
expired buffer lifetime and an unclosed allocation request. A later truncation
preserves the earlier imported handle while refusing to read the next incomplete
word. The explicit allocation callback accepts only already-provisioned capacity;
it does not fabricate allocation or OS failure behavior. API volatile registers
and flags are invalidated, and callee-saved state/protected return are checked.
These are component executions with declared startup/handle inputs, not fresh
Windows observations or whole unchanged-binary translations.

The concrete remaining allocation gate is 40BF2A and its block constructor 40BE7A:
64 records of 56 bytes, with critical sections at record offset 0. FILE locks are
at offset 32. Heap allocations currently carry Buffer role, while low-I/O records
require Descriptor role plus independent lock construction/lifetime. Reusing the
FILE adapter or changing pointer-kind bits would grant incorrect authority.
The coherent next scope must bind allocation and the typed record/lock lifetime,
then feed inherited parsing, standard handles and FILE startup on the same owner,
including partial allocation/lock failure and EH4 cleanup. Locale producer and
full formatter gates remain separate. This is a concrete ownership refactor
suitable for bounded Astra High after Sol review.

CI for a5db451: startup run 40906539916 failed in native-unwind-slice job 123565233818,
where the `owned` command exceeded the unchanged 15-second projection limit.
Artifact 12912002933 was uploaded successfully; archive SHA256 is
`29258b8fa930284ff2819e46697c8edca260d23acfbdeadd86c5faf9c434fce0`.
This reproduces the same command/limit symptom as the retained local failure,
without proving the underlying cause. It is distinct from original-Windows
process-alive timeouts. No passing rerun is used to erase either history.

Opt-in case timing now records the start/completion of each of 202 owned-frame
cases. The command also runs its existing initialization/raise prechecks. The
projection checker preserves partial stdout/stderr and a status/elapsed report
on timeout or process failure and rethrows the failure. The limit stays 15 seconds;
there are no retries. Successful output must include all ordered completions
and no extra output. Two independent harness tests verify retained timeout data,
continued failure, full coverage and rejection of reordered/noisy diagnostics.

Final local checks: 177 CRT tests passed (the existing observation test is
separate), 178 frame/unwind and 175 root tests passed; formatting, Clippy, artifact
replay and the two diagnostic tests passed. The changed implementation's
projection command completed in 12.335 seconds with 202 ordered case timings. This
is a new implementation measurement, not a diagnosis or removal of prior failures.
The five existing Windows boundary comparisons replayed; zero new Windows pairs
or whole-PE translations were added. PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
generated wrapper Rust SHA256 is
`d470d50085cbed3e52c08ca11b4b8bbdfeaa8abf618e00b798284a021f4341cb`.

## Descriptor allocation, distinct lock lifetime and connected original bodies

The private CRT memory kernel now issues a descriptor role at allocation time,
before exposing the capability. It does not relabel an escaped Buffer pointer.
The bounded request is 1..64 records of 56 bytes with checked heap availability
and zero initialization supplied by the calloc effect contract. The constructor's
actual calloc helper also has new-handler and errno paths; those complete effects
remain unbound. Null-return tests are component boundaries, not complete helper
failure equivalence.

Descriptor critical sections occupy offset 0..24, unlike FILE offset 32..56.
Construction consumes a checked external BOOL outcome and forgets opaque bytes;
FALSE creates no lock. Record locks have runtime/capability/thread/serial identity
independent of a not-yet-imported handle. Record access after initialization needs
the exact record lease or existing exact descriptor lease. Lock destruction and
allocation release reject live leases/bindings; a descriptor allocation must be
released through its full root. Existing base-pointer Buffer free behavior remains
unchanged. Opaque lock bytes cannot become ordinary loads, stores or output bytes.

The unchanged constructor `40be7a..40bef5` and destructor `40bef5..40bf2a` now run
through the shared decoder/emitter and protected calls. The produced block feeds
the original inherited parser and standard-handle initializer in the same runtime.
Four component schedules cover full construction/import/destruction, null allocation,
second-lock failure retaining the first record's writes, and destruction blocked
at a live second-record lease after the first lock has already been destroyed.
The original constructor ignores the lock API BOOL; continuation after FALSE is
still explicitly rejected, not substituted with an invented original return.
The manager/table publication/global-lock effects remain declared component inputs.

Original constructor address traversal briefly creates an address 32 bytes beyond
the block before subtracting back. `LEA` now retains capability/subrange identity
through such address calculation. Ordinary effective addresses still validate
range, and every load/store validates its full width. Out-of-range pointer storage,
neighbour-allocation access, foreign role and stale lifetime remain rejected.
The existing signed-index memory rejection test remains unchanged and passes.
Unknown entry ECX is an explicit volatile scalar, not a protected saved-register
slot or a fabricated zero.

Two independent native regression functions cover count/resource limits, failed
allocation atomicity, typed alias rejection, distinct FILE/descriptor offsets,
foreign tokens, unknown opaque bytes, duplicate construction, ordered/stale leases,
handle binding, close/destruction/free ordering, exact slot boundaries, adjacent
regions, narrowed subranges and stale computed addresses. The original four-case
composition is additional component evidence; it supplies no new Windows pairs.

Local verification: 180 CRT tests passed (one recorded-observation test run
separately by the artifact checker), 180 frame/unwind tests and 175 root tests
passed. The five existing recorded Windows boundary comparisons replayed. Full
formatter/startup/rcedit admission remains rejected; whole-PE pairs remain zero.
The unchanged PE hash is
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
new generated wrapper Rust hash is
`5e3ac4dbfe36db78e5719e9bd7083b5a253e97db0e566dc6a5e25f9159c59e5f`.
Constructor hash `ed3f4e10179a221e87069b15899a9a8f57b49cc8b3c7e78da2c81dfdff1e03ba`
and destructor hash `adf905229815b123eeba9374e8e869b070327b72bbbb884fbb55ec5f7cf72042`
are checked against the original PE, including DeleteCriticalSection import identity.

### Projection failure measurement, with failure preserved

For `c44f2a3`, both full Rust workflows 40909024429/40909012580 passed. Startup
40909012601 failed the unchanged 15-second owned projection batch, job 123574640413;
all its other jobs passed. The uploaded artifact 12914070783 has ZIP SHA256
`2f7dc5316a1d0bc1092c952b897f0315d0e5a0c7ccdb57f77d527ea4abaf7c5b`.
Its original timing records and provenance are retained in
[evidence/projection-c44f2a3](evidence/projection-c44f2a3/).
The batch completed cases 0..198 and started 199 at timeout. Completed durations
sum to 14.938595 seconds; the largest was 0.194904 seconds (case 196). This is
observed aggregate budget exhaustion with ongoing progress, not evidence that one
case hung. It does not explain the original-Windows process-exit timeouts.

The projection harness now compiles with `-Copt-level=1`, explicitly retaining
`-Coverflow-checks=yes` and `-Cdebug-assertions=yes`. Every case, assertion, checked
memory operation, 15-second deadline and fail-on-timeout rule remains. A controlled
local run of the same saved c44 generated source completed all 202 cases in
1.516212 seconds. This is a measured harness performance change, not a retry erasing
the prior failure. Build commands and per-case output continue to be retained.

Earlier `a5db451` push CI 40906539904 passed; PR CI 40906552121 failed the imported
output original-Windows fixture at its 15-second process timeout (job 123562781377).
That failure and startup projection failure 40906539916 remain in the history.
No claim that either historical timeout family has been generally eliminated.
