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

## Allocation manager scope and distinct global lock

Review of `1055f51` retained all descriptor/FILE ownership boundaries and verified
that projection compilation keeps overflow checks, debug assertions, every case,
and the 15-second timeout. Startup workflow 40912897460 passed. The two full Rust
workflows 40912908434/40912897599 remained running at this checkpoint; neither is
reported as passed. The earlier Windows process-alive failures remain unresolved.

The shared component kernel now has a separate module-global critical-section
identity and lease, bounded to 32 indexes and 32 nested leases. A successful
initialization outcome is explicit, not assumed from zero bytes. Storage has
checked owner, runtime, lifetime, alignment and full 24-byte bounds. Typed aliases,
overlapping locks, duplicate construction and opaque byte access reject. Leases
carry runtime/thread/serial/index/storage identity; stale or foreign/out-of-order
release, live destruction, phase transition with a lease and serial exhaustion
reject. These leases cannot be supplied as FILE or descriptor-record authority.

The original manager body `40bf60..40bfbc` now executes with the original cleanup
funclet `40bfbf..40bfc8` and descriptor constructor on the same guest stack. Original
instructions acquire lock 7 before scope activation, publish blocks and capacity,
retain earlier blocks on later null allocation, set scope -2, execute cleanup,
and exit at the explicit pre-epilog boundary `40bf4e`. Protected call/RET validation
covers constructor and cleanup calls. A release failure preserves the held lease,
scope write and previously published blocks; acquisition failure never activates
the scope. Six native schedules check full two-block growth, partial allocation
failure, acquisition failure, release failure, request zero (which the original
strict comparison expands to one block), and immediate null allocation.

These are component executions with a supplied live initialization token, owned
frame/local extent, initialized request, global-lock initialization and declared
API outcomes. Enter/Leave helper/API effects remain explicit contracts. Injected
acquisition/release failures are adversarial contract failures, not new Windows
observations or claims about a particular exception code. Actual EH4 prolog,
registration, exception-triggered cleanup invocation and outer epilog are not
closed by supplying this frame. This scope therefore does not enable full startup,
formatter, ordinary CRT or rcedit. The invalid-request path, new-handler/errno,
HeapFree failure and locale producers remain open.

Independent global-lock tests check foreign runtimes, wrong initialization tokens,
role/index/alias rejection, false initialization, unknown opaque bytes, wrong thread,
LIFO/replay, live destruction, serial exhaustion and stale initialization. Existing
ownership, partial-failure and address tests remain. Local verification: 182 CRT
passed (recorded observation test separate), 181 frame/unwind and 175 root passed;
Clippy and Python checks passed. Original manager/cleanup bytes are artifact-bound
in the wrapper checker. Five existing recorded Windows boundaries replay; six new
manager schedules are native-only, with zero new Windows or whole-PE pairs.
Generated wrapper Rust SHA256 is
`2e10d7e8e4b2239b15d0a4de7664df354899edf0d8b7e9cc699aff74ad1cb06a`;
PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.

Next connected scope: bind this manager's actual EH4 frame/registration/epilog and
lock helper instructions under the existing thread ownership machinery, then call
it from the inherited producer. Keep allocator/API effect cuts explicit. Sol can
continue; a concrete unresolved exception-effect contract would justify a bounded
Astra pass. Locale production and complete formatter integration remain mandatory.

## Registered allocation manager called by the inherited producer

Review of `25d29a9` kept the distinct global/record/FILE lock identities and partial
failure ordering. Startup CI 40915016998 passed. Both full Rust runs
40915027942/40915017038 were still executing their final independent LLVM
comparison step at this review; no full CI success is inferred from that state.

The shared normal-call binding now has an explicit initialization entry requiring
the exact live `CrtInitialization` token. It retains that token and validates it
on subsequent binding transitions, together with arena/thread/epoch/record and
saved-state authority. Ordinary `bind` still rejects initialization. Foreign
initialization tokens and ending initialization before epilog cannot authorize
return. This adds no initialized bytes or exception-delivery proof.

The unchanged manager prolog helper executes with allocation 16 and scope
41b6a0, installs its record into the live normal-call registry, executes the
allocation loop/normal cleanup, performs the original MOV EAX,ESI, unlinks through
the original epilog and validates its return. The generic epilog proof now also
accepts plain RET as zero callee-pop bytes, preserving every saved-slot, scope,
guard, registry-order and protected-return requirement. A changed saved-register
POP is independently rejected by the epilog proof.

The original inherited-record body now calls this registered manager through a
protected call on the same guest stack. A new native case starts with capacity
zero, produces the descriptor block, restores the previous thread-chain head,
returns to the inherited parser and imports the two valid inherited handles.
Five registered-manager cases cover success, corrupted guard, revoked
initialization authority, null allocation and foreign initialization token.
The component bridge rejects request >=8192 before registration: the original
invalid-request/errno/API branch remains unbound. A regression checks that this
rejection changes neither registers nor registry head. It is not replaced by the
allocation loop's different error behavior.

The artifact checker now binds the manager PUSH allocation/scope/CALL bytes and
epilog bytes in addition to the existing helper, loop, cleanup and inherited
bodies. It runs both new registered component tests on each host, alongside the
five pre-existing recorded Windows boundary comparisons. These six registered
scenarios and the invalid-request negative are native component evidence, not
fresh Windows observations or whole-PE translations. The existing completed-event
registry fixture, initial module/thread state, global-lock initialization,
GetStartupInfo/GetFileType results, calloc/new-handler/errno and API exception
effects remain explicit cuts. Full startup/formatter/rcedit remains unsupported.

Local checks: 184 CRT passed (one recorded-observation test handled separately),
181 frame/unwind and 175 root passed; the focused changed-epilog and invalid-request
checks passed after review. Clippy/format/Python checks passed. Both historical
Windows process-exit failures and the separately preserved projection-budget
failure retain their earlier evidence and qualification.

Next connected scope: execute the actual global-lock helper instructions under a
bound module lock table, then establish calloc/new-handler/error effects and
FILE/locale producers. Actual startup entry and exceptional cleanup/delivery
remain separate admission gates. Sol can continue this path; escalation needs a
concrete unresolved semantic question.

Registered-manager wrapper Rust SHA256: `8298843fe741e1f31a505d3b94e41acaefd744e4f5b484d30ed9988d6bd0870f`.
The unchanged PE remains `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.

## Indexed global-lock helpers through the registered manager

Review of `4c9a1d6` retained initialization-token lifetime, manager cleanup ordering,
protected return and corruption checks. Startup workflow 40917003089 passed;
Rust workflows 40917011420/40917003240 were still running at inspection. No
historical Windows timeout has been diagnosed or discarded by these results.

A reusable private helper certificate now validates the complete indexed cdecl
helper, including its saved EBP, argument at EBP+8, IMUL stride24, ADD table base,
API call and RET. It binds the supplied import/table roles and rejects truncated
or changed argument, stride, import, saved-register/return and code/table/IAT
alias forms. The original helper instructions execute in the shared native
emitter. At the API boundary, the scalar computed address must agree with the
exact constructed module-global object for its bounded index and table. No
integer-address coincidence creates a capability or authorizes another object.

The registered allocation manager and cleanup now call these original Enter and
Leave helpers rather than shortcutting their instructions. API effect callbacks
still own synchronization outcomes and exceptions. A failure after acquisition
preserves the lease and earlier memory effects; it never fabricates epilog
completion. The proof is shared by both helpers and permits relocated tables and
imports under the same protocol, without application-name/hash dispatch.

Two independent test functions cover changed complete helper forms and 40 native
index/effect schedules across two module table locations, plus two mismatched
object/table checks. Valid indexes0/7/31, index32/-1, unknown argument, absent
constructed object, volatile-result knowledge, saved-register restoration and
failure after acquisition are checked. Existing manager, inherited producer and
EH4 lifecycle tests still pass. The helper module is currently wired into the
component example's tests; this does not change whole-PE converter admission.

Original helper hashes are
`b2181e2d5d9e8fcb2ab12060b38d0efb1e11dc9bd4d29676179f7a521e8e7df1`
and `9b394c6a93fd4e9ffa27b07f229bd21be454dae81f2812c6f5d451b8390ddcbf`.
The wrapper checker binds both to the unchanged PE and the actual Enter/Leave
imports. New wrapper Rust SHA256 is
`b437fd1cd32cf422d64f473743ad310851f3932b79e5e334a7175a5ede885d7c`;
PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
Five existing Windows boundaries replayed. There are no new Windows observations
or whole-PE translation pairs. Local checks: 186 CRT passed (existing observation
test separate), 181 frame/unwind and 175 root passed; Clippy and Python passed.

[ALLOCATOR-EFFECTS.md](ALLOCATOR-EFFECTS.md) records the next cohesive gate from
actual allocator, new-mode, heap-producer and free instructions plus primary
Microsoft contracts. In particular, allocation failure does not imply an empty
API effect: new-handler retry and thread-owned errno remain to connect. HeapAlloc
failure does not set LastError; zero-request physical allocation is not authority
to expose readable requested bytes. The pinned heap producer's IAT4150f8 is
GetProcessHeap; allocation/free/error IATs415094/415098/415044 are HeapAlloc,
HeapFree and GetLastError. Current descriptor allocation-result callbacks still
replace those helper effects. Full formatter/startup/rcedit remains unsupported.
Sol can continue the actual heap/allocator/error connection; no new architectural
escalation is required merely for routine integration and verification.

## Original heap acquisition and calloc/error control flow

The private component runtime now carries an opaque process-heap identity tied to
its arena/lifetime and an explicit exception-policy input. It transports through
full typed words, rejects partial reads and foreign-runtime handles, and grants
no numeric address or pointer authority. TEST of the same non-null heap token
proves only ZF=0, CF=OF=0; sign remains unknown. The actual producer's SETNE AL
replaces only AL, loses heap authority in EAX, and leaves upper bits unknown.
The separately stored typed heap token remains usable. No stable host handle
value or cross-thread/process sharing guarantee is invented.

The original GetProcessHeap producer `40c8f0..40c901`, calloc body
`407cf0..407d50`, and new-mode getter `4071c0..4071c7` execute through the shared
IR/emitter, protected calls and original branches. An exact two-operand 32-bit
IMUL form was added using the existing signed low-product/CF/OF computation;
unknown operands reject and undefined ZF/SF remain unknown. Literal boundary
vectors include MIN*-1, MAX*2, negative non-overflow, zero low product and memory
sources. Partial-width and LOCK variants reject.

HeapAlloc's bound component effect requires the live opaque heap, exact supported
flags and known non-exception policy, then allocates with the already checked
role/lifetime/initialization kernel. Failure preserves prior LastError; success
leaves its knowledge unknown. A HeapAlloc result alone is not treated as calloc's
complete behavior. Original instructions read new-mode on failure, call the bound
new-handler effect with the actual requested byte count, honor retry/decline,
and execute the original errno12 store before returning null. The errno accessor
is still a declared effect returning an exact live, separately mapped four-byte
thread-context cell; its actual implementation and side effects are not closed.
The new-handler implementation is also an explicit effect input. Unknown mode,
unknown heap policy, stale errno after a handler mutation, unsupported zero request,
and retry-budget exhaustion reject, retaining earlier writes/effects.

Thirteen native schedules cover success, terminal failure, overflow before API,
retry success, unknown mode, rejected handler continuation after a write, failed
heap retrieval, unknown heap policy, descriptor construction through actual
calloc, zero-request rejection, retry exhaustion, handler decline, and handler
retirement of errno before decline. The descriptor constructor's new test path
calls this actual calloc body rather than directly selecting its allocation
result. Its initialization/lock API effects are still explicitly bound. The
previously registered manager/inherited fixture still has its earlier allocator
result callback; connecting these two tested paths is an explicit remaining gate.

Independent kernel tests reject foreign initialization/heap identity, forged
scalar handles, wrong flags/extent, unknown exception policy, partial transport,
and expired initialization authority. Existing root/frame/ownership checks remain.
Artifact binding checks original producer/calloc/getter bytes and GetProcessHeap/
HeapAlloc imports. These tests are component evidence with declared input state,
not new original-Windows observations or whole-PE translations. Zero-request
calloc currently rejects before helper execution; no minimum physical allocation
is claimed to authorize readable requested bytes.

Local full CRT suite:189 passed, one separately handled original-observation test;
frame/unwind:182 passed; root:175 passed. Focused handler-argument/lifetime and
multiply boundary cases passed; Clippy/format/Python checks passed. The five existing
recorded Windows boundary comparisons remain the differential gate, not 13 new
Windows pairs. Full formatter/startup/rcedit admission remains unsupported.

Next: connect the actual allocator path into the registered manager with explicit
heap/mode/errno bindings; establish actual errno accessor/PTD and new-handler effects,
then original free failure mapping and locale/FILE producers. The source of initialized
mode and heap configuration cannot be inferred from a successful sample. Sol can
continue a bounded integration/review pass; escalate only a concrete unresolved
TLS/exception-effect question.

### Predecessor Windows timeout retained

For `772c3e6`, startup workflow40918525979 passed. PR Rust workflow40918534890
failed its authored-Windows job123605174805 during the combined imported/corpus
step: all seven imported cases completed, then original corpus case16 timed out
in process.wait after15seconds. PE hash for case16 was
`386f0579d2509323b1148ad53c8bd610187044352a5a1bd57fbffed60a993fbe`.
This is not a translated ELF failure. Artifact12917441977 (`corpus-launch-evidence`)
has ZIP hash `d2211dee3921c9f764cfee23e2499e36f45aa3ae8d0c54314238b583e7341379`.
The independent launch-diagnosis artifact12917287207 has ZIP hash
`163f38153d3c335a3afab71110d548db0fff06a726d6414598214e2c92c4f2db`.
Cause remains unresolved. Push Rust40918526018 was still running at inspection.
No retry, timeout relaxation or inferred diagnosis was used.

Heap/calloc checkpoint wrapper Rust SHA256: `37a9af55f16e6980a04f86dbe2d60a8effd73f75aeb0738a03f8a61ed027c689`.
PE SHA256 remains `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.

## Registered manager uses original calloc and canonical errno routing

Review of `bb7b991` preserved opaque heap/null/partial-register knowledge and retry
failure ordering. Its startup workflow40921033508 and push Rust40921033519 passed;
PR Rust40921040084 remained running at inspection. Historical Windows timeout
failures, including original case16, remain unresolved and preserved.

The registered manager/inherited producer now uses the original calloc body,
heap producer and new-mode getter on the same owned runtime and protected call
stack. It no longer selects the descriptor allocation result directly. Heap API
outcomes, heap exception policy and initial new-mode state remain explicit
component inputs. Existing manager null-allocation tests now pass through the
actual errno path before normal cleanup and validated EH4 return.

The original errno router `407ccd..407ce2` executes through the emitter. Its
PTD lookup is a callable external effect, allowing writes/failure before pointer
validation. A valid non-null result must be the exact live root of a ThreadData
region with the full prefix needed for offset16; forged integers, unrelated
Context storage, foreign runtimes and retired roots reject. A null PTD result
selects the original bound module fallback at41c130. The original pointer-valued
return is normalized only against this complete instruction/body proof and the
owned selected cell. Fixed image-address/load-base assumptions remain explicit;
no arbitrary scalar-address coincidence becomes pointer authority.

The accessor binds its selected four-byte cell as canonical errno storage without
initializing unknown bytes. Original stores update the known-value cache from the
actual bytes, and the stream error adapter writes that same cell. ThreadData
retirement invalidates the cache and future accesses reject; it does not renew
old pointer authority. Typed pointer writes into the errno scalar field reject.
A composition regression found that a stream error before the first accessor
could otherwise update only the old shadow cache. The actual-heap composition
now requires a bound canonical cell before that adapter can act; rejection leaves
the cell, errno and doserrno unchanged. Legacy isolated error-state input cuts
remain separate from this new composed path.

Nine errno-routing schedules cover fallback, PTD, scalar-forged pointer, wrong
role, expired PTD, unknown input, retirement after binding, foreign arena and a
lookup write followed by failure. They check canonical writes in both directions,
unknown-value preservation, and failure ordering. A separate regression protects
the pre-binding shadow error gap. Existing registered-manager failure ordering,
foreign initialization, changed epilog and root corruption cases still pass.
Local full CRT suite191 passed (existing Windows observation test separate),
frame/unwind183 and root175 passed. Clippy/format/Python checks passed. These are
native component executions and five replayed recorded Windows boundaries, not
fresh Windows observations or whole-PE acceptance. Full startup/rcedit remains
unproven; ordinary CRT/general app/XP7 and driver support are not claimed.

### Concrete remaining PTD and handler gates

The actual PTD getter40a332 calls prolog414268 and epilog414254. This is a different
record/continuation protocol from the current manager EH4 helper401e60: record at
EBP-0c, level sentinel-1, a variable stack reservation and epilog continuation
POP/PUSH relocation. Its installed handler is414ad6. Do not reuse the EH4 proof
by changing constants or assume no exception path exists.

The getter chooses TLS/FLS using41d130, index41c170, a dynamic function slot41e00c
or TLS import thunks. It preserves LastError on the TLS branch. Lazy creation at
40a1ee installs an initializing -1 sentinel before allocating1*0x364 bytes; failure
can call calloc/errno recursively, making the sentinel and fallback semantics
observable. The present routing callback does not prove these effects read-only
or complete. A bounded shared state/prolog contract is needed for lookup,
initialization, recursive allocation failure, cleanup and restoration.

The new-handler getter40ca20 locks global0, decodes the pointer from41d2cc with
cookie41c000 using406d47 (XOR and ROR), then unlocks through an EH4 cleanup.
Dispatcher40c9c0 performs a guard call through slot415128 before CALL ESI. That
slot is not an import-table binding in this image. Its source/target, callback
identity/lifetime and actual callback effects remain unproved. Sampled mode0 or
a successful handler callback cannot close this gate.

Routine review and CI belong on Sol. A bounded Astra High pass is justified for
the different PTD frame/continuation protocol and recursive TLS/errno state if
that is the next integration target; no Ultra is needed. Free-error mapping and
locale/FILE producers remain on the same critical path.

Registered allocator/errno wrapper Rust SHA256: `8dc49ff3bf8ffec192fcc69d83b730594638a2aa03a5a5400f9b7f840b0867f3`.
Unchanged PE SHA256: `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.

## Original PTD normal continuation and FLS lookup (2026-10-29)

Review corrected a concrete provenance error in the preceding inventory: the
import at4150a0 is **FlsGetValue**, not TLS; the dynamic name is **FlsGetValue2**.
See [PTD-FLS.md](PTD-FLS.md) for primary contracts and the complete supported-domain
and remaining-boundary description. Fiber identity is now distinct from thread,
runtime, FLS index and allocation generation; unknown or stale state is rejected.

The connected native errno test executes the original135-byte PTD getter,
51-byte prolog and20-byte epilog, plus the actual FLS thunk. The helper certificate
preserves the distinct variable-frame and moved-continuation ABI instead of
reusing the manager EH4 proof. Independent expected offsets across four frame
sizes, token uniqueness/replay, saved-register/guard/chain corruption, code/IAT
mutation, foreign fiber/runtime, slot reuse and retired PTD cases protect it.
LastError save/restore and sentinel normalization follow original instructions.
Unknown errno bytes remain unknown, and canonical writes use the selected cell.
Retiring a fiber also invalidates canonical errno knowledge/binding.

This is still an explicit normal-path component: existing initialized FLS/heap
state, the borrowed incoming head and no admitted exceptional delivery through
this record remain inputs. The manager's old PTD result cut is not silently
claimed closed. Lazy40a1ee allocation/recursive errno, failed setters and cleanup,
FlsGetValue2 resolution, the actual new record's live registry integration,
new-handler/guard effects and full locale/formatter/startup remain open. Original
null lookup rejects at the lazy-call boundary after preserving earlier effects.
There is no new program admission, fresh Windows pair or rcedit success claim.

Verification: full CRT suite196 passed/one existing observation test separate;
frame/unwind183 and root175 passed. Five focused PTD tests pass after the final
helper/IAT certificate and unknown-errno additions. Clippy, format/diff checks and
57 Python tests pass (one skipped). The artifact checker retains the unchanged PE
and five recorded Windows wrapper-boundary comparisons; it now binds PTD helper,
getter and thunk bytes plus the actual FLS import. Native PTD cases remain
separately labeled, zero new Windows/whole-PE pairs. Projection completed all202
owned cases in1.533seconds with the same15-second limit and assertions.

Wrapper Rust SHA256: `218df65548262081500fd96bf480041345ef54f06e11dcc8f193a59f2cc96bdb`.
PTD prolog SHA256: `4bd86fc014c6b4bc62ac075e441ebc162fabb51277692e679f58bd206520081d`.
PTD epilog SHA256: `48fda296793be6b2a3465d1d3bae4cd47eb5966f166ec10c7bfd01d4318dbb48`.
PTD getter SHA256: `faa3e4ab000682b51138fbc8b51753258055ea5cd96f46a51dc7a97d0303126c`.
FLS thunk SHA256: `6c9cde534e3bc89d09a7ad64399133317c2a2219c947afa1d4be5b5c6b4f06ad`.

Predecessor645a0ed startup40924630119 passed; both Rust runs40924641012 and
40924630001 completed successfully. Exact new-head
workflow conclusions must be checked after publication; no new-head CI pass is
inferred from local checks. The earlier case16 Windows timeout remains preserved
and unexplained, separately from the diagnosed projection aggregate-budget issue.
Sol can resume substantive independent review and bounded registry/FLS evidence
integration. No Ultra, formal approval, merge, release or full-startup claim.

Final state audit also removed stale helper-return authority from volatile
registers after RET: original ECX retains the numeric caller continuation, while
the consumed protected token cannot be pushed again as control authority. The
independent differently-sized-frame cases assert both the precise numeric PC and
absence of remaining protected-return values in registers.

## Sol review: lazy FLS setter and canonical errno invalidation

Reviewed a182104 continuation relocation/restoration and TLS→FLS provenance.
Found and fixed canonical errno surviving FLS slot retirement: mutation/retirement
now invalidates the binding/cache, without modifying the original PTD bytes.
A stale-generation/wrong-fiber/wrong-index setter rejects before effects. Failed
setter outcomes conservatively make slot knowledge unknown; undocumented failure
atomicity is not assumed.

Original lazy40a1ee..40a296 and setter thunk40806d now execute on the connected
getter stack through the first setter outcome. Failure returns null and restores
the outer LastError; success preserves the -1 sentinel, then rejects at actual
calloc407cf0. Unknown LastError can be saved/restored as unknown scalar state.
Seven focused tests cover these paths and prior continuation/ownership cases.
No new Windows observations or translated program pairs; original artifacts remain
unchanged, and the normal registry/exception cut remains explicit.

Inspected actual handler414ad6: guard(record-16) XOR(record+12), call40154c,
metadata41b42c, JMP403002. Metadata's first word is19930522, count2, unwind-map
pointer41b41c. This is a distinct three-word record/state protocol. The registry's
reserved Cxx kind has no admission implementation and explicitly rejects through
check_image; its existing independent negative test still protects that gate.
See PTD-FLS.md. A bounded Astra High pass is justified for the shared C++ metadata,
state/cleanup and continuation adapter; routine verification remains on Sol.
The existing EH4 certificate must not be repurposed by changing addresses.

Local verification: 198 CRT passed (one existing observation test separate),
183 frame/unwind and175 root passed; seven focused PTD tests, Clippy/format/diff
and57 Python tests passed (one skipped). Artifact-bound replay retains five older
Windows boundary comparisons and zero new whole-PE pairs. Wrapper Rust SHA256:
`4747748b1b1f775de195605cf2ca2e466d027c97978540abfc229708e17be489`.
Historical Windows timeouts remain unresolved, including case16. New checkpoint
CI must pass independently; no merge or formal approval is submitted.

### Distinct PTD C++ record and original handler prefix

The bounded adapter now binds the real three-word record, complete metadata and
unwind map to a live PTD normal frame. The original handler load/LEA/XOR and
metadata-load instructions execute with a fresh protected cookie-check call.
Unknown/corrupt guards, forged establisher pointers, overlapping call/frame
storage, stale/cross-runtime owner, invalid state, changed metadata/code and
post-epilog reuse reject. There is no C++ registry admission or cleanup receipt.

Both actual unwind entries select `4026fc -> 40770c`, a PTD-dependent termination
path. This new static finding rules out treating them as successful returning
cleanup. The common dispatcher and termination/callback effects remain unbound.
See [CXX-PTD-RECORD.md](CXX-PTD-RECORD.md) for the connected implementation and next
gate. Full formatter/startup/rcedit remains unsupported.

Local verification: 199 CRT tests passed, one existing observation test separate;
Clippy, format and diff checks passed. The final focused C++ test includes six
handler call/guard scenarios, state/lifetime checks and byte-mutation negatives.
Artifact replay passed seven prior PTD tests and the new C++ test, then the five
previously recorded Windows wrapper comparisons. There are zero new Windows
observations or whole-PE pairs. PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
wrapper Rust remains `4747748b1b1f775de195605cf2ca2e466d027c97978540abfc229708e17be489`.
Handler SHA256 `b61580e10d4983c8a533aaa4a2770d4146f2de0e445b3b868c2584ddc96ba722`;
metadata `90464cfd6bf7bc9a6f4ce0a354390f8194c197a2491a54990dd8fa4f6e642a44`;
unwind map `dd42109d84842589ecaf204820e2fdf4b9a01fea8212769d04aed9b0e6066443`.

Predecessor a182104 concluded: push Rust40928088917 and startup40928088993 passed;
PR Rust40928096259 failed at original-Windows corpus case24. Its preserved
process.wait timeout is unresolved. At this review, 89123fd startup40929659363
passed and both Rust runs40929667611/40929659415 were still running. No failure
has been removed, retried silently or explained by a different run passing.

### Common C++ wrapper and dispatcher entry connection

Sol review found no admission escape in the owned-record prefix. Original common
wrapper403002, thunk403e78 and dispatcher entry403d76 now execute after its guard
and metadata load. Seven native handler/stack cases verify exact argument forwarding,
protected nested call, failure preservation and the existing negative ownership
cases. Complete common/thunk/entry byte mutations reject. CLD uses the documented
existing forward-cdecl ABI domain (DF=0), preserving arithmetic flags; no unknown
Windows thread flags are silently initialized. A deliberately short stack rejects
after preserving the actual prior metadata write. No failed activation is reported
as completed cleanup or disposition.

Execution stops at original context-validator402877. Its guard-pointer branch,
CONTEXT saved-ESP read, thread stack bounds and fast-failure effects remain to bind
before dispatcher PTD acquisition and table traversal. Both unwind entries still
lead to termination. This is component evidence with zero newly translated PE
pairs. Full startup/rcedit remains unsupported.

Artifact replay passed with the same PE and wrapper Rust hashes above, seven PTD
checks, the connected C++ check and five prior recorded Windows comparisons.
Common-wrapper SHA256 `d3b9de408d983d602e1dea6518ad5fd4e6831732cb34aa7b09606f093c23d750`;
thunk `e20bdda8db1ae8aa50523ea8d431e785cf82b497c34ce93555cba41154261bf9`;
dispatch entry `1821f2e8cb0ab16faafa538d6f14d001319b0ea80a3279a73f0418f81ff48fef`.
199 CRT tests, final focused seven-scenario C++ test, Clippy/format/diff passed.
All three89123fd workflows ultimately passed. b8e49de workflows40932067466,
40932056425 and40932056438 were still running at this checkpoint; historical
original-Windows failures, including case24, remain preserved and unexplained.

### Bound context validation before C++ dispatcher PTD acquisition

The original helper proof for402877 now composes with the C++ wrapper. A typed
capture binds live Context and Stack roots, runtime/thread/normal-frame identity
and saved ESP. It revalidates lifetimes, exact root extents, unchanged typed ESP
and the live module selector before a protected helper call. The constructor's
explicit valid-stack domain is retained even on the selector bypass; no INT29
emulation or original Windows acquisition is claimed. The decoded helper's
volatile registers/flags are conservatively unknown on return. The original
caller POP ECX then executes and the path rejects at PTD call4028c3.

Eight native handler scenarios and independent capture checks cover argument
identity, root/stack alias, narrowed extent, both valid endpoints, wrong runtime,
unknown/changed/forged ESP, unknown selector and retirement. Existing helper
boundary/control-flow regressions remain shared. No cleanup disposition or
restoration authority is produced, and both original unwind actions still lead
to termination. See CXX-PTD-RECORD.md for remaining acquisition/effect contracts.

Verification: 199 CRT tests passed (one existing observation case separate),
final focused context/lifetime regression, Clippy/format/diff and Python syntax
checks passed. Artifact replay bound the48-byte original context helper in
addition to the wrapper/thunk/entry and passed seven PTD tests, the C++ test and
five previously recorded Windows wrapper comparisons. The PE and wrapper Rust
hashes are unchanged from the preceding checkpoint; zero new Windows observations
or whole-PE pairs. 77715cd startup40932819504 passed; Rust40932829428 and40932819895
were still running at inspection. Historical Windows timeouts remain unexplained.

### Distinct dispatcher PTD getter, extent and original field read

Sol review retained captured-context/root/ESP rejection. Original dispatcher
getter4028d1 and required-object wrapper4028c3 now execute, followed by the21
original dispatcher bytes through CMP [PTD+0x20],ESI. This distinct object is
allocated40 bytes and its lookup402bb4 resolves a dynamic function or TLS fallback
(import415060 TlsGetValue); it is not the UCRT FLS/20-byte errno-prefix object.

The lookup remains a protected explicit callable cut. Returning required objects
must be exact live ThreadData roots with40-byte extent before field access.
Fourteen independent PTD cases cover success,20/39-byte truncation, scalar/interior/
unknown/wrong-kind/stale/foreign results, null/sentinel/invalid index, unknown
LastError, lookup failure with preserved prior writes, and replay rejection.
Nine connected handler cases include unknown PTD+0x20. Original null/sentinel
termination edges and lazy setter/allocation/free calls reject at unbound effects;
LastError restoration is not invented after a call that fails to return.

Local200 CRT tests passed (one existing observation test separate); Clippy,
format/diff passed. The next gate remains resolver/backend/index/thread identity
and dispatcher branch/table effects, including termination callbacks. See
[CXX-DISPATCH-PTD.md](CXX-DISPATCH-PTD.md). These are native component executions,
not original Windows observations or whole-image translations. Historical Windows
timeouts remain unresolved. a60666c startup40934310524 passed; both Rust runs
40934321605/40934310614 remained active at inspection with final Linux jobs running.

Artifact replay passed: both C++ Rust tests and seven prior PTD tests, followed
by five previously recorded Windows wrapper comparisons. Original PE and wrapper
Rust hashes remain unchanged above; zero new Windows observations/whole-PE pairs.
The checker additionally binds both dispatcher getter/wrapper bodies, the actual
PTD field-use bytes, and TLS fallback import identities.

### Checked cached backend selection and dispatcher normal return

Original resolver cached fast path and lookup wrapper now select the known -1
cache route to TlsGetValue. The actual requested dynamic name is FlsGetValue,
which remains a separate unresolved backend. Zero/cold cache, dynamic function
pointers, unknown values and truncated/wrong-role module storage reject. The
backend callable is now at the actual stdcall API boundary with RET4, not the
whole402bb4 wrapper. Actual slot acquisition and cold loading remain unproved.

The original dispatcher217-byte tail and common epilog now execute, returning
numeric disposition1 for two supplied non-unwind component cases. Metadata
address refinement uses its already-owned exact live module capability; exception
reads require typed live Context storage. Unwind/search/dynamic-handler effects
reject at original call sites. The return does not authorize guest resumption.
19 PTD cases and11 handler scenarios retain prior ownership/failure tests and
all eight forwarded arguments; complete resolver/wrapper/tail mutation tests pass.
Local200 CRT tests and Clippy passed. No new Windows observation or whole-PE
support is claimed. Historical original-Windows timeouts remain unexplained.
65129fd startup40936314592 passed; Rust40936324513/40936314665 were still active
at this inspection.

Artifact replay passed with the unchanged PE/wrapper Rust hashes recorded above,
two C++ tests, seven prior PTD checks and five previously recorded Windows wrapper
comparisons. New original bytes for cached resolution/lookup/dispatcher tail and
the FlsGetValue dynamic symbol are bound to the PE. Zero new Windows observations
or whole-image pairs. Final focused and changed-code checks passed after review.

### Post-backend capture review and measured cold-resolver boundary

A new adversarial native test reproduced normal dispatcher return after a backend
callback changed or retired the captured Context. Post-PTD context revalidation
now rejects changed ESP, foreign-stack ESP and retired capture, preserving earlier
writes. Handler coverage expands from11 to14 scenarios; no normal callback return
can rely on those stale captures. Existing lifetime/address-reuse tests remain.

The entire cold resolver/load helper is now artifact-bound and independently
inventoried: four memory XCHG publication sites, FreeLibrary/GetProcAddress and
LoadLibraryExW/GetLastError/prefix-fallback calls. Shared IR still rejects memory
XCHG and there are no module/function capabilities with unload lifetimes.
Cold resolution and dynamic FLS remain rejected pending the cohesive ownership/
publication scope in COLD-RESOLVER-HANDOFF.md. No new whole-PE or Windows comparison
claim follows from this inventory or the review fix.

Verification:201 CRT tests passed, one existing observation test separate; three
focused C++ checks, Clippy/format/diff and Python syntax passed. Artifact replay
passed three C++ checks, seven prior PTD checks and five recorded Windows wrapper
comparisons, with the same PE and wrapper Rust hashes above. Zero new Windows
observations or whole-image pairs. 9fc5c1f workflows40938216500/40938203406 and
startup40938203420 remained active at inspection, without a completed-failure
conclusion. Historical Windows timeouts remain preserved and unexplained.

### Owned cold resolver and checked publication

The original 160-byte cold resolver and 75-byte load helper now execute as native
components with module/reference/export identity and lifetime checks. Original
word exchanges return the previous value without changing flags, under an
explicit startup-exclusive component contract and registered typed cache cells.
Successful load/release callbacks must produce the matching reference change;
scalar addresses, stale generations, incorrect symbols, replay, unknown or partial
cache storage and foreign ownership reject. Prior effects survive later failure.
The original error-87 comparator/retry branch, actual DLL initialization/detach,
API-set/forwarder dependencies and dynamic FLS invocation remain unresolved.
See [COLD-RESOLVER-HANDOFF.md](COLD-RESOLVER-HANDOFF.md).

Local validation passed 203 CRT tests (one existing observation test separate),
175 root tests, Clippy, format/diff and Python syntax. Artifact replay passed five
C++ checks, seven existing PTD checks and five previously recorded Windows wrapper
comparisons. Thirteen new scripted resolver scenarios and independent
registry/exchange negatives are native component evidence, with zero new Windows
loader observations or whole-PE pairs. All 235 bytes in the two bound bodies are
individually mutation-tested. PE SHA256 remains
1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4.
The updated generated wrapper source SHA256 is
1d4353871658ac3470ff65cd4be5703d8bea347fed26ef5413801ba861ef5300;
cold component source SHA256 is
88e743efc4b25a472b008bd5aadf31ed1b88cf1352e21a3481179c9d81153a81.
These source hashes must match fresh cross-host CI before making that claim.
Durable selected evidence: [cold-resolver-component.json](evidence/cold-resolver-component.json).

Completed predecessor CI: all three 9fc5c1f runs passed. At5c3c2b5, startup
40939350184 and push Rust40939350110 passed; PR Rust40939364543 failed the
original-Windows imported hello process wait at15 seconds, job123678335203.
The prior launch controls for the same PE passed; that does not explain the later
hang. Uploaded artifact12926905477 has GitHub-reported ZIP SHA256
389e4eaaa6274596210bd0718fe51043eeb0be1b5d44ba10f71c029d6fbb837c.
Its storage download returned Forbidden, so only logs/metadata were inspected;
no local ZIP verification or process-state interpretation is claimed. The exact
log evidence is preserved in
[windows-hello-5c3c2b5.json](evidence/windows-hello-5c3c2b5.json).
Historical Windows timeouts, ordinary startup and rcedit remain unresolved.
