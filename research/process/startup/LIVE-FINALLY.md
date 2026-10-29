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
