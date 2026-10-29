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
