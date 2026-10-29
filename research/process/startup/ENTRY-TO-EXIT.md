# Entry-to-exit critical path after captured-object review

The target for this existing track is the unchanged authored ordinary-CRT
unwind/report program already measured by `reported_binding.py`,
`check_reported.py` and `stdio-frozen.json`. Preserve its original PE/source/
toolchain hashes. Recompilation produces a separately identified artifact; no
binary surgery, alternate entry or guessed-main invocation counts as completion.
This target exercises more of the current work than another small new fixture.
It remains substantially smaller than rcedit, which is a later independent gate.

The current evidence is incomplete. Normal report comparisons accept supplied
Main/driver state, handler comparisons accept captured-state cuts, and the stream
components accept constructed CRT state. Passing all three does not prove that
one executable can establish and connect those states by its own instructions.
The shortest credible route is to remove these cuts in one composition, retaining
the artifact and independent Windows baseline, rather than add more receipt types.

1. Bind incoming module/thread/stack/borrowed-chain state at the actual entry.
   Execute original initialization and its external effects. Keep borrowed-root
   containment: no incoming chain dereference/dispatch without a proved contract.
2. Execute the original Main/handler path from that state, including RaiseException,
   original handler prefix/helpers, selection, ordered cleanup and nonlocal restore.
   Captured context must be an owned delivery effect with justified observable
   fields; CALL registers are not a substitute. The new checked-object helper
   composition closes one context-check call, not delivery acquisition or dispatch.
3. Connect the same live FILE/descriptor/lock/locale/PTD state to actual formatter
   execution. Remove the formatter driver cut, and prove or reject its C++ FuncInfo,
   failure/termination, temporary buffering and cleanup paths. Preserve short writes
   and unknown volatile state. A precomputed report string cannot replace printf.
4. Follow original return into exit registrations, flush/close and termination.
   Return/flush failure must preserve actual status, physical stdout/stderr and
   process termination behavior. Matching bytes alone is insufficient.

Acceptance is a normal converter invocation on the entire unchanged PE from its
header entry, producing deterministic native Rust/ELF with no supplied runtime
vectors, expected result stencil or skipped startup. Record PE/Rust hashes, compare
Windows/ELF exact stdout, stderr and exit with independent source expectations,
and test failure paths including short/failed writes, invalid captured state,
wrong owner/lifetime, cleanup failure and rejected unsupported startup effects.
Keep unrelated fixtures and the reserved utility families as holdouts.

Next cohesive hard step: connect the existing original handler prefix/helpers
(including the decoded context check) to owned delivery objects and the existing
selection/cleanup/restoration engine. Define the observable delivery contract
and rejection gates before enabling it. The context/record constructor currently
validates supplied captured input; it does not implement acquisition. Once that
step is connected, advance formatter and exit on the same state rather than
branching into another isolated probe chain. This needs a bounded Astra High
architecture pass; routine regression and evidence review belongs on Sol.

No current whole-startup, rcedit, ordinary-app or XP/7 support claim follows.

## Concrete storage/ownership bridge found in Sol review

Source review of 9c96396a found that dispatch_emit::emit_control emits writes
through FrameMemory<FrameImage>; FrameMemory::write_try_level changes only that
image's map and cursor. CrtNormalException::dispatch_source instead rebuilds a
fresh image from checked CRT bytes. The two storage paths cannot be directly
joined and treated as one execution. ThreadRegistry::expected_callback also
rejects a normal epoch, and Machine::check_raise_binding requires a fresh owned
event with unknown context, not the finished outer event currently lending the
epoch. These are concrete adapter obligations, not permission to skip guards.

`check_projection_boundary.py` reproduces the storage mismatch from the emitted
normal harness, executing two native cases. A projected TryLevel write of -2
leaves checked live TryLevel0 and suspension intact. This is an architecture
experiment, not a defect in a currently admitted translation or new Windows pair.
The existing startup Linux workflow retains its report. Reproduce locally by
emitting the normal harness with W2L_EH4_EVIDENCE, then passing normal-wrapper.rs
and an output directory to that script. No foreign PE is executed by this probe.

The next bounded Astra implementation should close these obligations together:

- Add a shared write-through frame interface for original handler/installer/
  TryLevel/cleanup stores, backed by actual typed CRT storage. Reuse decoded
  operations and validate exact ordinary/protected ownership and every word
  range. Read-back must observe each write; callback failures preserve prior writes.
- Give nested delivery its own event/source/phase and scope cursor, preserving
  the finished outer event/context and borrowed predecessor. Keep source types
  distinct; never revive FrameId or clear the epoch guard to impersonate it.
- Run original prefix/helpers and actual table-driven selection through that
  interface; bind callback/result/cleanup/restoration authority to the new event.
  Retain captured-state acquisition as an explicit blocker unless its observable
  contract is independently closed. Reuse pending token and scalar result checks.

Acceptance must include a real instruction-derived scope store observed in live
bytes, original callback/cleanup ordering and failure effects, nested/shared
frames, stale/wrong event aliases, protected-slot and unknown-data rejection,
and proof/native-emitter agreement. Then connect the same state to the chosen
unchanged artifact. A supplied callback or a modified projected image cannot
stand in for that entry-to-exit result. This scope should replace further small
standalone receipt wrappers; it is a concrete complex integration beyond this
Sol review. Keep the current PR draft and admission blocked while incomplete.

## Live storage implementation after the projection experiment

The pending-event path now has `CrtLiveFrame`, which borrows the actual CRT
runtime, interrupted activation, normal-frame binding and delivery identity.
Ordinary word reads/writes check the original frame's complete range and exclude
record, saved-register, guard and saved-ESP words. Typed pointers remain typed;
unknown scalar bits remain unknown. No mutable `FrameImage` is committed back.
A decoded original `MOV [establisher+12], register` writes TryLevel immediately.
The original instruction at VA 0x402355 is extracted from the same unchanged
unwind PE by `check_normal_wrapper.py`; independent register permutations and
malformed forms exercise the lowering separately.

`execute_context_checked_live_handler` connects the existing decoded context
check and owned captured objects to this storage view. Native helper nesting
shares the same pending delivery and scope cursor, with distinct protected CALL
identities, a 32-depth/4096-call cap and activation-local scratch bounds. It never
revives the outer finished Machine or clears normal-call suspension. The actual
original FILE cleanup graph now runs in that composition, reading its original
frame argument and invoking the checked unlock effect. Success releases the
lease; malformed cleanup arguments preserve the held lease and preceding stores.
A failed nested call poisons delivery even if a callback tries to swallow it.
Handler receipts also bind the resulting live scope value, rejecting a later
alias change before result consumption.

The native harness contains 24 live-adapter cases, including protected/partial/
out-of-range accesses, unknown values, stale event/frame identity, expired
captured storage, aliased call scratch, resource limits, nested cleanup failures
and post-return scope mutation. Two earlier projection cases remain as a negative
control: an ordinary detached FrameImage still has no live-storage authority.
These are component regressions, not 26 Windows comparisons. The five existing
original-Windows wrapper observations remain a separate prolog/epilog comparison
with supplied body results. No new complete-PE translation is claimed.

Remaining integration is concrete: the table-driven `dispatch_emit` path still
uses owned FrameId/FrameImage and cannot be passed a NormalFrameId by coercion.
Route its original search/local-unwind action sequence through this live adapter,
then bind its selected landing to a proved normal-frame restoration operation.
The current returned scalar/level receipt deliberately cannot resume the guest.
Captured-state acquisition, borrowed-chain containment and a second exception
raised during delivery also remain unproved; native nested helper calls do not
establish those contracts. Keep full startup/rcedit admission rejected.

## Sol review of ed4d843a: exact next code connection

The existing dispatch adapter is not interchangeable with the live normal source.
`frame_unwind.rs` creates an abstract `BridgeMemory` and executes the decoded
installer into `BridgeWord` maps before invoking filter proofs. The original
installer puts record/context at handler EBP-28/-24 and stores their pair address
at establisher+16-20. In the live runtime the handler CPU currently has only a
protected CALL boundary; it has not executed and owned the original full handler
prolog. Installing a numeric pair into that supplied scratch frame would grant
unproved storage and lifetime authority. Similarly, `dispatch_emit.rs` retires
OwnedFrameBinding values, whereas this source is a suspended NormalFrameId.
Changing the identifier or clearing suspension cannot establish the missing proof.

The next cohesive implementation should:

1. Lower the actual original handler prolog/installer to CrtCpu and checked CRT
   memory. Keep its stack allocation, saved registers and pair locals live across
   original filter calls. Reuse InstallerProof's decoded operation sequence with
   a storage backend, rather than copying BridgeWord maps into memory. Bind its
   record/context pointers to the same event's CrtNormalObjects, and its owner
   slot to CrtLiveFrame's ordinary word checks. Reads must retain pointer tags.
2. Lower the existing table-driven search/local-unwind actions through that same
   live source. Reuse the original LocalUnwindEffects instruction schedule;
   temporary registration and notification callbacks need concrete owned storage
   and effect bindings. Check each TryLevel update against live storage. Keep
   finally effects on failure and reject any unproved nested exception delivery.
3. Connect the original selected landing to a normal-source restoration proof,
   validating saved context, surviving stack extent, completed cleanup and live
   object lifetimes before consuming suspension. A handler result scalar or
   matching TryLevel supplies neither a captured CONTEXT nor resumption authority.

Acceptance includes real installer writes/read-back, live pair dereference by
original filter instructions, nested/shared frames, failure after each store or
cleanup, stale owner/event/pair pointers, expired handler locals, unknown context
and invalid landing rejection. Then compare the unchanged target from actual
entry through exit. This remains complex proof/emitter composition suited to a
bounded Astra High pass; current Sol review did not relax admission to cross it.

The review adds three independent native cases (27 total live-adapter cases): a
foreign callback activation, a same-address pointer from another runtime and a
scalar with establisher address bits. All reject. The ed4d843a CI artifact retained
24 cases per host and matching PE/Rust hashes; that evidence predates the three
new cases. Full-CI Linux completion is reported independently of the successful
startup workflow. Historical original-process timeouts remain unresolved.

## Connected original handler-local installation checkpoint

The CRT backend now lowers the admitted original PUSH EBP / MOV EBP,ESP /
SUB ESP,28 prolog and the existing InstallerProof's decoded five MOV/LEA
operations to checked live storage. Both byte regions are extracted from the
same original PE in check_normal_wrapper.py and included in hash comparison.
The prolog checks the full stack extent and rejects overlapping typed state.
SUB flags remain conservatively unknown. The same installer proof still serves
the abstract backend; CRT lowering is emitted from the same decoded operations.

CrtHandlerPair binds the live callback activation, pending delivery, normal-frame
owner, actual saved EBP/return and initialized captured objects. Its reads verify
the actual owner slot and both pointer words. Changed activation, replaced owner
slot and access after LEAVE reject, including restoration of numeric EBP alone.
The native case reads event code and captured ESP through the installed pair,
then continues existing live scope-store/nested cleanup checks. This is connected
component evidence with an explicit cut across the other original prefix calls;
it does not claim that a complete original handler already executes.

Remaining executable gap: lower/bind the original prefix normalizer, guard and
context calls into this actual activation, preserve its pair locals across the
original filter/LocalUnwindEffects schedule, and give the selected landing a
normal-source restoration proof. Current pair access is restricted to the owning
handler CPU; a filter borrowing it requires a proved call/borrow boundary.
Captured-state acquisition, temporary nested registrations and borrowed-chain
containment remain obligations. No ordinary startup/rcedit admission changes.

Verification accounting: CRT example includes three inherited handler_bridge
model tests newly imported by the harness and one new prolog rejection test.
They are not four new differential cases. The 27-case native harness gains the
connected installer/read/lifetime assertions inside its existing success case.

## Sol review: stack identity correction and bounded filter borrowing

A regression reproduced a component defect in 3958e24f: pair validation checked
ESP's address without requiring its stack capability. A pointer from another
runtime at the same numeric address could pass pair.read before a later stack
operation rejected it. Validation now checks the actual pointer's runtime
identity/range and matching stack capability. This does not change PE admission.

CrtHandlerPair::call_filter now lends the live pair across an actual protected
nested call. Owner-only pair reads remain unavailable to the child CPU; the
borrowed path checks event/frame identity, the still-live owner return, owner
slot and both stored pointers before and after the callback. TryLevel changes
reject rather than silently retarget selection. The parent revalidates on return.
Independent cases mutate the owner slot/pair word or fail the callback; preceding
marker writes remain and delivery fails. The native success case now executes
installer, borrowed filter read, live scope changes and nested original cleanup
on the same pending source. There are 30 native cases and two separate projection
negative controls. Filter body semantics are still an explicit callback cut.

Next connected implementation remains actual original prefix/helper calls and
original filter instructions under this borrow, followed by table-driven local
unwind/temporary registration effects and a normal-source selected restoration
proof. The present scalar return grants no disposition/guest-resumption authority.
Astra High is warranted for that combined prefix/temporary-registration/restoration
proof; current shared storage and borrow machinery can be reviewed on Sol.

## Sol implementation: live instruction-derived language filters

FilterProof now emits a CRT backend from the same decoded MOV/XOR/CMP/SETE/RET
instruction sequence as the existing abstract backend. Reads and stores use
CrtLiveFrame and actual typed pointer dereferences, not a temporary snapshot
copied back at callback completion. Volatile registers/partial SETE and flags
are updated through CrtCpu; the containing protected call executes RET. The live
exception-code load checks the proof's event boundary before subsequent stores.
Changed/unknown live code therefore cannot reuse a selection proof silently.

The owned-pair native success case now executes decoded matching and nonmatching
filter bodies through two protected borrowed calls, checks independent 1/0
expectations and observes the exception-code temporary in live frame storage.
A changed-code case rejects at the load and retains a preceding marker store.
These are independently specified authored x86 instruction fixtures using the
shared filter semantics. They do not establish execution of the entire frozen
compiler-produced handler/filter or new whole-PE Windows comparisons. The original
prefix helper calls and actual filter-bridge register setup remain explicit cuts.

The CRT suite imports seven inherited selection tests; its increased total is
not seven newly authored tests or differential cases. Existing malformed pointer,
unknown flag and protected-write rejection checks still run. Thirty native
adapter cases and the five retained wrapper observations remain separate counts.

Next useful Sol scope: connect the decoded prefix normalizer and readonly guard/
context checks to the same activation and bind actual target filter bytes and
owner-frame register setup. Table-driven LocalUnwindEffects still requires actual
temporary registration ownership and exceptional/collided delivery, followed by
normal-source restoration. The precise complex question is how those temporary
registrations and cleanup effects bind to the suspended normal epoch while
preserving its borrowed predecessor and captured-context authority. It cannot be
resolved by clearing suspension or reusing the finished outer Machine. Escalate
that bounded question only when the shared instruction/effect connections reach it.

## Sol connection: original event normalizer under live call ownership

CodeIdentity now retains its initialized-global requirements and emits a CRT call
wrapper for the existing proved summary. The proof explores all reachable feature
branches and establishes the same event code at every return with no observable
nonprivate writes. The wrapper validates actual initialized Module words, live
captured objects, argument and full temporary stack range, executes the protected
CALL/RET boundary, performs caller argument cleanup and invalidates ECX/EDX and
status flags. It does not pretend that every private helper instruction is emitted;
the optimization is justified by the existing all-path proof, not sampled output.

The actual 119-byte helper at VA0x414a1b and initialized word0x41ccb8 are extracted
from the unchanged PE in the wrapper workflow and hashed across hosts. Native
cases run feature0,1,UINT_MAX and reject an uninitialized word before CPU/call
changes. The exact helper rejects a special MXCSR-requiring event and missing
module-read premises at proof time. Existing installed-pair/filter/cleanup cases
run after the call. These are strengthened existing native scenarios, no new
whole-PE Windows/ELF comparisons. The five original wrapper observations remain
separate evidence with body inputs.

The context helper is already decoded/checked at owned entry. The remaining
readonly guard connection needs the actual scope-table cookie header bound to
this normal frame's initialized live module state, then the original guard proof
lowered at its call boundary. Current FrameImage rebuilding validates saved words
and cookie identity, but it cannot stand in for original helper execution without
that header/call binding. This can be attempted on Sol. The original prefix caller
stores/register setup and actual target filter bytes also remain to be connected.
Table-driven temporary registrations and selected normal-source restoration are
still unproved; no result/level/normalizer summary authorizes resumption.

## Sol connection: original readonly guard proof at the live call boundary

The unchanged guard validator (VA0x4021d0,50bytes), security checker
(VA0x40154c,14bytes) and FILE scope header (VA0x41b400,16bytes) are now extracted
and hashed with the other component regions. GuardProof can consume guard offsets
derived from the already-proved CRT prolog layout. Its original ProvenFrame entry
still delegates through the same checks; the CRT path cannot invent a guest offset.
The header is stored inside the resulting proof so an emitter cannot supply a
different header after proving it.

The emitted call validates the complete live module header against that proof,
reads the initialized cookie and checks the original guard predicates through a
readonly view of actual CRT guard bytes. It preflights temporary stack ownership,
executes a protected call with the original table/frame arguments, then performs
caller cleanup and volatile-register/flag invalidation. As with the existing
GuardProof backend, private helper instructions are summarized by the decoded
proof; mismatching guards are excluded from the admitted entry domain. This is
not emulation of the helper's fail-fast target.

The connected native case now runs normalizer, readonly guard call, installed
pair, decoded filter and cleanup. Mutated/unknown headers and a corrupted live
guard reject; valid header/guard calls succeed after restoring the test mutation.
These strengthen the existing30scenarios. CRT test count includes nine inherited
frame_proof/frame_memory/handler_guard tests newly imported, not nine new Windows
comparisons. Existing five wrapper observations remain distinct component evidence.

Still missing: original prefix caller instructions/register setup and target
filter bridge, complete scope search/local-unwind scheduling, temporary-registration
and exceptional/collided effects, selected normal-source restoration and actual
entry-to-exit execution. The checks do not authorize clearing suspension, reviving
the outer Machine or assuming captured context. Routine prefix caller lifting can
continue on Sol; exceptional registration/restoration requires a concrete reviewed
contract when reached. Full startup/rcedit remains rejected.

## Sol original prefix caller: through the first helper and code writeback

PrefixProof now retains a native lowering of its decoded caller instructions
through the original normalizer call and MOV [record],EAX. The lowering uses
CrtCpu/checked memory for actual pushes, register loads, local byte/word stores,
CALL and record writeback. It is derived while the existing full prefix data-flow
proof validates the original sequence; it is not an application/result stencil.
The complete98byte prefix atVA0x402210 is extracted and hashed with the original
component artifact. No complete-handler execution is inferred from this slice.

The normalizer binding now distinguishes caller-owned arguments from the
standalone component wrapper. In the prefix form it checks the actual existing
argument and preserves it after RET. The original caller accumulates four argument
words over three helpers and cleans them once; immediate per-helper cleanup would
change original stack behavior. The new native case checks saved EBX/ESI/EDI,
local flag/constant stores, code writeback and the remaining code argument at
EBP-44. Its failure case rejects an unknown module word while preserving preceding
caller stores/pushes. Both cases stop at the guard/context continuation rather
than manufacture a normal return or dispatch disposition.

Thirty-two adapter scenarios now run; two new prefix scenarios are native
instruction/component evidence, not Windows/ELF whole-PE pairs. Four inherited
handler_checks tests newly imported explain the CRT suite total increase.
Original Windows wrapper observations and historical timeouts remain separate.

Next Sol work: extend this same caller lowering through table decoding, original
guard/context calls, deferred16byte cleanup and zero-flags branch to the already
connected installer. Bind decoded-table provenance after the original XOR,
preserve original arguments/register clobbers and reject unproved flag delivery.
Then connect actual filter bridge/target bytes and table-driven local unwind.
Temporary-registration exceptional/collided effects and selected normal-source
restoration remain open; scalar result and scope equality do not supply that
permission. No full startup/rcedit admission changes.

## Sol connected full prefix caller through installer

The same PrefixProof lowering now executes the remaining original caller
instructions: load/decode the scope table with its actual cookie, establish the
owner-frame address, retain guard/context arguments, invoke both checked helpers,
load the original record, perform the single16byte cleanup, read TryLevel, test
flags and reach the installer only in the full zero-flags search domain. A decoded
table scalar gains Module provenance only after matching this bound frame's
proved scope address. Complete module-range checks still precede helper reads.

Guard/context bindings now support caller-owned arguments without per-call
cleanup. Helper bodies retain their existing decoded proof/summary and protected
CALL/RET behavior. The context helper is extracted/hashed from this same PE too.
The ordinary-prefix native case adopts the actually installed pair after checking
all three saved nonvolatile slots, executes a decoded filter and verifies the
owner/table locals, ESI/EDI state and forgotten helper arguments. Header corruption
and an unknown context selector fail at the expected distinct stack depths while
preserving caller effects. The unknown-feature failure remains at the earlier
normalizer boundary. Thirty-four scenarios now run; these are component cases,
not new whole-PE comparisons or a Windows acquired-context implementation.

The full98byte caller path is connected for the admitted component entry. The
ordinary handler's actual filter bridge/target bytes, scope-table search and local
unwind schedule, temporary-registration/nested exceptional effects and selected
normal-source restoration remain unproved. Current native filter code is an
independently authored instruction fixture. Full startup/rcedit remains rejected.
Next useful Sol work is the actual filter bridge and target binding before any
normal-frame retirement or resumption is admitted.

## Sol original filter bridge and measured target-frame boundary

The original23byte bridge atVA0x402800 now has a CRT backend derived from the
existing BridgeProof instruction decoder. It executes real saves, owner EBP
setup, zeroing of EAX/EBX/EDX/ESI/EDI, nested protected filter CALL and original
POPs/RET. The containing binding validates a Module pointer and complete expected
target bytes; a scalar target, changed bytes or callee failure reject and preserve
preceding effects. Existing abstract proofs remain available for any original
forms the new native backend cannot lower; requesting an unavailable native
lowering rejects rather than weakening the old proof or fabricating execution.

The full-prefix native success case now executes that actual bridge with the
independently authored bounded filter, checks original filter-entry registers
and restoration of all four saved nonvolatile registers. Three failure scenarios
increase adapter cases to37. Three inherited unwind_bridges tests newly imported
explain the CRT suite count increase, not three new Windows comparisons.

The unchanged actual Main target atVA0x401333/41bytes is extracted/hashed alongside
the bridge. It is deliberately tested against the current FILE-wrapper layout
and rejects with `selection: unowned frame word`: the original filter writes
EBP-776/-780, whereas this wrapper owns only its small prolog-derived locals.
Main's original scope header is [-28,0,-796,0], distinct from the FILE header
[-2,0,-44,0]. Retargeting or enlarging this fixture without original Main frame
proof would be false support. No source/PE edits or offset substitutions are made.

Next coherent gate: connect the already-proved original Main frame initialization
and two-cookie layout to CRT live-frame ownership, then bind its actual table row,
filter bridge and unchanged filter target. The independent wide Main frame and
small FILE frame must remain distinct and both keep ownership/lifetime negatives.
After that, perform original table-driven scope search/local unwind and selected
normal-source restoration. Current work executes the actual bridge but does not
translate that Main target in this FILE frame, full startup or rcedit.

The code-level Main integration gap is also an authority distinction:
CrtNormalLayout/storage_image currently represent one guard and NormalFrameId,
whereas the existing Main frame proof has distinct GS/EH guards and an owned
registration. It cannot be installed as a fabricated normal child or reuse the
finished outer event's resumption authority. A shared live-source adapter must
preserve each source identity, actual original Main initialization and both guard
words before accepting its full filter-local range. The original Main event code
is0xe0424242; the independent small adapter fixture uses0xe0420042. Keep those
input/provenance domains explicit. Substituting offsets, event codes or frame
kinds to obtain a matching result would invalidate the evidence.

## Sol owned Main storage and unchanged filter execution

CrtOwnedStorage now connects a ProvenFrame's original prolog memory effects to
checked CRT storage and an actual OwnedFrameBinding/RegistrationId. Initialization
uses the decoded prolog's final private-store summary with full-range/role checks
before writes and registry installation at the endpoint; supplied caller CPU/RET
and initial thread/module state remain component entry premises. Unknown words
are not zero-initialized. Saved values retain actual typed entry values/known masks.
No NormalFrameId, normal epoch or finished event is substituted for this owner.

Every view access revalidates Machine event/phase, live registration, complete
stack lifetime, both immutable guard words, original saved/control words, module
cookie and unique return. Unexpected protected tags in ordinary storage reject.
Only prolog-derived ordinary full words are writable. The supplied installed pair
is a checked input cut: Context roles, full ranges, pointer graph, event code and
actual owner slot are rechecked; it is not an implementation of OS capture or the
original Main handler prefix. Selected callback/containment input is also explicit;
this single-frame component does not prove the original multi-frame search/unwind.

The original Main prolog and actual41byte filter now execute their proved memory/
filter semantics with actual Main-owned EBP-776/-780 storage and both cookies.
The unchanged23byte bridge sets owner EBP, executes that filter and returns1 for
its original0xe0424242 domain. Both temporary writes are read back from live bytes;
the immutable FrameImage cache remains unknown there and grants no writeback
permission. The independently sized original Inner frame rejects those offsets.
Thirteen owned-frame scenarios also cover each guard, stale binding/registration,
pair corruption, module cookie, foreign arena, ended event, protected-slot writes,
hidden control aliases and bridge/source-stack overlap. Bridge preflight now
checks the full original private scratch extent before its first push, for both
normal and owned sources.

These13native scenarios are separate from the37normal adapter cases, two projection
controls and five original wrapper comparisons. One new test function is added;
no new whole-PE Windows/ELF pair is claimed. Next: share the already-connected
prefix/captured-object interface with this owned source, then actual table-driven
selection/local-unwind scheduling and validated restoration. Original Main body
initialization/external effects and full entry-to-exit execution remain open.

CI40737854599(de253f4f PR) failed imported-output Windows hello while all other jobs
passed. Artifact12837907867 retains PEhash30a0afa2..., stdoutHello, empty stderr,
process alive at15seconds and killed/reaped afterward. Earlier controls and18launch
samples passed on that run. No retry, threshold change or solved-cause claim.

The original Main prolog's TryLevel sentinel(-2) is retained in this binding.
The native filter invocation is an explicit supplied callback entry, not a claim
that current scope-table dispatch selected an active Main scope. The next path
must execute the original Main-body activation store and give that specific store
write-through scope authority before table-driven selection is accepted. It must
also replace the installed-pair input cut with original owned-source prefix/
captured-object effects. The cached image cannot grant either transition.

The same de253f4f push run40737845011 also failed original Windows corpus29
(PEhashd782a279...) after15seconds; all other jobs passed. Artifact12837473505 is
retained separately from PR hello artifact12837907867. These are two preserved
failures, not a passing retry or proof of a shared cause.


## Main activation and owned handler entry

The original Main activation at VA 0x40130f (`MOV [EBP-4],0`, seven
unchanged bytes) now has a separate instruction certificate. Its emitter checks
the original frame shape and module identity and updates both checked live
TryLevel storage and its protected metadata before event issuance. Replay,
post-event use, corrupted prior storage and the independently smaller Inner
frame reject. This is a separate fragment after an unproved Main-body gap: it
does not execute or certify the intervening initialization/external calls.

The owned handler-entry binding checks the live event/registration, actual
callback arguments and protected return, complete disjoint captured-object
ranges, initialized record fields and captured ESP, plus the original full
prefix scratch extent. Captured Windows ESP is deliberately different from
the callback CALL ESP. The same instruction-derived handler prolog lowering
now supports either the normal or owned storage view. It pushes the actual
saved EBP and allocates the original 28-byte handler locals without granting
unknown values scalar knowledge. Owned prefix entry requires the exact record
and context already bound to the event's checked pointer graph.

An independent same-byte/different-object regression reproduced acceptance by
the first unpublished binding; matching object identity is now required both
at binding and later validation. Additional negatives cover unknown captured
ESP, scalar-for-pointer arguments, wrong establisher, nonzero exception flags,
typed scratch overlap, post-binding captured-ESP changes and guard corruption.
A second positive relocates the Main frame and callback stacks while keeping
the original instruction bytes and frame-relative semantics unchanged.

There are 24 owned native scenarios (the previous 13, plus 11 covering activation
and prefix entry), 37 inherited normal adapter scenarios and two inherited
projection controls. These are generated native component executions, not new
Windows/ELF whole-PE pairs. Five original-Windows prolog/epilog observations
remain separate, and their unchanged PE/hash provenance is retained.

Next executable connection: adapt the existing decoded normalizer, guard and
context-check helper calls and full prefix caller to the owned source, preserving
its distinct identity and actual two-guard Main scope header. The present work
binds prefix entry and executes its prolog, not the remaining original prefix,
OS captured-state acquisition, table-driven selection/local unwind or validated
restoration. Original startup and full rcedit remain rejected. The earlier
de253f4f hello and corpus29 timeouts remain unresolved; successful later CI does
not explain either failure.


## Owned Main prefix helpers and original stack-pair installation

The existing CodeIdentity, GuardProof and ContextCheckProof emitters now share
call/argument/scratch/clobber lowering across normal and owned sources. Their
source-specific identity checks remain distinct. The unchanged Main header
[-28,0,-796,0] is extracted and hashed from its original PE range; its two guard
checks use original frame roles and checked live bytes. No FILE-frame offset or
event code is substituted. The normalizer retains its all-reachable-path
readonly identity proof for the independently bound Main event code.

The same decoded 98-byte original prefix now executes on the owned source through
normalization/code writeback, scope decode, guard and context helpers, deferred
16-byte argument cleanup, flags check and the original installer stores. Helper
CALL/RET identities remain protected, volatile values and flags retain their
conservative effects, and captured Windows state is separate from CALL registers.
The entry remains supplied: this is not acquisition of OS captured objects.

A captured-input binding can now exist without a preinstalled exception-pointer
pair. Reads of the owner's pair slot reject until actual original installer
stores have executed. Adoption checks the real handler EBP/ESP, three saved
register slots, saved EBP, owner record and typed pair graph. It binds pair
lifetime to the actual live callback return; replay, changed pointer tags and
consumption of that return reject. The old supplied-pair scenarios are retained
as explicitly different component entry cuts. No projected image writes back.

Two positive cases, including relocated source/callback stacks, execute the
prefix and then the unchanged Main filter through the protected bridge using
that actual installed stack pair. Bridge target selection/caller setup is still
an explicit cut, not original scope-table search. Independent negatives cover
unknown normalizer global, changed Main header, unknown context selector,
post-install pair corruption, expired callback, repeated adoption and changed
guard. Earlier local stores and caller-owned arguments remain visible at each
failed helper boundary, and a failed prefix cannot be resumed as a valid view.
There are 33 owned native scenarios: 24 inherited and nine added. CRT test
functions remain 130 passed/one ignored; frame tests remain 171 passed. These
counts are not new Windows comparisons. Five recorded wrapper observations,
37 normal adapter cases and two projection controls remain separate.

Remaining entry-to-exit work: bind actual scope-table search/local-unwind
selection and selected restoration to these live objects, then remove Main-body,
captured-state acquisition, formatter and exit cuts together as justified.
Full startup and rcedit remain unsupported; this PR remains draft.

f7a0968e CI reconciliation: startup workflow40785293748 passed. PR full run
40785300452's authored-windows-fixture failed the original corpus case10 after
15seconds (job123156873330); hashd7893cc370c4ed69e3e70b9848560228c71adc36448978d74ee5e1fabce8619d,
stdoutC10, empty stderr, poll_at_timeoutNone, exit_after_kill1. Artifact12859790274
retains the launch diagnostics and executed PE; the archive is also saved locally.
The independent host controls and18launch samples passed earlier on that runner.
The same-head push's authored fixture passed; this neither explains the PR
failure nor erases it. Both full runs' final Linux jobs were still running at
inspection. No retry or timeout-threshold relaxation was performed.


## Live owned table search to the original global-unwind call

The next connected slice reuses HandlerDispatch's existing semantic proof and
the shared CRT IR/native emitter. The routing certificate now retains its exact
original scope-table bytes. Native binding rejects a table with a changed parent
even if the filter address is unchanged; an independently constructed regression
protects that proof/input identity. The unchanged Main table has one row with
parent -2, filter VA0x401333 and landing VA0x40135c. Its complete28bytes and the
complete350byte handler are extracted and cross-host hashed.

CrtOwnedSearch lowers the original search instructions after the installed pair
atVA0x402272. It validates actual post-prefix registers/locals, live callback
return, complete table/code bytes and typed source ownership. Actual table loads
and indexed LEAs select the filter; only the original proved code-cell binding
can turn the loaded function value into an executable Module capability. The
original protected bridge and unchanged filter run, followed by actual partial
CL stores, TEST/signed branches, record-class comparison and call-argument moves.
The component stops immediately before the original global-unwind CALL at
VA0x402332. ECX is the live registration pointer and EDX the live exception
record. No expected filter result is substituted for instruction execution.

Shared path lowering accepts only a path from a semantic proof, with exact
instruction boundaries, original legal successors, finite instruction budgets
and no repeated-PC loop assumptions. Every conditional edge is checked against
the actual runtime flags before following the proved route. Independent native
inputs check the valid edge, a disagreeing edge and unknown scalar/flags;
malformed cuts, wrong successors, repeats, overlapping cuts and unproved RET cuts reject.
An independent overlapping-short-jump/indirect-call vector reproduced acceptance
by the first unpublished path utility; a disjoint-span check now rejects it.
The existing full routing decoder already enforces complete instruction starts;
this closes a reusable utility gap without claiming an admitted-PE defect. The
generated runtime has no decoder, solver or dynamic instruction fallback.

Two normal/relocated owned cases now connect prefix through table-derived filter
search. Seven new negatives cover changed original body/table/filter bytes,
stale scope, expired callback, scalar table-address alias and wrong owner-frame
register. Failure preserves prior original effects and never invokes the filter
when its code binding is wrong. Protected nested bridge/filter calls remain
distinct from nested exception delivery, which is still unproved. Successful
search explicitly fails an attempted restoration before its callback executes;
the saved owned context remains unknown and unchanged.

Counts:42owned scenarios =33inherited +9new. Three independent native edge
cases are separate. CRT134passed/one ignored =130prior +3inherited routing tests
newly imported +1new branch-regression test function. Frame171tests remain
inherited. Five recorded original-Windows wrapper observations and37normal
adapter/two projection cases remain separate; zero new whole-PE pairs.

The remaining executable bridge is specific: original global-unwind wrapper
VA0x402840 must be bound to the live registry's younger-frame schedule and
target-preservation/continuation contract. Original local-unwind/selected
TryLevel stores must write through checked owned storage and its protected
metadata, not mutate a detached FrameMemory projection. The selected-transfer
VA0x402820 and original landing/context preparation must then consume actual
cleanup/restoration authority and initialized saved state. Current search
creates none of that authority. Main body/capture/formatter/exit cuts also
remain open; full startup/rcedit conversion is still rejected.

CI reconciliation for0ab40304: both full Rust runs40787171592/40787165663
completed SUCCESS. Dedicated startup40787165757 failed original-entry observer
compilation at60seconds before new cross-host handler cases ran. Job123163126584
retains the exact cl command/TimeoutExpired; artifact12858954284 contains
observer.exe and observer.obj, archive SHA256
d4e7215c8bb6ddf3f0148edcba812745b9fe48e5337b8e68bde10d0d1d324183.
The archive is retained locally. Binary output existing does not prove compiler
completion or establish why it timed out. No retry or threshold relaxation.
Earlier f7a0968e PR40785300452 is now terminal FAILURE(corpus10); its push
40785293650 and dedicated40785293748 completed SUCCESS. All earlier original
Windows timeout causes remain unresolved.


## Original global-wrapper boundary and owned selected-store effects

Review of bda01875 verified all three workflows40791014337/40791006618/
40791006642SUCCESS. Downloaded native artifact12861742283 contains actual
Windows and Linux reports with identical PEhash
836e40be0afaa83b399d392a12a562330e5ed141013750093d6c6e16e515281d
and Rusthash4603f8b1b308904b1ebd82933a73f194c430eff4b6b1c7b3c7d9d03bd49db32c.
Both report42owned cases, three branch-obligation cases, five retained wrapper
comparisons and zero whole-PE pairs. This CI rebuild is distinct from the older
local recorded original PE1e96cb39...; hashes are never mixed across baselines.

The unchanged26byte global wrapper atVA0x402840 now executes from the live
search state through its prolog, four original argument pushes and the exact
imported CALL atVA0x40284f. The checker independently confirms the original
PE import is kernel32.dll!RtlUnwind. All36bytes of original private scratch
are preflighted from BridgeProof before the first wrapper push. Execution
checks the actual target frame, original TargetIp0x402855, exception-record
pointer and ReturnValue0. It then REJECTS at the still-unbound API effect.
The reached stack stores, live transient CALL and unknown saved context are
retained; no fake API return or cleanup success is inserted.

The same exact three-byte MOV proof now supports owned protected TryLevel
storage. It checks the live registration/phase, typed establisher, complete
initialized before value and independently bound after value; only record+12
is writable. Actual bytes and protected FrameImage metadata update together.
Positive/permuted-register, scalar alias, wrong frame/value, unknown value and
replay cases exercise this operation. This is a separately supplied MOV-fragment
entry cut after search, not a claim that the global API completed or original
control flow skipped over it. Machine stays Cleanup; attempted restoration
rejects before its callback and leaves saved context unknown.

There are51owned scenarios =42inherited+9added, three inherited native branch
cases and one new ordinary-call negative control. CRT134passed/one ignored
and frame171passed remain unchanged function counts. New component cases do
not add whole-PE Windows/ELF comparisons.

### Concrete continuation and delivery gap

Fresh separate original-Windows artifact12861766580 (bda01875) corroborates the
existing contract on Server2022/MSVC14.44.35207: at the original API continuation
EBX changed from0xfffffffe to0 and ESI from0x4ffc40 to0 before wrapper POPs;
EAX was0 and ESP advanced16. Search callbacks used CONTEXT0x4fed88 while unwind
callbacks used0x4fe8c8 with the same exception-record pointer0x4fed38 and flags2.
These numeric addresses describe that observed run only, not portable addresses.
Observed TargetIp0x112855 is original RVA0x2855 in a load at0x110000; the native
component uses preferred virtual-image TargetIp0x402855. This is relational
component/control evidence, not general rebasing validation.
The independently authored native negative control demonstrates why ordinary
CrtCpu::call_activation/finish cannot supply this effect: changed nonvolatile
state fails the callee-saved RET check. That guard must remain for normal calls.
The search-only CrtOwnedPrefixInput also correctly rejects unwind flags2; clearing
those flags or reusing its captured-context identity would fabricate semantics.

Microsoft's RtlUnwind contract supplies TargetFrame, TargetIp and ReturnValue
semantics; EXCEPTION_RECORD documentation marks unlisted flags as system-reserved.
Neither page specifies a complete arbitrary callback/memory mutation footprint.
Primary references:

- https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record

The next bounded architecture pass must connect a genuine owned TargetIp
continuation outcome (not an ordinary protected RET) to actually completed
younger-frame cleanup. It must allow conservative unknown register/record
knowledge before the wrapper's real POPs, maintain separate search/unwind
delivery CONTEXT lifetimes, and execute local temporary-FS/nested callback
effects through live storage. Current OwnedStorage initialization is also
raise-source-only: check_raise_binding requires the current youngest binding,
so installing older Main/Outer records in a multi-frame native composition
needs a separate validated installation contract, not removing event checks.
Then bind selected TryLevel/guard/transfer and original landing/context stores
using actual receipts. The new store primitive reduces that work but grants no
unwind completion.

Acceptance must include normal and changed-nonvolatile continuations, wrong
TargetIp/IAT/thread/record, stale delivery objects, independent three-frame
cleanup order and partial failures, plus unchanged-artifact evidence. No callback
result Boolean, supplied saved array or detached image may authorize resumption.
This is a concrete Astra High question about nonlocal control/effect ownership;
routine testing and CI remain Sol work. Full startup/rcedit stays rejected.
Earlier observer-build and original-process timeouts remain unresolved; current
passing CI explains neither.

### Owned unwind delivery lifetime and conservative continuation boundary

The global wrapper now has a checked delivery-lifetime component at its exact
imported call boundary. The enclosing instruction proof still binds the original
four arguments and IAT. `CrtOwnedUnwind::begin` validates the live wrapper return,
stack extent, source registration and captured input, then suspends the search
input token permanently for that epoch. Clearing record flags later cannot revive
that token. This operation does not implement RtlUnwind or issue a completion.

A delivery receives a separately supplied, checked CONTEXT capability. The
captured search CONTEXT, exception record and all active delivery contexts must
be disjoint from it. The complete 716-byte context range, initialized ESP, thread
bounds, callback arguments, protected return and private scratch are checked.
Nested deliveries have distinct callback identities and descending stack ranges;
there are limits of 16 active deliveries and 64 delivery scopes per boundary.
Sequential callbacks may reuse the same live unwind CONTEXT with a fresh scoped
lease, as the original observations do; an active alias remains rejected. The current
narrow component accepts flags 2 and dispatcher argument 0 only. These are explicit
input restrictions, not general Windows exception semantics. In particular, this
is not yet a binding of the observed nonzero Windows dispatcher-context object.

These new delivery cases use the already bound source frame; they do not yet
install or retire younger frames. Each delivery executes the original handler prolog against its own call registers
and checked stack. Captured ESP remains distinct from callback ESP. All context
comparison snapshots are read-only validation data: they cannot write back or
initialize Machine's saved state. Parent delivery tokens cannot be used during a
nested delivery. A changed argument graph, expired context, captured-context
mutation, corrupted callback token or body failure rejects while retaining prior
memory effects. No successful delivery scope grants cleanup completion, return
from a handler, or guest restoration.

An independent corruption test exposed a defect in the first unpublished version:
it checked delivery argument identities at entry but did not recheck them when the
scope ended. Replacing the CONTEXT argument with the captured search context was
therefore missed. The exit check now verifies the four typed argument words again;
the regression demonstrates rejection before the still-unbound API boundary.

The unchanged global wrapper's original POP/RET sequence also executes in four
separate continuation-input tests. At that explicit test-only API cut, EAX is the
specified ReturnValue and ESP is the checked continuation stack; every other
register and tracked flag is unknown. Original POPs restore EBX, ESI, EDI and EBP
from actual saved words before the normal protected RET. Unknown-flag reads,
corrupt saved words and a consumed caller return reject. This demonstrates that
native emission can preserve conservative register effects without weakening
ordinary-call ABI checks. It is not an executed RtlUnwind, a proof of its memory
footprint, or a new Windows/ELF translation comparison.

There are 72 owned native scenarios: 51 inherited, 17 delivery-lifetime cases and
4 continuation-input cases. The three branch cases and one ordinary-call negative
control remain separate. CRT tests are 134 passed and one ignored; the five
recorded original-Windows wrapper observations are replayed separately. None of
these adds a whole-PE pair. The local baseline remains PE
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`;
the separately rebuilt CI PE `836e40be...` must not be substituted for it.

The remaining executable boundary is precise: the native API needs an owned
nonlocal continuation issued only after actual younger-frame handler execution,
local cleanup and registry retirement have completed. That binding must supply
validated delivery and dispatcher-context objects, preserve or conservatively
invalidate every observable external effect, and consume the API call control
state at the proved TargetIp. The current component deliberately has no completion
method. Original local-unwind writes still need the live owned-storage adapter,
and older-frame installation needs its separate pre-event contract. Only then
can selected transfer/landing and Machine restoration be connected. Ordinary
startup and full rcedit remain rejected. Sol can review this bounded change and
its CI before the next ownership/completion integration.

Prior-checkpoint CI is not uniformly green: d27f8f5d startup run 40794626841 and
full PR run 40794635242 passed; full push run 40794627077 failed in the original
Windows corpus launch. Case 27, PE
`4dc763b44f80b5e2f7b49b4ae6f0090b6fa56e12ec321e81b7eefea4098e9305`,
produced `C27` and empty stderr but was still alive after 15 seconds. It was killed
and reaped with exit 1. Both independent host exit controls and all 18 launch
samples passed earlier in that job; the other eight jobs passed. Preserved artifact
12863490978 has SHA256
`504490a02a0b9cb407bd8b4d231cb6b8c089bb87093bc4185e3608840c274aeb`.
This is an original-process timeout, distinct from the earlier observer compiler
build timeout. Neither cause is established, and no thresholds or retries changed.

Final local component Rust SHA256: `06051479c0279575d418b00e0099005d9a6af6759fd6fd9e9e145ddc16560d72`.
The retained native projection check also passed with 72 owned cases; its
37 live-adapter and 2 projection cases are inherited, not additional translated
programs. Frame tests passed 171/171; Clippy and formatting checks passed.


### Independent review and cleanup prerequisite connection

The separate captured/delivery lifetime and argument-exit fix were reviewed on
Sol. The original API boundary now has `check_cleanup_boundary`: it rejects
inside any active delivery, rechecks the live wrapper activation and all four
original argument values, and requires the registry's exact target to be ready.
The latter means every younger registration has completed its handler, unlinked
and retired. A returned callback or an unlinked but still-live frame is
insufficient. The independent two-frame lifecycle regression now checks both of
those intermediate states before its existing actual registry retirement step.

Native delivery cases check that an active callback cannot pass this boundary,
even in the zero-younger-frame fixture. After scoped deliveries end the original
argument check succeeds; changed TargetIp or wrapper identity rejects. These two
new corruption cases bring the owned count to 74 = 51 inherited + 17 delivery +
4 explicit continuation-input cases + 2 cleanup-boundary cases. The boundary is
a read-only prerequisite, never an API completion receipt, jump or saved-context
restoration. Existing full-program admission remains unchanged.

The exact remaining code-level connection is the live owned local-cleanup
adapter: `ThreadRegistry::execute_local` currently mutates `FrameImage`, whereas
original handlers read and write `CrtOwnedStorage` bytes/protected roles. The
owned view borrows registry and Machine immutably. Completing the path requires
scoped mutable registry execution while the adapter updates the same live source,
then actual handler epilog/guard validation, retirement and a nonlocal API control
outcome. Copying a completed detached image back, or treating this prerequisite
check as completion, would skip that proof. No new external permission is needed.

All three 6a612ccf workflows are being checked; the dedicated startup workflow
40797171456 has passed. Full runs 40797179466 and 40797171510 were still active at
the review checkpoint. Prior original case-27 timeout evidence remains preserved
and unresolved; no retries or timeout thresholds changed.

### Canonical owned storage inside registry cleanup

The registry's handler and local-cleanup executors now accept a
`RegistryFrameStorage` interface that exposes immutable frame metadata. Existing
FrameImage users retain the same behavior. CrtOwnedStorage implements that
interface, so the same executor can lend the canonical storage mutably to the
callback while validating its registration at entry and exit. There is no cloned
image or projection writeback, and no change to unlink/retirement authority.

The original local body's MOV at VA0x402775 (`89 48 0c`) now has a live owned
lowering through the existing exact scope-store proof. It requires an installed,
active LocalRecord for this registration and the enclosing handler lifetime.
Before writing it checks the actual source, cookie, protected fields, known
before value, typed establisher and proven after value. It writes actual record+12
bytes and canonical protected metadata together. The existing selected-scope
store delegates to the same mutation, preserving its prior checks.

Ten independent native scenarios exercise this exact fragment inside actual
registry handler/local lifetimes: normal, nested, before FS installation, after
FS restoration, scalar address alias, changed guard, changed live level, replay,
foreign runtime and failure after the write. The nested case uses the same
canonical storage in two scoped local executors. Partial failure retains both
the actual -2 word and its matching metadata; no completion or restoration is
issued. Machine context remains unknown and premature restoration rejects.
These tests supply explicit local-entry/FS commands and a store-fragment entry;
they do not yet execute the whole original local loop, cleanup callback, guard or
epilog, and the target frame is not retired as a younger frame.

Evidence extraction now reads the three store bytes from the unchanged PE and
binds their hash across hosts. There are 10 new local-store component scenarios,
separate from the inherited 74 owned scenarios and five recorded Windows wrapper
comparisons. Local verification passed 135 CRT tests/one ignored, 171 frame tests,
Clippy, formatting and the wrapper/projection checks. Generated Rust SHA256:
`d1151d74e4507cf7dc22c2943b899254ee9ee730bc212b8b698ea37bc50cbb6b`.
Zero new whole-PE translation pairs are claimed.

The next connected step is to use this canonical storage in the decoded
`LocalUnwindEffects` loop instead of `OriginalLocal`'s FrameMemory-only writer.
Bind the live scope row and original parent transition, then notification and
actual cleanup callback, temporary FS restoration, handler guards/epilog and
retirement. Only those completed effects can feed the checked continuation
boundary. Older-frame installation and complete API/context effects remain
separate admission requirements. Full startup and rcedit remain rejected.

CI readback: all three 6a612ccf workflows (40797179466, 40797171510,
40797171456) completed successfully. At this checkpoint 728e6df3 dedicated
40798060349 passed and both full runs were still active. Historical timeouts
remain unexplained.

### Decoded local loop using canonical storage and native callback fixtures

The unchanged 159-byte ordinary local body at VA0x402710 now runs its emitted
`LocalUnwindEffects` control flow through `CrtOwnedLocalEffects`. Each scope read
checks the canonical initialized level and the full bound table rows. A parent
must decrease or be -2. The original parent store reaches live bytes/protected
metadata before notification and cleanup. Notification and invocation validate
the pending row, target and abnormal reason; source/table/level checks run again
after callback effects. Failure retains reached stores and the installed
registry temporary head. Invalid nested/collided-handler entry remains rejected.

Thirteen independent native scenarios use a separately authored two-row table,
with two native callback instruction sequences that compute a trace value from
shared owned storage. Their expected order and values (5 -> 53 -> 537, or 57
when a filter row skips one cleanup) are specified independently of the decoder.
Callback bytes execute through the shared CRT emitter and protected CALL/RET,
and changed callback code rejects before its write. The callbacks and notification
provider are conformance fixtures, not the unchanged program's CleanupA/B or
original notification implementation. Their module/byte/protected-call checks
supply component evidence only, not program admission.

The cases cover normal cleanup, nested no-duplicate cleanup, notification failure,
callback failure after its write, changed table, corrupt cursor, changed guard,
nested failure, a filter row, an out-of-module callback, unknown level and changed
callback code. Successful nested calls restore the registry head in order; partial
failures retain actual marker and parent writes and cannot create a handler receipt
or Machine restoration. The changed parent-store displacement also rejects the
compiler proof. The wrapper evidence script now extracts and hashes all 159 original
body bytes and runs these cases on each host. The existing five recorded Windows
wrapper comparisons and whole-PE pair count remain unchanged (zero new pairs).

CRT tests passed 143/one ignored: 135 inherited, seven existing local-unwind tests
now included through the new test module, and one new native integration test.
The 13 new loop cases are separate from 74 owned and 10 local-store cases. Clippy,
formatting and projection/evidence checks pass. Existing frame tests are retained;
no decoder, API or whole-program admission policy was widened.

Remaining integration: prove/bind the unchanged notification and cleanup callback
bodies to this live adapter, back the temporary FS record with actual owned CRT
bytes, then execute original handler guards/epilog, retire younger frames and
issue the nonlocal continuation. The current component's temporary FS schedule is
validated by the registry; it is not yet the original guest thread's entire byte
state. Nested ordinary local invocations do not establish collided/nested exception
semantics. Older-frame installation, delivery-context effects and complete startup
remain unproved. Full rcedit/startup remains rejected.

All three 728e6df3 CI workflows completed successfully. For df78665c the dedicated
startup workflow40799674213 passed; both full runs40799681764/40799674303 had eight
successful jobs and compiler-native-linux still comparing independent LLVM outcomes
at the review checkpoint. Neither active work nor later passes resolve historical
original-process or observer-build timeouts; their diagnostics remain preserved.
