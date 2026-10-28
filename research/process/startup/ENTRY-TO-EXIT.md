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
