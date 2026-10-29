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
