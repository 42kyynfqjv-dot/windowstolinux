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
