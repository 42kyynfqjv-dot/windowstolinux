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
| C++ unwind | Original state read4043e9 and state write404406 now execute on the same checked live record | Wrapper4041a4 and EH4 body4041bc still unbound: own its registration/frame, PTD+18 counter, metadata traversal, pending action, callbacks and exceptional exits |
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

Integrate original4041a4/4041bc using the existing owned frame/continuation system:
EH4 metadata41b298 and actual registration/epilog, signed state traversal, full
map bounds, PTD+18 increment/decrement, pending action ownership and actual action
calls. Include nested delivery, stale aliases, wrong counter/storage, action failure
and nonreturning termination cases. Do not bypass the EH4 prolog or infer a
no-exception domain from successful normal cases. The actual map's actions jump
to40770c, whose PTD+12 callback and eventual abort behavior remain external gates.

This is the next meaningful composition, rather than another scalar helper.
A bounded Astra High pass is appropriate if the EH4 child-frame and pending-action
ownership cannot be established using the reviewed shared machinery. Sol can
review this checkpoint and collect the exact original metadata/effect evidence.

## Objective whole-program acceptance

One normal converter invocation on the unchanged PE, from its header entry,
must produce deterministic Rust/ELF with no supplied state/result vectors or
skipped startup. Require matching original Windows and Linux stdout, stderr and
exit, artifact/source/toolchain hashes, failure-path checks, and independent
lifetime/alias/unknown-state/cleanup negatives. Passing individual rows does not
establish their entry-to-exit composition.

## CI evidence

At the preceding checkpoint, fe0d0dc push run40949077644 attempt1 failed artifact
creation with ECONNRESET, leaving later comparisons skipped. Its exact job/steps
remain in [upload-reset-fe0d0dc.json](evidence/upload-reset-fe0d0dc.json).
Only failed job123714769651 was explicitly retried through GitHub's normal API;
run attempt2 is a labeled infrastructure retry of the *old* commit. It neither
erases attempt1 nor validates newer heads. Historical original-Windows process
exit timeouts remain separate and unexplained.
