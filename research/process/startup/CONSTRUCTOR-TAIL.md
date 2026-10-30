# Original constructor tail and checked indirect-call boundary

The explicit native profile now runs original constructor402c2d..402c73 through
its indirect CALL402c61. Original MOV402c47 preserves the returned function in ESI;
ADD402c49 removes the four resolver arguments; TEST selects the non-null branch;
the three PUSH instructions preserve original flags/spin/object arguments. The
mapped guard cell415128 must select401bf9 and the actual three executable bytes
must remain `RET0`. That original stub executes under a protected nested call.

Guard entry checks ECX and ESI identify the same live implemented export. The
local receipt is consumed once at the indirect instruction, then unique published
export, source provider and actual target lifetimes are revalidated. Scalar
addresses cannot substitute for typed functions. The indirect CALL uses the
shared protected call machinery with stdcall cleanup12; a successful API return
is not manufactured. The unsupported resource contract returns an error before
initializing any lock. Existing module/function caches and earlier startup writes
remain visible, while startup itself remains unfinished.

At the boundary the actual call arguments must have checked initialized words,
a writable aligned24-byte image/object range and flags0. A numeric image address
is resolved only through canonical process-image ownership, never retagged from
an unrelated allocation. These checks establish argument/storage prerequisites;
they do not certify allocation success or execute InitializeCriticalSectionEx.
The fallback import415058 is still explicitly unsupported and its prospective
stdcall cleanup is8. No missing symbol is rewritten to a successful fallback.
The original complete RET0 is decoded but has not been reached by the admitted
explicit-profile entry path. Default admission still rejects LoadLibrary402b00.

## Review and evidence

Review of4ee74c7 retained unique case-sensitive named lookup, source publication
membership and independent target lifetime, with fixed reference limits and no
new callable authority from a descriptor. All three predecessor4a7ec01 workflows
41056014512/41056006557/41056006622 completed successfully. Reviewed4ee74c7 CI
41057500037/41057487928/41057488149 remained in progress at review.

Ten independent guard cases cover actual original stub execution, preserved
registers/flags/stack, typed-versus-scalar mismatch, unpublished and uncallable
exports, stale module identity, invalid protected return, wrong target and replay,
changed original guard bytes and changed mapped guard target. Every successful
case asserts success, and failures assert exact rejection and unchanged references
and zero constructed objects. Existing missing-name, stale-provider, capacity,
readonly storage and changed-loader cases remain mandatory. Mutation tests bind
to unchanged PE sections; no fixture program or compiler flags were tuned.

The extraction harness previously retained only26 prefix bytes; it now extracts
all71 unchanged original bytes. The failed extraction/code-identity test is
retained locally in constructor-tail/replay. The first implementation attempt
also hit the generic Graph decoder's deliberate indirect-call rejection; the
constructor now uses the existing closed indirect-call emitter contract, as other
checked dynamic wrappers already do. Generic graph rejection was not weakened.

## Exact remaining semantic question

Original entry reaches CALL402c61 with spin4000, flags0 and the actual mapped lock
argument. Native fixed storage does not alone establish what an original Windows
call would do when resources are scarce. The primary
[InitializeCriticalSectionEx contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex)
specifies nonzero success or zero failure with GetLastError, opaque object handling
and deletion before reinitialization. It does not supply one universal allocation
failure code or a complete failed-object byte contract. Documentation was checked
on2026-10-30; success observations cannot prove arbitrary resource availability.

A bounded Astra pass is warranted to choose and justify either (a) a recoverable
native failure relation with established LastError/object/cleanup behavior, or
(b) an enforceable resource-sufficient profile relation with explicit Windows-side
premises and native reservation/budget proof. It must not issue a synthetic success
token or map every internal rejection to guest failure. Then connect actual
InitializeCriticalSectionEx behavior, original constructor return and lock count
publication4029c5..4029da before advancing to FLS. This is a concrete external-effect
contract question; no new generic loader layer or identical success probe closes it.

[Machine-readable evidence](evidence/constructor-tail.json) retains hashes and
validation. Component replay is separate from whole-PE entry-to-exit. Full
startup/rcedit and historical Windows timeout causes remain unresolved.

Validation:279 CRT tests passed, both artifact tests passed in replay, all ten guard cases passed,75 Python tests passed (one existing skip), and Clippy/format passed. Five recorded Windows wrapper component comparisons retained; zero new whole-PE pairs.
