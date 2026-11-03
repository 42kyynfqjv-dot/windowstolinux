# Original C++ initializer and process filter registration

The controlled native-profile entry now executes the original caller cleanup
and result branch at0x401678, then the guarded void array at0x406ca1. Its readonly
range0x415130..0x415138 contains NULL and0x40160d. The original callback registers
0x401d9f, calls the existing zero-mode helper, and executes the checked original
new-mode setter/XCHG and RET. The caller pops both arguments, stores startup
state2 and pushes its lock-release flag. It stops **before CALL0x4016b4 →0x401a9c**.
It does not complete ordinary startup, Main, exit, or whole-PE conversion.

## Reviewed predecessor

Review of62eaa8c found no additional production defect in raw versus truth-only
BOOL binding, ABI preflight, full-word knowledge replacement, failed MOV/RET
partial effects or opaque-owner overlap. Its final560-source manifest was
independently compared to every committed blob; report SHA256 is
b01b7deea10790d1ba0d51f2bd2516a8fec3dc35be0ee1975bf25b5d92c23bc9.
The five retained Windows comparisons are component evidence, not whole startup.
All three exact62eaa8c workflows41384567740/41384562524/41384562526 passed.
That does not diagnose historical original-Windows launch failures. New-head
gates are tracked separately.

## Declared process-owned exchange contract

Primary requirements:
[SetUnhandledExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter)
and [UnhandledExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter).

The first API exchanges the process-wide top-level filter and returns its
previous address. NULL selects default handling. Registration alone does not
invoke the callback. Actual invocation depends on unhandled delivery, debugger
state and the faulting thread's exception/context state. The second API is a
separate effect and remains unbound here.

One canonical runtime process slot starts **Unobserved**, not NULL. Its initial
returned word has no known bits or pointer authority. The original registration
wrapper returns that unknown word; its caller really overwrites EAX with the
zero-mode helper before observing it. No guessed predecessor is erased. Once
known, NULL/default and checked guest code targets retain their actual identities
across subsequent exchanges. Repeated registration returns the previous target.

Supported targets are NULL or canonical executable pointers into the live,
process-owned main image. This does not acquire a temporary DLL reference or
make an unimplemented export callable. The narrow ABI adapter derives a pointer
only through the already-owned main-image argument contract, checks stdcall
cleanup/saved registers/return/stack permissions before effects, and leaves
LastError knowledge unknown on success. Unknown addresses, foreign or truncated
views, stale image generations and unsupported roles reject before exchange.
Native exchange uses a fixed enum slot without allocation. Concurrent guest
threads, asynchronous host mutation, external DLL callbacks, restoration of an
unobserved prior filter and Windows resource-failure equivalence remain outside
this startup-exclusive domain.

The slot survives initialization/fiber retirement while its process/image is
live. It is distinct from FS registration order, the borrowed incoming handler,
and saved exception context. Callback storage carries no execution certificate:
`unhandled_filter_delivery` rejects for every state, including NULL/default.
Changing the stored callback body does not cause registration to execute it.
A full delivery implementation needs the faulting event, live EXCEPTION_POINTERS
and owned x86 CONTEXT, callback instruction effects/disposition, and debugger,
error-mode, continuation/termination contracts. Existing containment requirements
still reject whole-program admission when these paths are unproved.

## Original consumers and ordering

The artifact's registrations are0x401d98 (guest callback) and0x4017b3,0x401d28,
0x407a55 (NULL in failure paths). The latter immediately approach the separate
UnhandledExceptionFilter API; they are not converted to successful delivery.
The installed0x401d9f callback can inspect C++ exception records and reach PTD
mutation and termination helpers. None of that is executed or inferred here.

The void walker reuses checked readonly array/argument identity, guard receipts,
cursor bounds, ordered single-use completion and protected CALL/RET validation.
It does **not** inspect a void callback's EAX; nonzero, unknown and owned-pointer
returns do not short-circuit traversal. Failed callbacks preserve preceding writes
and prevent later callbacks. C and C++ walker code guards remain distinct.

Original XCHG accepts only the existing exclusive initialization domain with a
known scalar old mode; unknown/readonly mode state rejects with prior filter
registration preserved. Invalid mode errno/handler paths remain unbound. The
caller publishes state2 only after normal array return. Its four-byte release
argument preserves the actual byte-initialized local: upper bytes stay unknown.

## Next connected scope

Sol can review this exchange/walker boundary and connect the original lock-release
helper at0x401a9c. Its existing runtime-flag guard controls a shared-lock XCHG;
the original CMP reads only the release argument's low byte. Unknown upper bits
must not be forced to zero. Further callback
cells, normal Main entry and termination remain separate original instructions.
No Astra escalation is required for this routine review. If actual unhandled
delivery becomes necessary, the exact unresolved problem is how the faulting
thread's live EXCEPTION_POINTERS/CONTEXT and process-selected callback produce
validated context changes, debugger/default handling or termination while
preserving the existing incoming-chain containment boundary. Registration does
not close that problem.

## Independent expectations and evidence

Eight independent original result-prefix cases execute zero/nonzero, partial
known/unknown and symbolic truth, argument pops, failed scope writes and the
protected-control alias rejection. They are supplied-result instruction cases,
not original-Windows allocation-failure observations.

Twenty void-array cases cover empty/null/maximal arrays, unrelated callbacks,
ignored nonzero/unknown/pointer returns, failures after writes, missing or damaged
RET, stale initialization/image, changed arguments/guards/code and replay.
Twenty-eight filter/CPP cases cover first and repeated exchanges, known default,
unknown initial return, prior-target replacement, restoration of owned targets,
foreign/truncated code views, fiber/thread/process lifetime, readonly/unknown
mode failure and original caller/callee mutations. Failed later instructions do
not undo completed registration or mode stores. A changed installed handler body
still registers but never gains delivery authority.

The frozen authored Windows probe first checks that its two targets differ,
then records five exchange identity observations
without invoking either callback and restores its own initial host filter before
exit. Distinct callback bodies and disabled identical-code folding prevent a
self-confirming same-target exchange. Its source/expectations hashes, compiler/SDK identity, executed PE hash and
launch artifacts are retained by the existing CI workflow. This is a new original
Windows API observation, **not translated-PE evidence**; its result is pending
until the exact-head artifact is available. The bounded native subset does not
claim restoration authority for an unknown external initial filter.

All prior canonical, aggregate, Python, Clippy, adversarial and152 low-stack gates
remain required, followed by a clean commit-pinned replay. Synthetic environments
only. Historical original Windows C01/case19 timeouts remain unresolved: WCT and
output do not identify the stalled instruction/stack. No passing later run is a
root-cause diagnosis. No timeout relaxation or comparison removal closes them.

Local verification passed362 CRT tests (two artifact gates separately handled),
185 unwind-example tests, canonical controlled-entry and all28 filter/20 void
array cases, eight independent result-prefix cases,115 Python tests (one skip),
all-target Clippy with warnings denied and formatting. All152 word cases passed
at the unchanged512KiB child limit plus64KiB inherited padding. The frozen new
Windows API observer is pending exact-head CI; these local checks do not claim
that observation occurred. Final committed-source replay is a separate gate.
