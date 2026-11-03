# Original processor-feature initializer

The controlled, explicit native-profile entry executes the final original C
initializer at `0x4127b0`. It calls `IsProcessorFeaturePresent(10)`, stores the
whole EAX result at `0x41d2fc`, executes XOR EAX,EAX, and returns through the
protected return. The guarded C-initializer array then returns to `0x401678`.
The caller's two argument pops, result branch and subsequent C++ initializer
array are the next unexecuted instructions. This is component execution from
the unchanged input entry, not whole-PE conversion or full rcedit support.

## Contract and evidence

The callback uses the same live CPU/OS observation as the earlier startup
classifier. Explicit component profiles and actual Linux x86-64 observations
remain distinct. The native mapping uses the existing legacy SSE execution
premise and Linux ABI; it does not claim old Windows HAL/XP/7 equivalence or
permission to emit arbitrary SIMD instructions.

Microsoft's IsProcessorFeaturePresent contract specifies zero or nonzero BOOL,
not the exact nonzero representation:
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent

A false result is known zero. A true result is a runtime-bound symbolic nonzero
word. The original full-width store removes previous byte/pointer knowledge,
without manufacturing known TRUE bits. Full-width zero comparison and self-TEST
retain truth knowledge; byte reads, nonzero numeric comparisons and unsupported
bit observations reject or retain unknown flags. Distinct true results cannot
be assumed to share set bits. This value supplies no pointer authority.

Disassembly of the frozen PE finds direct consumers at `0x411690` and `0x4126a0`;
both compare the complete stored word with zero before accessing MXCSR. Their
subsequent FP operations are not admitted by this callback integration.

API binding checks profile initialization, process/thread/host identity, active
return authority, stdcall cleanup, saved registers, writable stack and selector
before acquiring a result or changing LastError knowledge. The earlier exact
truth-only caller retains its existing normalization contract. The new callback
uses a separate raw-BOOL binding. No externally supplied success result replaces
the original CALL, MOV, XOR or RET instructions.

## Independent checks

Twelve API cases cover true/false, unknown/wrong selector, expired initialization,
wrong cleanup/saved registers, stale thread/host, malformed CPU profile, duplicate
return identity and fresh result identity. Thirteen original-artifact cases cover
code mutation, cross-runtime/profile expiry, readonly destination, repeated fresh
calls and replacement of a prior pointer word. A failed original MOV preserves
the successful API effects. A later RET failure preserves the prior MOV.

Eight independent FILE/global-range cases cover overlap on either edge, exact
adjacency, equal ranges and address overflow. With zero FILE metadata capacity,
o reservation occurs on overlap rejection; byte knowledge and the existing
global owner remain intact. The earlier original-body regression also preserves
the already-published FILE vector and zero pending slots. Canonical empty and
three-entry synthetic environment variants retain owned FILE, environment,
locale, argv and reference-count checks through the C-array return.

Validation results and final source-pinned replay are recorded separately. Five
retained original-Windows component comparisons are not new whole-PE evidence.
No newly admitted full program or complete original-Windows delivery is claimed.

## Next review and connected scope

Independent review should check raw versus truth-only API binding, BOOL store
knowledge, ABI preflight, prior effects on failed MOV/RET, and the overlap edge
cases. Then Sol can connect the original caller's two pops and result branch,
and guarded void-array traversal at0x406ca1. The readonly range0x415130..0x415138
contains NULL and callback0x40160d. That callback first executes0x401d93, which
registers0x401d9f through SetUnhandledExceptionFilter at IAT0x415010, then calls
the existing mode helper and0x4071d0. The process-owned unhandled-filter exchange,
callback lifetime and eventual exception/termination effects need an explicit
contract; this inventory does not admit them. A difficult exceptional-delivery
composition question would warrant a bounded Astra pass, not routine polling.

Local verification:361 aggregate CRT tests,185 unwind-example tests,114 Python
tests (one skip), all152 low-stack cases at512KiB plus64KiB padding, canonical
original-entry cases, formatting and all-target Clippy. Final commit-pinned
replay and exact-head remote CI remain separate publication gates.

## Preserved limitations

The default/unknown FP profile remains rejected. Native resource rejection is
not Windows allocation-failure equivalence. Exceptional cleanup, copy-error
termination, broader FP semantics, full startup and rcedit remain unsupported.
Only controlled synthetic environments are used.

The original-Windows C01 timeout in run 41378889653/job 125065106041 is retained
with artifact 13112293419. C01 output followed by a still-live process occurred
before conversion. WCT metadata identifies neither the stalled instruction nor
its termination stack. The missing evidence is a same-process thread context or
stack/termination-location observation; current retained diagnostics cannot
establish loader, CRT or harness causation. No timeout change, dropped comparison
or pass-only rerun was used. Passing later CI does not diagnose this failure.
