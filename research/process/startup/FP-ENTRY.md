# Original FP-control caller: integer prefix checkpoint

This records `bf95b1f`. See [owned FP effects and current boundary](FP-OWNED-CONTROL.md)
for the subsequent implementation; the historical evidence below is retained.

## Connected execution

The original call `0x401be4 -> 0x4076a0` now executes its integer validation,
argument loads, mask transformation, actual branch and nested CALL. The original
callee at `0x40d000` executes its real frame prolog and saves EBX/ESI/EDI.
Connected startup rejects **before waiting FSTCW at `0x40d00b`**. No control word
is read, output pointer written, x87/MXCSR state changed or successful FP return
supplied. The existing post-call continuation remains separately rejected.

Original argc/argv, SLIST, callback encoding and earlier startup effects remain.
The actual low-level frame carries new-value `0x10000` and mask `0x30000` on the
connected path. Full startup, rcedit and default converter admission remain
unsupported. These are original-instruction component cases, not whole-PE pairs.

Both new regions are verified against the unchanged authored PE before replay.
No source bytes were changed to fit. The first prefix includes the waiting
opcode in its byte guard, while its graph ends before that unproved instruction.
Integer proof/emission uses the existing shared checked stack and protected CALL
machinery; it does not grant an FP effect token or suppress pending exceptions.

## Independent boundary cases and unknowns

[Expectations](evidence/fp-entry-expectations.json) and
[results](evidence/fp-entry-prefix.json) distinguish **16 rejection-boundary
cases** from successful FP operations. Cases cover original precision setup,
query and non-NULL output, invalid-mask ordering, unknown input words, expired
initialization, code mutations, duplicated return authority and pending status.
Output bytes and the entire existing guest x87 state remain unchanged. The
actual low-level argument words and their knowledge masks are checked.

An initial test expected unknown new-value/mask words to reject immediately.
The actual integer operations can decide the invalid-bit check when a known
mask or new-value filters those bits, while leaving other argument bits unknown.
The expectation was corrected to check that exact partial knowledge reaches the
unbound FP instruction. An unknown output condition still rejects; no unknown
bit was filled in and no FP effect was admitted. No acceptance rule changed to
make the test pass.

For invalid mask with NULL output, execution rejects at the original errno
acquisition. With non-NULL output, the original query precedes that error path
and reaches the unbound waiting instruction first. Neither route is represented
as successful cleanup, an errno write or an invalid-parameter callback.

## Concrete next semantic scope

A bounded Astra High pass can establish these connected requirements:

1. Bind initial/control/status x87 knowledge to the live guest thread/fiber and
   process. Current FNCLEX state deliberately starts with unknown control bits.
   CPU reset defaults, a Linux host snapshot or an authored test seed do not by
   themselves establish original Windows entry state. Identify a documented
   target-profile premise or independently observe the original entry boundary.
2. Implement waiting FSTCW separately from FNSTCW. Preserve the control-word
   store and memory knowledge. Check pending unmasked exceptions using the same
   owned status/control context; reject missing delivery proof. Earlier actual
   FNCLEX knowledge may justify a no-pending path, not arbitrary future calls.
3. Preserve FLDCW control updates and deferred unmasking behavior; do not clear
   status or assume that loading a control word delivers every pending exception
   immediately. Preserve actual state changes if a later supported effect fails.
4. Keep MXCSR distinct from x87 and XMM payload. Lift the original feature-gated
   STMXCSR/LDMXCSR path with supported/reserved-bit checks, permissions, lifetime,
   output ordering and coherence with the declared CPU/OS feature profile.
5. Execute the existing CRT integer mask conversion/reconciliation instructions
   (including helper `0x40d390`), not a replacement that returns a guessed CRT
   control value. Retain ambiguous x87/SSE state and invalid-mask behavior.
6. Close original output/errno/invalid-parameter paths only with their existing
   owned producers. FP state can change before a later output store; unsupported
   alias/fault paths must reject admission, not silently roll back or report a
   fabricated Windows result.

Independent tests should cover known/unknown masks, masked versus unmasked
pending flags, reserved bits, stale/cross-fiber state, aliased or protected
outputs, partial effects and changed code. Authored native/Windows probes must
save and restore their own FP state, preserve raw failures/timeouts, distinguish
x86 from x64 CRT behavior, and remain component observations. No host security
settings, kernel work or ordinary application compatibility claim is needed.

## Primary contract grounding

Microsoft documents different x86/x64 control behavior, denormal-mask differences,
invalid-parameter handling and potentially ambiguous x87/SSE state:

- [_controlfp_s](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/controlfp-s?view=msvc-170), retrieved bytes SHA256
  `27e6b8da318f572416532186e91e15564ae6958b04b4ad5b060bea6217dfe792`.
- [_control87 / _controlfp / __control87_2](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/control87-controlfp-control87-2?view=msvc-170), retrieved bytes SHA256
  `56bc777b470bfc37a41d06a3c9b045ab90d9e6b75a82de1fb28f0e527f5b0ee2`.

These contracts guide the next proof; the implementation here only executes the
guarded integer instructions. ISA waiting/control effects need their own Intel
SDM grounding. Existing [FNCLEX evidence](X87-STARTUP.md) does not prove them.
The [stack-regression repair](evidence/word-stack-review.json) and historical
original-Windows timeout evidence remain separate from FP correctness.


## Verified checkpoint

CRT337 (two ignored artifact gates exercised by the complete replay), unwind185,
Clippy warnings denied, formatting and101 startup Python tests (one skip) pass.
Full original-source replay passes five retained Windows wrapper comparisons;
these are not new FP comparisons. Repeated emission is identical at Rust SHA256
`65ae157162f6fabe40981b192829bd9bd9ec3e2cc328cdb242a4c5b1e581d649`.
The frozen PE remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
No new Windows FP observation or whole-PE pair is claimed. New exact-head CI
remains separate; the earlier word-test failure is retained, not erased by the
local passes. Sol can review the integer-prefix and test-frame diffs. The next
Astra High scope is the connected owned guest FP/control contract above.
