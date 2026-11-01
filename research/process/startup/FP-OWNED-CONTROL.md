# Owned guest FP control effects and original precision call

The original `0x4076a0 -> 0x40d000` call can now execute the complete precision
and query paths with an independently supplied, owned FP input state. The actual
entry still has unknown initial control/MXCSR values. After its earlier FNCLEX,
FWAIT at `0x40d00b` succeeds and FNSTCW at `0x40d00c` writes unknown control
knowledge to the real stack. The next unsupported operation is **MOVZX ECX,BX
at `0x40d013`**, whose existing lowering requires known input. No known default
or pointer authority is created. This is component execution, not full startup,
ordinary rcedit execution or default converter admission.

## Supported effects

The structural decoder retains separate FWAIT and FNSTCW nodes. Consumers must
bind the owned effect contract; default lowering and generic linear fragments
still reject these effects. A diagnostic instruction address is recorded before
the effect; it carries no continuation or memory authority.

- FWAIT proves absence of each unmasked pending exception and checks the status
  summary. On success C0–C3 become unknown; this effect survives a later failed
  store. Pending, unknown or inconsistent summary state rejects. It does not
  synthesize exception delivery or discard status flags.
- FNSTCW performs a checked 16-bit store without waiting. Unknown bits remain
  unknown. Only after a successful store are condition-code knowledge bits
  C0/C1/C2/C3 discarded, as specified by Intel.
- FLDCW currently supports **known control operands and clean exception state**.
  Masked pending flags, deferred unmasking, unknown operands and reserved
  precision encodings reject before state changes. Modern documented control
  fields are loaded; bit 6 reads as one. Other reserved input bits reject.
  Undefined condition-code knowledge is discarded. This bounded domain does not
  implement the full deferred-exception contract.
- STMXCSR requires a separately declared enabled-SSE/no-DAZ guest profile and a
  known scalar snapshot. It writes four checked bytes. Unsupported optional or
  reserved bits, missing profile and unknown snapshot reject. The profile does
  not acquire an initial value or read host FP state.

All effects use the existing process/thread/initialization/fiber-owned FP
context. Ended initialization, stale storage, cross-runtime identity and fiber
change reject. Generic checked memory retains protection, bounds and tagged
pointer/return restrictions. Earlier writes/control changes survive later
rejections. Neither host FP registers nor fixture values become an entry producer.

## Original control flow

The full 906-byte original low-level function and 242-byte control conversion
helper are byte-checked against the unchanged authored PE. Integer mask and
control conversions, conditional moves, the real FLDCW/FSTCW sequence, feature
read, STMXCSR and the final ambiguity check all execute.

For the actual precision mask `0x30000`, the original SSE mask operation yields
zero. With known inputs, its original comparison selects the branch around
`0x40ce10/0x410d10`. No MXCSR read or preceding memory effect is erased. Paths
requiring those helpers reject: the original EH4/DAZ loader, its exception filter
and fallback remain unimplemented. The wrapper's real successful return and
stack cleanup execute; its failure termination stays rejected.

Eighteen original-call cases include known query/precision/rounding inputs,
actual wrapper return, unknown control/MXCSR, pending flags, stale owners,
protected output, changed body/helper bytes, a mask reaching the unsupported SSE
loader and replay. These are supplied-state conformance cases, not eighteen
Windows/ELF program pairs. Twenty-three separate runtime cases and four emitted
wait/store cases cover checked memory, partial knowledge, failure ordering and
exact instruction attribution. All 152 existing word cases retain the 512 KiB
stack limit, also tested with 64 KiB environment padding.

## Evidence and remaining proof

Intel SDM Vol2A FLDCW pp3-357–358 and FSTCW/FNSTCW pp3-389–390, plus Vol2B
STMXCSR p4-647 and Vol2C WAIT/FWAIT p5-567, ground the instruction contracts. The reviewed PDFs and hashes
are retained locally. SHA256: Vol2A `71f69c75ae9ce3d4a103333266ac2f22d44f097e5b32279931151d7598993545`,
Vol2B `036ae35aec4da9dd54ba3b683547f09963f69609a3b98eae15586a692c4cd3d2`,
Vol2C `eb6b8645764f417ee1ccfb4f3df5b24e0a9d0ba488317b1e9d437d0a4e735e91`.
`observe_fp_control.c` saves/restores its complete FP state around each authored
instruction block. Twelve Linux observations and twelve Windows PE32/MSVC14.44 observations
are retained and their parsed instruction rows match. Windows run41352824230,
job124986487622, artifact13102241023 belongs to implementation head da1d3bd.
Source, PE and original CRLF output hashes were independently checked; see
[evidence](evidence/fp-owned-control.json) and
[raw Windows rows](evidence/fp-control-windows-da1d3bd.jsonl). These
observations establish only the tested instruction cases, not loader state or
initial Windows thread acquisition. Raw output is retained before validation.

The next semantic requirement is a justified producer or explicit initial guest
FP profile, with original-entry evidence and lifetime provenance. Existing
MOVZX lowering could preserve partial knowledge more precisely, but doing so
alone cannot establish the missing control/MXCSR values. Full deferred x87
exceptions, EH4/DAZ loading, resource failures, full startup/rcedit/default
admission and historical Windows launch-timeout causes remain unresolved.

## Validation checkpoint

At implementation commit `da1d3bd`, the final CRT aggregate passes 341 tests
(two artifact-dependent gates run separately), all nine FP tests pass, and
185 unwind tests pass. Clippy passes for all targets with warnings denied.
The evidence/protocol suite passes 104 tests with one skip. The unchanged
152-case stack gate also passes with its 512 KiB limit and 64 KiB environment
padding. A fresh coherent artifact replay is running; its completion and the
three current GitHub workflows must be checked independently. No final CI pass
is inferred from the successful Windows instruction probe.

Independent Sol review should inspect owned context and feature premises,
undefined-condition knowledge (including FWAIT), no-read versus checked-store
failure ordering, original call/return and precision-only loader exclusion,
partial effects, and the unknown actual-entry boundary. The remaining initial
state producer and deferred-exception semantics need a bounded design pass;
more supplied-state examples alone cannot close acquisition.
