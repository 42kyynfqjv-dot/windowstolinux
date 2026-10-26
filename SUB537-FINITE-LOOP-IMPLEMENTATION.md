# SUB-537: recognized finite loop implementation

Implements the exact SUB536-FINITE-LOOP-DESIGN.md graph and conditional domain. The
owned checked importless image classifier routes writable images beginning with XOR
opcode33 to the private loop proof; other inputs keep existing read/straight-line
profiles. Classification grants no authority and failures never fall back. The loop
proof requires full28-byte graph/entry, every fixed byte and iced instruction boundary,
exact forward/backedge targets, closed only debug/relocation metadata, initialized
nonshared scalar data and two exact HIGHLOW fields bound to the same full word. Every
relocation is accounted for. Data-targeted loader writes remain rejected by intake.

Private ProvenLoop owns the validated image and derived bound/steps/result. Proof
construction uses structural induction, not run_bound or sampled termination: reset
i=0, stable bound N, one increment, unsigned comparison, sole backedge and rank N-i.
N<=254 gives no counter/sum wrap and <=1024 executed instructions (5 ifzero else6+4N).
Portable exit0..255 is separately checked, restricting this initial shape to N<=23.
Unknown resets, altered branches, extra paths/stores/calls and unproved cycles reject
before Rust output is written. Inspection reports confer no execution capability.

Generated native Rust contains a structured loop with scalar ADD/INC/CMP semantics,
not a general instruction interpreter. The same loop_state.rs checked transitions
are exercised by independent Rust unit expectations. XOR resets are explicit zero
initialization; JBE uses CF||ZF, JB uses CF, INC preserves CF before CMP replaces it.
The exact NOP has no memory effect. Runtime rank/step/result checks fail explicitly
with diagnostic/exit125 on an internal invariant violation; they cannot truncate and
return success. Normal proved execution completes within its static certificate.
No Wine, decoder or AI runtime dependency in the generated ELF.

Two new Rust functions bring the root suite to79 tests: independent scalar/zero/loop
boundaries and static-budget-versus-exit diagnostics. Seven deterministic native CLI
cases cover N0/1/2/5/6/23 and another preferred image base.96 rejection cases include
every fixed code byte, unknown-reset and unproved-cycle mutations, all truncated
bodies, prefixes, metadata/alias/partial-word targets, equal-valued different bound
words, missing/duplicate/extra relocation fields, unused-data loader writes, N24/254
exit errors and N255/high-bit budget errors. Failed conversions preserve existing
output. Nine prior Python model functions are inherited, not new native comparisons.

CI changes only frozen held_loop acceptance. Source/compiler configuration and PE
bytes remain untouched. Both hosts independently convert the same hashed PE to
identical Rust; actual ELF must match Windows empty stdout/stderr exit10. Twelve
compiler programs now required, plus102 authored comparisons and18 launch diagnostics;
remaining four held-out runtime/ordinary CRT/PE32+ cases reject. Alternate preferred
base tests do not establish observed Windows rebasing; actual loop load base remains
unobserved. Windows Server2025 results are not XP/7 or general application evidence.

Preserve original CPU support for multi-byte NOP, normal successful loader, flat32-bit
readable no-fault image, valid incoming stack/return and no external/asynchronous data
mutation assumptions. Physical volatile events/timing/debugger interaction are outside
the process-output contract. No generalized loops, writes, heap or external calls are
added. Three historical Windows timeout causes remain unresolved, no silent retries.
Next medium review: classifier/proof isolation, graph/relocation coverage, rank/step
limits, emitted structured control flow and unchanged artifact provenance. No merge/release.
