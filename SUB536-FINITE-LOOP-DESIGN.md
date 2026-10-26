# SUB-536: proven finite scalar loop, design only

The frozen loop.c sums0..4 and returns10 with empty stdout/stderr on Windows
Server2025. Its source/configuration freeze remains cf042295303dccedb8506564f1e466ef9d353acd.
The unchanged MSVC19.51.36260.0/LINK14.51.36260.0 image contains this28-byte body:
`33c0 33c9 390500304000 760f 0f1f4000 03c1 41 3b0d00304000 72f5 c3`.
HIGHLOW fields at entry+6 and entry+21 both address the initialized bound word5.
Production still rejects at the first XOR in its private straight-line image-read
profile. This proposal adds test-only proof/model evidence, not loop execution.

## Primary semantics and scope

Independent authored Rust design/Python prototype, MIT OR Apache-2.0, no Wine source.
Read Intel SDM093 CMP/INC/Jcc/ADD/XOR in Vol2A and NOP/RET in Vol2B from the previously
downloaded primary text, including explicit NOP no-memory and JBE/JB flag conditions:
https://cdrdv2.intel.com/v1/dl/getContent/671199
https://cdrdv2.intel.com/v1/dl/getContent/671241
PE initialized data and HIGHLOW rules remain from the Microsoft PE specification:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

Choose a separate private recognized-loop candidate alongside the existing read/add/
return candidate. A checked decoder/shape classifier must select one before proof;
an unsuccessful proof cannot fall back to a more permissive path. This avoids granting
arbitrary backward control flow to the existing call/stack/output machinery. Production
implementation should factor common owned-image read/relocation checks if safe, while
keeping the loop proof token private. Public inspection reports remain non-emitting.

The first accepted loop graph is deliberately this exact ten-instruction layout;
absolute VA operands and initialized bound may vary subject to proof. This is semantic
recognition of a narrow compiler loop, not a general loop solver or application claim.
Entry equals sole code start, virtual code extent28. No prefixes, extra instructions,
alternative encodings, unproved unreachable code, calls, tails, stores or pointer escapes.

| Offset | Exact form | Semantics/successors |
| --- | --- | --- |
|0|33C0|EAX=0, logical flags; next2|
|2|33C9|ECX=0, logical flags; next4|
|4|3905 va32|CMP memoryBound,EAX; next10|
|10|760F|JBE: CF or ZF; taken27, otherwise12|
|12|0F1F4000|NOP; next16; no memory operation even though disassembler prints [EAX]|
|16|03C1|EAX += ECX modulo2^32; next18|
|18|41|INC ECX modulo2^32, preserves CF; next19|
|19|3B0D va32|CMP ECX,memoryBound; next25|
|25|72F5|JB: CF; taken16, otherwise27|
|27|C3|Entry return with scalar EAX0..255|

NOP requires an original CPU supporting the multi-byte NOP encoding. That assumption
must be explicit; this is not proof for every historical x86 CPU or XP/7 environment.
CMP subtracts second operand from first solely for flags, preserving both values.
JB/JBE are unsigned; substituting JL/JLE is unsound near sign boundaries. INC updates
ZF/SF/OF and preserves CF, while the following CMP defines CF before JB. All four
tracked flags have explicit knowledge; unknown consumers reject. AF/PF are affected
architecturally but not observed by these forms. XOR resets known scalar zero even
from unknown incoming volatile EAX/ECX; neither register is a pointer capability.

## Termination proof and invariants

Let N be the full known u32 from the same proven stable initialized word for both
comparisons. After reset EAX=ECX=0. CMP N,0 followed by unsigned JBE exits iff N=0.
The zero path executes five instructions and returns0. For N>0, the header at16 has:

- ECX=i, 0 <= i < N; EAX=i*(i-1)/2 modulo2^32.
- Stable bound N, unchanged code/metadata/return ownership; no program writes/escapes.
- Ranking function R=N-i is a positive mathematical integer.

One body iteration adds i, increments ECX to i+1 and compares i+1 with N. If i+1<N,
the sole backedge returns to16 with rank R-1. Otherwise i+1=N and the path exits27.
No other cycle or entrance to the body is admitted. At exit the nonzero path has
ECX=N and EAX=N*(N-1)/2 modulo2^32. The zero and loop-exit join can have different
flags; RET does not consume flags. No invented join values or unknown-state merging.
At each header flags are fully established by prior instructions, but ADD overwrites
them before use. ESI/EDI/EBX/EBP and stack are unchanged until terminal entry RET.

Static budgets: exactly10 decoded instructions, at most254 iterations, at most1024
executed instructions. Nonzero path has6+4*N instructions; N=254 takes1022. N=255
would take1026 and rejects before emission. This small limit ensures ECX never wraps;
total also stays below2^32 (maximum32131). Unknown/large/wrap-risk bounds reject
instead of assuming modular induction is monotone. The prototype separately tests
machine wrap/overflow flag semantics, but those cases do not widen admitted loops.
The portable exit0..255 gate further restricts this initial summation shape to N<=23
(sum253); N=24 has a valid finite proof but rejects executable eligibility (sum276).
Keep termination proof and observation-domain rejection distinct in diagnostics.

Future emitted Rust should preserve the mechanically recognized loop using typed
scalar operations and a native structured loop, with the same checked arithmetic/flag
contract as validation. No original-instruction interpreter, dynamic execution fallback
or AI runtime is needed. The proof fixes the exact iteration/step upper bound before
emission. A redundant runtime budget may fail explicitly with diagnostic/exit125 on
internal invariant failure; it must never truncate and return success. Such failure
is unreachable for proved inputs in the stated domain. Tests must cover the cap itself,
not infer safety from the fact that the sample N=5 terminates.

## Memory, relocation and environment proof

Carry forward SUB534/535 checked owned envelope and complete metadata closure: only
relocation/debug directories, one initialized nonshared RW section, file-backed full
four-byte reads, disjoint file/virtual ranges, no zero-fill or metadata aliases. Both
exact decoded address fields need unique HIGHLOW entries and must resolve to the
same RVA in the same snapshot. Equal numeric values at different addresses do not
establish this invariant. Account for every relocation; reject data-targeted loader
writes, extras, duplicates, unsupported kinds and field misalignment/overlap. No
caller-supplied descriptor/digest or inspection JSON confers authority. A private
loop-proof value must bind its graph, image, bound and budget together through emission.

No-store/no-call/no-system-effect proof covers the full graph, including the zero
branch and loop backedge; sampled execution cannot establish it. Relocated bytes are
operand fields only, not scalar bound data. NOP's apparent memory operand is not a
read and requires no pointer authority. General writable global/heap access remains
outside scope. Loaded scalar N cannot become an address. Original volatile reads are
stable only under the explicit normal-loader, flat32-bit, readable/no-fault, valid
incoming stack/return and no external/asynchronous mutation/thread assumptions.
The output contract excludes physical volatile-read event counts/timing/debug tracing.
Static proof excludes program-originated writes; it cannot exclude an external debugger
changing the bound. Actual load bases remain unobserved for this artifact; base-delta
arithmetic is not real rebasing evidence. No security changes or forced loading needed.

## Evidence and subsequent gates

Eight new independently expected model test functions cover literal N=5 header states,
zero/one/max iteration/exit boundaries, unsigned comparison tables, signed overflow,
INC carry preservation and wrap, unknown flags/scalars, changed/nonterminating graphs,
wrong backedges/resets/effects, truncated body, different bound addresses, metadata and
relocation errors and snapshot identity. The rank proof is checked structurally before
any concrete loop trace. Literal expected values are not obtained from production.
Test-only Image layout helpers and the permissioned PE model are inherited; their
existing tests are not new counts. Python Proof is a test dataclass, not a protected
production token; its trace accepts only internally proved values in the harness.

The artifact checker verifies frozen source/PE hashes, exact original bytes/data/relocs,
Windows empty output/exit10, literal header trace and26 model steps on both hosts.
Production conversion remains rejected. Existing eleven compiler comparisons,
102 authored pairs,18 launch checks and five held-out rejection gates remain required.

Medium review must challenge rank/step algebra, compare operand order, CF use/preservation,
zero-path join, NOP CPU assumption, immutable-bound provenance and proof-token isolation.
Then a separate Astra implementation issue may introduce only the table/graph above,
with independent native boundary and CLI malformed/nontermination/cap tests. Require
actual unchanged loop PE->Rust->ELF empty output/exit10 agreement and identical Rust
from the same hashed PE on Windows/Linux before changing acceptance. Preserve all
prior programs and remaining four held-out rejections. General loops/CRT/runtime input/
PE32+ remain separate. Three historical Windows timeout causes remain unexplained;
no silent retries. No merge/release. No known tool/resource blocker.

## Medium contract review

Rank and step algebra hold for the recognized graph. A u32 bound has no negative
value; bytes representing a negative signed integer (high bit set) instead denote a
large unsigned bound and fail the static budget. Do not reinterpret them as zero or
use signed branch conditions. N=0 consumes five instructions, bypasses NOP/body, and
returns with ZF=true/CF=false. N>0 consumes6+4N, with N=254 reaching1022; portable exit
eligibility is a separate later check. No counter/sum wrap is possible in the admitted
budget domain, while helper tests check architectural wrap semantics independently.

Added a ninth independent test function to close an evidence gap: structural proof
construction is tested while concrete trace/add/increment are disabled. It still
certifies bound254 and rejects255, demonstrating that sampled execution is not used
to create the certificate. The same test asserts the zero-path flags/join and mutates
every non-address code byte, including all NOP bytes, to confirm complete recognition.
Earlier eight-test count above is historical. No model behavior or production change
was required; no architecture blocker found.

SUB-537 must retain private certificate construction (Python dataclasses are only test
artifacts), verify the full decoded graph before binding/proving, and bind graph/image/
bound/budget through emission. Prove against the same immutable owned snapshot used
by emitted constants, never a public digest or mutable descriptor. Add production
regressions for all fixed graph bytes, high-bit bounds, zero join, static budget versus
exit-domain diagnostics, and reject unproved cycles before any native execution. The
model's action-level flag helpers do not establish a future Rust decoder or emitter's
correctness; actual same-PE Windows/Linux native evidence remains mandatory. Ready
for bounded Astra implementation after final review CI. Execution assumptions, NOP
CPU support, unobserved actual load base and three historical timeouts remain explicit.
