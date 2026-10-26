# SUB-556 nonlinear scalar contract

The frozen squares program first rejects at RVA104e (`ADD EDX,-48`). Its next
instruction, `IMUL EDX,EDX`, needs a nonlinear expression domain. Merely adding the
first encoding would expose the next rejection. The reviewed scalar IR supplies
operand identity, guard snapshots, API classes and owned initialized reads.
This design extends scalar values only; production remains unchanged.

## Exact initial forms and effects

The unchanged MSVC listing requires seven additional forms: `83 c2 d0` ADD EDX,-48,
`0f af d2` IMUL EDX,EDX, `8b 4c 24 02` local DWORD to ECX,
`0f b7 c9` MOVZX ECX,CX, `83 c1 d0` ADD ECX,-48,
`0f af c9` IMUL ECX,ECX, and `03 d1` ADD EDX,ECX.
A future decoder must parameterize the scalar operations while retaining exact
encoding policy. Register permutation in a model does not authorize new encodings.

Two-operand 32-bit IMUL captures both old scalar operands, interprets them as signed
32-bit integers, multiplies to a signed 64-bit product, and stores the low32 bits.
CF and OF indicate whether sign-extending that low result reproduces the full
product. SF/ZF/AF/PF are undefined. The first production proof may conservatively
invalidate every flag after IMUL and ADD; all flag consumers then reject until a
supported CMP/TEST resets the consumed bits. Native emission uses wrapping_mul;
no admitted consumer can observe discarded flags. A future flag extension needs
separate proof. Immediate and register ADD wrap32. MOVZX preserves flags and
projects a proven UTF16 component; loads preserve flags and require all four
owned initialized bytes. Partial destinations and pointer operands reject.

## Sound expression and range rule

Retain the immutable affine leaves from SUB-554; introduce immutable Add and Mul
nodes capturing operands before assignment. Evaluating nodes modulo2^32 implements
bit-vector arithmetic; unsigned multiplication has the same low32 result as signed
IMUL. Preserve leaf symbols across copies, register writes and branch snapshots.
The model never overwrites a symbol's meaning when a register changes.

Compute child bounds recursively with checked wide arithmetic. For unsigned
intervals [a,b] and [c,d], addition lies in [a+c,b+d] and multiplication in [ac,bd].
If endpoints are in the same quotient bucket under division by2^32, reduce both
modulo2^32; otherwise return [0,2^32-1]. This encloses all outcomes even when operands
share symbols. Treating correlated occurrences independently loses precision but
cannot exclude an actual outcome. Do not narrow a product using observed values,
assume distinct variables are independent facts, or special-case the squares graph.
For the first implementation, nonlinear predicates and nonlinear low16 projections
reject; affine guard refinement continues unchanged. No algebraic solver is needed.

Each path retains its own ranges and owner/initialization state. Reevaluate bounds
under that path's guards; never carry a narrowed bound into a wider joined path.
Existing snapshots reference immutable expressions, not mutable registers. Reject
any unresolved emitted read, ownership join or portable exit. The existing API
length forks remain exhaustive under the input contract, including zero and
oversize results. Products do not grant buffer initialization.

After the guards, each `(unit-48)` is in [0,9]. Its square is in [0,81]; the sum is
in [0,162]. This symbolic enclosure covers every admitted digit. For one character,
only the first square is used. Missing/empty/error/too-long/non-digit paths retain
their existing original outcomes. Unit tests over100 digit pairs check the rule;
the soundness argument is the interval enclosure, not enumeration of sample inputs.

## Limits and failure behavior

The test-only model admits at most63 expanded expression occurrences and depth12
per expression, counting repeated references each time. Construction rejects above
either cap, so recursive range evaluation visits at most63 nodes. A production
port must enforce caps before allocation or recursive descent and use at least
u64 for unsigned endpoint products/sums (u32 products fit u64). Existing128decoded
instruction,512code-byte and4096symbolic-state limits remain. No runtime expression
interpreter: future native code emits decoded operations directly; analysis trees
exist only at conversion time. Unproved ranges/flags/projections reject without
changing a pre-existing output file. Model constructors issue no production proof.

## Evidence and implementation gates

Eight new independent model functions cover literal signed overflow vectors,
Cartesian interval enclosure against integer arithmetic, all100 digit-pair expected
results, six register permutations, snapshot/guard behavior, wrap rejection,
ownership/unknown/partial-state negatives and resource/domain validation. The prior
eight affine tests are inherited. `check_nonlinear.py` verifies the downloaded PE
hash, literal seven-form inventory and continued production rejection on both hosts.
It checks an experimental trusted compiler artifact, not hostile PE input.

Next implementation requires medium contract review, then bounded Astra work:
1. Port immutable scalar expressions and checked resource/range rules; retain the
   private metadata/ownership admission path and affine refinement capabilities.
2. Decode only reviewed forms into shared operations, validate source-before-write
   semantics and conservative flags, reject pointer/nonlinear predicate escapes.
3. Prove all return paths and full buffer ranges; emit direct native operations
   whose results agree with the proof under the documented input assumptions.
4. Require untouched squares PE -> Rust -> ELF with17 genuine Windows/Linux
   stdout/stderr/exit pairs, identical Rust across hosts and converter environments,
   independent overflow/alias/unsafe-guard/resource negatives and unobserved inputs.
   Preserve14 compiler programs,102 authored pairs,18 launch checks and all other
   rejection gates. Model success alone cannot change acceptance.

Helper calls and pointer propagation remain separate; ordinary CRT remains blocked.
Genuine procfs/stable initial environment, UTF8/resource, valid-stack/no-fault and
unobserved actual-load-base assumptions persist. Windows Server2025 evidence is
not XP/7 validation; four historical timeout causes remain unexplained.

## Provenance

Independently authored original model; MIT OR Apache-2.0. Instruction contract:
Intel Software Developer Manual Volume2 IMUL (two-operand form), ADD, MOVZX and
Volume1 flag/register rules, via the [primary manuals index](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html).
No Wine or proprietary implementation source is used. Existing API/ABI provenance
is in DESIGN.md. Frozen C/flags/expectations remain in ../diversity/frozen.json.
