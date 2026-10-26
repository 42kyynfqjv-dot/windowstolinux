# SUB-554 bounded scalar IR and refinement contract

Decision: generalize the scalar operations of the existing input proof over
explicit register and width operands. Keep PE/API/owned-stack admission separate.
The first implementation target is the unchanged frozen `guard_join` program.
This document and Python model grant no production eligibility. All three SUB-553
programs must continue to reject until the later implementation gates pass.

## Representation and transfer rules

Canonical register IDs are EAX, ECX and EDX. An operand denotes the full 32-bit
value or its low 16-bit view (AX/CX/DX). The low view aliases the same underlying
value; it is not an independent register. ESI save/restore and entry ownership
remain in the existing input proof and are not generalized in this slice.
AH/AL, partial destination writes, other registers, segment/address overrides and
arbitrary memory forms remain excluded. A future partial destination write would
need a mask-preserving update of the other bits; neither unknown high bits nor
flags can be replaced by zero. MOVZX low16 to full32 explicitly zeroes upper bits.

Values are Unknown, Scalar(expression), or distinct typed capabilities such as the
owned local buffer and immutable name. Pointer values cannot enter scalar arithmetic,
MOVZX, comparison or exit checks. Expressions are affine bit vectors modulo 2^32
over immutable input symbols (two UTF16 units and the API result), with constants
and coefficients modulo 2^32. Register writes create new expressions; predicates
capture immutable expression snapshots, so later register writes do not change old
flags. Range knowledge belongs to symbols and paths, never to a register name.

Proposed normalized operations:

| IR | Effect |
| --- | --- |
| Copy(dst, src) / Constant(dst, imm32) | Full scalar write; flags preserved |
| LocalLoad32(dst, capability, offset) | Check all four owners and initialized bytes; flags preserved |
| ZeroExtend16(dst, src) | Project low16; prove projection or conservatively reject; flags preserved |
| Affine(dst, base, index, scale, displacement) | Read all source operands before writing destination; wrapping32; flags preserved (LEA) |
| AddImmediate/SubImmediate(dst, imm32) | Wrapping32 result; arithmetic flags updated, abstract flags may conservatively become unknown |
| Compare(src, width, immediate) | Snapshot expression and exact operand width; no register write |
| TestSelf(src,32) | ZF from zero test, CF/OF clear; SF sign, AF unknown, parity outside subset |
| Branch(condition, target) | Require supported known/refinable CF/ZF predicate; split paths |

Scalar ADD/SUB immediate flags have the usual width-limited result r: ZF iff r=0,
SF is r's sign bit, CF is unsigned carry/borrow, OF is signed overflow. CMP has SUB
flags with no destination write. TEST clears CF/OF and derives ZF/SF from its result.
MOV/LEA/MOVZX/load preserve flags. The first abstract implementation may invalidate
arithmetic predicates for ADD/SUB if it cannot represent these flags; later branch
consumption must reject rather than use a stale CMP. The frozen guard_join consumes
only comparison/test flags; arithmetic results are followed by stack cleanup/RET.
PF/AF and other branch conditions have no consumer in this scope. No flags are
silently retained across calls or unknown ESP-dependent allocation/cleanup.

The Python model represents branch-relevant CMP/TEST predicates, marks arithmetic
flags unknown, and contains a separate literal CMP CF/ZF/SF/OF calculator checked
against boundary truth tables. It does not implement a general known-bit flag engine.

## Refinement, widths and joins

API partition remains 0, 1, 2, 4..65, 66..UINT32_MAX. Only successful lengths 1/2
initialize respectively four/six bytes including UTF16 terminator. For length one,
the second word is the terminator. A DWORD at local offset zero contains both
UTF16 words, so its high half is unknown for length two. A DWORD at local offset
two is legal only with six initialized bytes; its high half is the terminator.
No assumption about sampled ASCII input initializes memory or fixes upper bits.

Unsigned CF/ZF branches refine exact modular preimages when the predicate reduces
to one symbol with unit coefficient modulo its comparison width. Split wraparound
preimages into disjoint intervals. Reject unsupported multi-symbol predicates or
truncation of a symbol whose range exceeds the width. CMP low16 of c-48 against9
therefore admits exactly48..57 over every possible UTF16 code unit. Six register
permutations and either digit order use the same transfer/refinement functions.

Affine bounds use signed representatives of coefficients/constants and mathematical
integer interval bounds, followed by modular projection. If bounds cross a modulus,
return the full unsigned range; never use a narrowed wrapping interval as a proof.
The model's known-bit mask is only the common prefix implied by these bounds.
This loses precision intentionally. MOVZX projection currently proves one character
symbol (high-word contributions cancel modulo16); other projections reject. The
first production slice can preserve this conservative domain rather than invent
arbitrary bit knowledge.

Keep joins as finite disjunctions of states with individual ownership, initialized
bytes, flags and symbol constraints. Every path must discharge every read/return
obligation. Do not union initialized bytes or length ranges across success/failure.
Existing 128-instruction /4096-transition caps remain hard rejection gates. No
widening, loop fixpoint or guessed merge is introduced. Exhausting proof resources
is unsupported input, never successful conversion.

## Ownership and effects

Register parameterization confers no new memory authority. Local loads must obtain
an existing live owner capability, validate the complete byte range and reject
return/saved/argument/metadata slots and stale or foreign owners. API admission
still verifies literal name, capacity3, current local owner and stdcall cleanup.
The call clobbers EAX/ECX/EDX and flags, then establishes the symbolic result and
conditional initialized-byte facts. Cleanup revokes local read authority; balanced
stack and original ESI are required at return. Other calls, writes, environment
mutation and pointers passed to helper routines remain excluded.

The prototype uses test-only owner tokens and manual API state construction. It
checks reads/joins/revocation, but does not prove real PE metadata, alias nonescape,
stack layout, initialization order or call signatures. Those remain production
admission obligations; model objects and booleans cannot issue certificates.

## Exact artifact scope and the other two programs

The retained SUB-553 listings/hashes are the source of the inventory, not matching
stencils or authorization by program name. The guard_join entry's additional forms
are CMP EAX,imm8 (`83 F8`), TEST EAX,EAX (`85 C0`), MOV EDX,[ESP+2]
(`8B 54 24 02`), MOV ECX,[ESP] (`8B 0C 24`), LEA EAX,[ECX+disp8]
(`8D 41`), MOVZX EAX,CX/DX (`0F B7 C1/C2`), LEA ECX,[EAX+EAX*4]
(`8D 0C 80`), LEA EAX,[EAX+ECX*2] (`8D 04 48`), ADD EAX,imm32
(`05`) and SUB EAX,imm8 (`83 E8`). Existing name/API/local allocation/cleanup,
short branches and RET remain required. Normalize these and existing equivalent
forms through the same parameterized operations; do not add a whole-graph byte
stencil, special result calculator, or source/hash-dependent acceptance.

`squares` is a deliberate limit: later IMUL of two unknown values is nonlinear and
cannot be represented by this affine domain. A future nonlinear-range/flag design
is required. `helper` is also outside this slice: entry follows an earlier helper
and padding; a backward direct call is not itself a cycle, but pointer argument
lifetime, callee reads, call contexts and distinct cleanup ownership need proof.
Merely relaxing entry placement or ignoring INT3 bytes would not establish this.
No prototype success is claimed for either program.

## Evidence and implementation gates

Eight new Python test functions, independent of production imports, cover:
12 register-assignment/digit-order combinations over full symbolic ranges; two
length-guard orders across five API classes and three length registers; all65,536
16-bit values against the independent ASCII interval; known bits/projection and
partial-write rejection; predicate snapshots and literal flag truth tables;
wrong-owner, stale-owner and failed-path joins; wraparound/noninvertible predicate
rejection; invalid scalar values/unknown registers. These counts describe checks
inside eight model tests, not eight executable programs or new Windows comparisons.

The decimal trace derives10*c0+c1-528, bounds0..99; the original profile's leading-zero
intermediate -24 wraps to FFFFFFE8 and still produces7 for07. Expected ranges and
literal flags are independently specified. Model permutation tests show semantic
reuse without proving a decoder/emitter simulation theorem or complete graph binding.
The existing unchanged-artifact CI still checks original input translation and all
three diversity rejections. Run `python3 -m unittest discover -s research/input/scalar -v`.

After medium contract review, a bounded implementation must:

1. Normalize exact decoded operands/widths into the shared IR and preserve the
   existing checked metadata/API/ownership admission boundary.
2. Use the same scalar transfer/refinement rules for original and guard_join;
   explicitly check source-before-destination aliasing and flags snapshots.
3. Demonstrate actual unchanged guard_join PE -> Rust -> ELF matches Windows for
   all17 frozen vectors, with identical generated Rust across hosts/environments,
   plus independent register/guard permutations and unsafe production negatives.
4. Preserve original input and all13 prior compiler programs,102 authored pairs,
   18 launch checks and four older held-out rejections. Squares/helper still reject.
5. Reject any unresolved projection, flag, owner, path, effect or resource proof.
   Return for medium production review before standing-authorized merge.

No architecture blocker is hidden: automatic instruction/IR correctness, emission
simulation, complete production ownership integration and real guard_join translation
are still unimplemented. This design makes that next slice concrete; it does not
claim broad memory, ordinary CRT, XP/7, IMUL or helper support. Existing procfs,
stable initial environment, encoding/resource and valid-stack/no-fault assumptions
and four unresolved historical timeout causes remain.

## Primary contract provenance

Independent implementation under MIT OR Apache-2.0. Instruction semantics use Intel's
[Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
Volume2 entries MOV/MOVZX, LEA, ADD/SUB/CMP/TEST and Jcc, with Volume1 register/flag
rules. [GetEnvironmentVariableW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew)
specifies return lengths and insufficient-buffer behavior. The
[Microsoft x86 calling convention](https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions)
specifies volatile registers and preservation. Prior local/stack contracts supply
conditional ownership assumptions. No Wine/proprietary implementation source is
imported, and no clean-room process is claimed.
