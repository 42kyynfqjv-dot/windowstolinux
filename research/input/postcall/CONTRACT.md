# SUB-561 post-call predicate contract (historical design)

SUB-562 now implements this bounded starting unit; see
[composition progress](../heldout/COMPOSITION.md). Statements below describing
all eight rejections record the design checkpoint, not current admission.

Decision: add a bounded entailment stage before the existing exact single-symbol
refiner, and normalize seven additional observed byte forms into existing scalar,
argument and borrowed-WORD operations. A no-base scalar LEA needs an explicit
absent-base operand. This is a proposed production slice, not an admission change.
The independently authored Python model is test-only and grants no emission token.

## Observed evidence versus proposed proof

SUB-560 froze four sources and O1/O2 configurations before evaluation. All eight
untouched PEs still reject, with 112 original Windows observations and zero new
native pairs. `check.py` rechecks all eight artifact/source hashes and exact first
decoder diagnostics. `forms.json` independently inventories the composed O2
listing from run40410456789/artifact12692352644: all49 instructions, seven missing
forms and15 unreachable INT3 padding bytes. It binds every code byte to the same
PE; it does not decode arbitrary binaries or certify their eligibility.

The observed composed O2 rejection is CMP EAX,202 at RVA104b. The predicate engine's
inability to compare constant/multi-symbol returns is a separate source/model
finding, encountered only after decoder gaps are addressed. It is not the common
first rejection across the eight PEs. No new Windows baseline, new compiler flags
or rewritten source is introduced by this design.

| Artifact family | Observed first barrier | Later requirements / scope boundary |
|---|---|---|
| All O1 | PUSH EBP prologue | EBP frames remain excluded |
| shared O2 | LEA EAX,[ESP+8] | saved scalar ESI and offset authority remain excluded; predicate rules could later be reused |
| nested O2 | MOV EDX,EAX | pointer copy/shift, nested return/CMOV effects remain excluded |
| composed O2 | CMP EAX,imm32 | seven exact forms below plus predicate proof are the bounded target |
| larger O2 | SUB ESP,12 | allocation/capacity5 remain excluded |

## Scalar and predicate provenance

An affine value is the immutable 32-bit bit-vector expression
`c + a0*u0 + a1*u1 + a2*length (mod 2^32)`. The three symbols retain their identity
from the single acquisition. Register assignment changes a binding, not existing
expression nodes, flags snapshots or caller argument values. Scalars never carry
buffer authority. Unknown registers, partial scalar values and capabilities cannot
be coerced into affine operands. This slice leaves existing nonlinear arithmetic
and return support intact, but introduces no nonlinear predicate inversion.

Each returning path retains its expression, input ranges, initialized bytes and
live owner facts. Analyze real callee instructions with the existing protected
return/stack/ESI checks. Retain its proven EAX value and mark ECX, EDX and predicates
unknown at the conservative return boundary. This is analysis loss of information,
not a claim that RET itself clears flags or registers. Emit the actual operations.
The argument cleanup ADD ESP,8 also invalidates known flags because the numeric
initial ESP is unknown. A later supported CMP or TEST must reestablish them.

CMP captures its source expression, width and decoded immediate without changing
the source. For `83 /7`, sign-extend imm8 to the operand width first; `3D id` uses
the whole unsigned immediate bit pattern. A supported self-TEST shares CMP-zero's
CF/ZF branch semantics only; this does not admit other TEST masks or signed/overflow
consumers. MOV, MOVZX and LEA preserve the captured predicate. Arithmetic invalidates
it unless an existing separately proved transfer supplies the required flags.

Only NE (`!ZF`), BE (`CF || ZF`) and A (`!CF && !ZF`) are consumed here. After a
comparison with k, unsigned value enclosure [lo,hi] proves:

| Predicate | Always true | Always false |
|---|---|---|
| NE | k outside [lo,hi] | lo=hi=k |
| BE | hi<=k | lo>k |
| A | lo>k | hi<=k |

Otherwise the result is unknown, not false. Proven branches retain the entire
path unchanged; their impossible successor contributes no state. No new range or
initialization fact is fabricated. Unresolved affine predicates may use the
existing exact modular preimage refiner only when exactly one nonzero coefficient
is1 at the comparison width and that symbol is proven below the width's modulus.
Other unresolved predicates reject conversion. In particular, `2*x != 1` may
reject despite being mathematically true: no parity solver is claimed.

## Sound enclosure, wrapping and joins

For width16 or32, lift the affine coefficients and constant to signed32 integer
representatives. Their integer linear combination is congruent to the machine
value modulo2^width. Sum endpoint minima/maxima in checked i128 (three u32 symbols
and signed32 coefficients fit). If both endpoints lie in the same Euclidean
modulus bucket, their remainders enclose every value; otherwise use the full
unsigned domain. Endpoint *sampling* or simply masking a crossing interval is
unsound and forbidden. Comparison width is part of the predicate; 32-bit bounds
cannot be reused as 16-bit facts without modular projection.

Independent symbol intervals overapproximate missing correlations. Algebraically
identical immutable symbols may cancel, but distinct symbols are never equated.
No merged range hull may manufacture a relation, and success/error/API-failure
paths remain disjunctive. Apply branch processing separately to every incoming
path; do not combine the success interval with error202 and invent a new result.
Keep the existing4096 total symbolic-step budget,4 internal frames,16 tagged words,
128 instructions/512 code bytes and63-occurrence/depth12 nonlinear expression
caps. Check limits before growing state. The model's4096-path collection cap is
only a local interface check, not a replacement for production's global budget.

The composed callee's digit guards prove each used unit in48..57. Its one-unit
return is `u0-48` in0..9; two-unit return is `10*u0+u1-528` in0..99. Error paths
return constant202. Therefore the subsequent NE202 branch is decidable per path,
and successful LEA produces6..204. These bounds follow from operations and all
admitted UTF16 values, not the14 sampled inputs. The model enumerates eight
disjunctive callee-return paths (invalid digit intervals split at modular wrap).
It does not implement the acquisition prelude; existing API path proof must
continue rejecting uninitialized reads on missing/empty/oversize/error paths.

## Exact operand and ownership integration

No prefixes, alternative address sizes, extra registers or memory modes are
admitted merely because iced-x86 can decode them. Seven new forms from composed O2:

| RVA | Bytes / normalized operation | Required proof |
|---|---|---|
|104b|`3D id`: Compare(EAX,32,imm32)|immutable known affine scalar; CF/ZF reset|
|1056|`8D 04 45 id`: Lea(EAX,None,EAX,2,disp32)|old scalar EAX captured; absent base is zero, not old destination|
|1070|`8B 4C 24 04`: Argument(ECX,4)|current frame's tagged argument, exact protected stack shape|
|1074|`0F B7 01`: ReadWord(EAX,ECX,0)|live borrowed capability, both bytes initialized|
|1086|`0F B7 51 02`: ReadWord(EDX,ECX,2)|same owner and both addressed bytes initialized|
|108d|`83 FA ib`: Compare(EDX,32,signextend imm8)|known scalar, CF/ZF reset|
|1095|`8D 04 4A`: Lea(EAX,EDX,ECX,2,0)|both old operands scalar; wrapping32 arithmetic|

All immediates in these exact forms are decoded values, not fixed202/6/9 answers.
The complete49-instruction inventory also covers existing Allocate8, Buffer,
Push, Name/import call, Test/Compare, forward NE/BE/A, Mov-immediate, Cleanup8,
Ret, BufferAt4, direct Call, SubEAX/SubEDX, CompareArgument8 and LEA ECX,[EAX+EAX*4].
The original graph, metadata/relocation binding and unreachable CC-padding gates
remain mandatory. Adding forms cannot suppress unknown instructions on an edge
that an observed input did not take.

`Argument(ECX,4)` can carry a typed buffer, unlike scalar `Move`. WORD reads capture
and validate the old source before writing the destination, including aliasing
source/destination cases already supported. Require the current frame's read-only
borrow, original live allocation, matching owner/generation and full initialized
range, with existing physical-load binding consistency across contexts. Loading a
capability into a different register grants no extra offset/lifetime authority.
At1092 ECX becomes a scalar *after* both WORD reads, so a later pointer use through
ECX must reject. At1056 LEA has no memory access and cannot preserve pointer type.

Borrowed memory has no admitted writes, repeated acquisition or unknown external
effects. If such an effect appears, reject; no saved scalar or return predicate
restores invalidated memory facts. Caller argument cleanup preserves its allocation;
local cleanup ends lifetime. The existing tag proof selects the mode explicitly,
rejecting mixed/protected slots. A branch result never overrides these obligations.

## Evidence and limitations of the prototype

Eleven new test functions use literal expectations and separate concrete modular
arithmetic/CF/ZF truth tables. They cover constants, both widths, signed coefficient
enclosures, full small-domain enumeration, exact preimage partition, wrap/correlation
unknowns, snapshot/register permutations/guard order, return clobbers, flag reset,
WORD source overwrite, wrong owner/generation/initialization/lifetime, disjunctive
joins, the all-domain callee trace and malformed/resource boundaries. Iterations
inside a test are not additional test functions or Windows/native comparisons.

The model is independently authored Python, without production/generator imports.
Its `returned`/`cleanup` methods assume the existing production graph, stack tags
and saved-register checks have already passed. `returned` models return to the
owning root (no active borrower); production must restore an actual enclosing
frame for nested returns. Test constructors can create capabilities; production
must never accept those as public certificates. The model is affine-only, is not
a PE interpreter and neither proves arbitrary call stacks nor emits native code.

The binding checker runs after the existing Windows measurement and on Linux's
same downloaded artifacts. Its deterministic report includes each PE hash and
the literal inventory hash. Existing112 original scenarios remain original-only;
the existing16 compiler programs,51 runtime-input pairs,102 authored comparisons
and18 launch checks are preserved. Four historical Windows timeout causes remain
unexplained; retries or relaxed thresholds are not evidence of a fix.

## Reviewed implementation gate

After medium contract review, a bounded Astra implementation can add the seven
exact forms, an explicit optional LEA base, and affine predicate entailment before
the existing refiner. It must preserve existing nonlinear return behavior and all
capability/graph/tag checks. Required tests include independent decoder/IR results,
wrong prefix/register/SIB/address/truncation rejection, immediate sign extension,
no-base nonzero-EAX overwrite, wrap/width/unknown predicates and post-call volatile
uses. Exercise production paths with guard-order/register changes, mixed/protected
cleanup, stale/wrong owner and incomplete WORD reads, including alternate paths.

Acceptance requires the untouched frozen composed O2 PE on Windows and Linux,
matching hashes and identical deterministic generated Rust across converter hosts
and environments, and actual stdout/stderr/exit agreement for all14 frozen inputs
plus independent unobserved boundaries. Keep the other seven rejections explicit
unless separately proved in a later issue. Never relax proof to obtain acceptance;
report any additional prerequisite exposed by integration. The ordinary CRT path
remains blocked. No general stack/pointer/capacity/loop/API expansion is implied.

## Primary contracts and provenance

Independent MIT OR Apache-2.0 implementation; no Wine or proprietary source port.
The [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
Volume2 entries CMP, TEST, Jcc, LEA, MOV, MOVZX, CALL and RET, defines the byte-form
and flag behavior. The range abstraction and conservative clobber policy above
are this project's design decisions, not promises made by the ISA.
Reviewed Volume2 order325383-093US (September2026), CMP3-161/162,
LEA3-547/548 and MOVZX4-130/131; official download
`https://cdrdv2.intel.com/v1/dl/getContent/671110`, SHA256
`d137a7887787bbb06c1a8b8bafd51958d8d2e16b4dff987a03226c845cca1516`.
The manual itself is not vendored or relicensed.
Microsoft's [x86 argument conventions](https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions)
specify EAX scalar return, stack arguments and preserved register obligations.
[GetEnvironmentVariableW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew)
defines success length and undefined undersized-buffer contents; existing private
acquisition restrictions supply the narrower cross-platform domain.

Valid sufficient stack/no fault, normal loader and relocation provenance, genuine
procfs/stable initial environment, existing encoding/resource restrictions and
unobserved actual load base of these input artifacts remain explicit assumptions.
Windows Server2025 measurements do not validate Windows XP/7 or ordinary apps.
