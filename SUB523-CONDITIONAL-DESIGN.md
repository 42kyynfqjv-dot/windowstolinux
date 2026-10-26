# SUB-523 bounded conditional register design

Status: design and test-only model; production continues rejecting the frozen
compiler/structures/conditional.c artifact. No compiler source/flag/PE alteration.
Observed helper RVA1050..1064 contains the six new forms below and existing RET.
Entry already uses supported save/output/calls/checks and two-/five-word cleanup.

| Exact bytes | Proposed operation |
| --- | --- |
| 8B442408 | EAX = scalar direct-caller argument2 |
| BA01000000 | EDX = Integer1 |
| 8B4C2404 | ECX = scalar direct-caller argument1 |
| 3BC8 | flags = CMP ECX,EAX; registers preserved |
| 0F4DC2 | conditional scalar EAX = EDX if SF equals OF |
| 03C1 | scalar EAX += ECX, modulo2^32; update CF/ZF/SF/OF |

Only these exact unprefixed 32-bit linker-profile encodings are proposed, including
literal1 for EDX. No generic register indexing, alternate immediate, memory CMOV,
other addressing/register forms, partial registers or authored-profile expansion.
Existing argument2 ADD and argument1 MOV contracts are not silently broadened.

## Independent requirements and provenance

Intel SDM Volume2A, order253666-093US, September2026, CMOVcc pages3-157..160,
CMP3-161..162 and ADD entries, accessed2026-10-26:
https://cdrdv2.intel.com/v1/dl/getContent/671199 . CMP subtracts source from
destination to define flags without storing a result. CMOVGE tests SF==OF,
preserves flags and preserves the destination on false. Its source read is
unconditional; memory forms would introduce extra fault behavior and are excluded.
ADD wraps at operand width. The prototype uses wide signed arithmetic to derive
overflow; future Rust should reuse the independently tested existing flag helper.
Microsoft x86 calling conventions and preserved ESI/EDI/EBX/EBP:
https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions .
The following rejection/abstraction rules are project policy, not extra x86 rules.
No implementation code is imported from Intel/Microsoft/Wine; original code remains
MIT OR Apache-2.0. No clean-room claim is made.

## State and safety contract

Add ECX and EDX using existing Value tags with distinct unknown entry origins.
Never initialize them to zero. New argument loads require the current callee's
protected Return on top, the complete selected word within the tagged stack,
and Data ownership by the immediate caller. Require Integer values for these
new loads; Pointer/Unknown reject rather than lose provenance. EDX1 is Integer.
Existing EAX pointer operations retain their existing restrictions. No new path
creates a pointer, touches raw ESP, reads a return word or accesses general memory.

CMP requires Integer ECX/EAX; tracked flags describe ECX-EAX. Signed comparison
must account for subtraction overflow: testing SF alone is wrong at signed limits.
CMOV requires known flags AND Integer EAX/EDX, even when false or values equal.
This conservative domain rejects otherwise executable unknown/pointer selections.
True selects EDX, false retains EAX; ECX, EDX, flags and stack stay unchanged.
ADD requires Integer EAX/ECX and overwrites all four tracked flags. MOV preserves
flags, including unknown flags. Cleanup still invalidates flags. AF/PF, memory
faults and CPU capability probing are outside this slice; original machine must
support CMOV (the observed Server2025 x86 environment does). No XP hardware claim.

Internal CALL is not an external ABI summary: execute every decoded instruction
in the existing whole-program state and continue with its actual register/flag
effects. CALL itself neither clobbers nor zeros ECX/EDX, and RET must not restore
caller ECX/EDX. The separate ESI snapshot/protected return checks remain mandatory.
Verified unchanged helper bodies may preserve these volatile registers; ABI
permission to clobber does not mean that CALL hardware always destroys them.

In contrast, native support for external _write does not execute the original CRT
instructions. After a validated successful output, set EAX=count as before, flags
unknown, and ECX/EDX to fresh distinct Unknown origins. Preserve ESI and caller
stack under the existing contract. Old known volatile values cannot survive this
summary. Arbitrary external calls remain rejected. Runtime must perform exactly
the same invalidation as the validator; scalar reads then reject unless redefined.
No claim covers errno, arbitrary CRT startup or unsupported output environments.

All-path validation retains separate complete states with ECX/EDX and unknown
identities, stack owner/frame and continuations. Clone without replacing unknown
identities. Do not merge differing paths into guessed scalar/flag values; a bad
state on either successor rejects. Existing1024 decoded/executed instructions,
4096 explored transitions,128 extra words and32 calls remain unchanged. New state
fields do not authorize new loops, indirect calls or stack stores.

## Test-only evidence and its limits

Eight unittest functions in tools/test_conditional_register_model.py use literal
expected flags/results, seven signed CMP boundary rows, three ADD boundary rows,
six exact helper traces, unsupported byte forms, pointer/unknown/owner negatives,
external clobber/reload and internal effect/context separation. No production
parser, flag helper or fixture generator supplies expected arithmetic. Helper(7,5)
gives8 and helper(3,4) gives7. Entry expects9 and therefore returns99 with Branch
output. Boundary byte-level wrap tests are x86 arithmetic, not claims about signed
C overflow. Prototype decode only models these forms plus RET, not a full PE/CFG.
It does not replace production ownership/resource validation or establish native
Windows/Linux equivalence. Existing compiler/timeout gates remain unchanged.

## Smallest implementation gates after medium review

1. Add two typed state fields, exact six Ops/forms and external-call invalidation
   in the shared production validator/emitter. Keep fields lexical to each image.
2. Add literal expected IR/byte tests and full production loader/CLI negatives:
   prefixes/truncation/neighbor operands; wrong caller/protected/missing word;
   pointer/unknown compare/add/select, both CMOV outcomes, overflow, flags preserved
   through MOV/CMOV and invalidated by cleanup/_write, internal call effects and
   unknown post-external state, bad joins/untaken paths and unchanged limits.
3. Freeze independently expected true/false signed-edge native fixtures, exercise
   generated output, and preserve deterministic source/no decoder runtime.
4. Require unchanged conditional.c same hashed PE independent Windows/Linux
   conversion to byte-identical Rust and ELF Branch/empty/99. Also cover helper's
   opposite condition with independently authored machine cases; the fixed entry
   runtime short-circuits after its first mismatch, so it is insufficient alone.
5. Retain six previous compiler programs+102 authored pairs, nested rejection,
   all existing negative suites and18 mandatory original launch samples. Record
   any new timeout; two historical different-fixture waits remain unexplained.

Astra High is justified for production typed-state/call-effect integration after
medium contract review. No external blocker identified. More registers, arbitrary
immediates, general memory and nested tail-transfer/argument-store support require
separate evidence and design; no merge/release is authorized by this contract.

## Medium contract review

No semantic defect was reproduced. Literal expectations are not computed from the
model's arithmetic function; the unused arithmetic import in tests is removed.
Existing false-CMOV tests explicitly reject an invalid EDX source, so source type
checking is not conditional on selection. Pointer/unknown destination rejection
is stricter project policy, not a claim that x86 reads old EAX on a taken move.
Memory CMOV fault behavior remains excluded. Signed overflow rows cover SF!=OF
and SF==OF across the min/max boundary, and CMP operand order matches3BC8.

Two justified regression gaps are closed: explicit MOV preservation of known and
unknown flags plus internal CALL preservation, and pointer/unknown CMP/ADD operand
rejections without register/flag mutation. External invalidation now asserts fresh,
distinct origins across repeated calls. There are now10 prototype test functions,
not10 native cases;54 root functions and production behavior remain unchanged.
The prototype lacks full CFG/resource/ESI modeling, so SUB-524 must test actual
production contexts and native emission rather than count this as integration.
Ready for bounded Astra High integration after this review; no new architecture
question identified. Existing timeout and compatibility limits still apply.
