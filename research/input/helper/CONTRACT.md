# SUB-558 helper borrow and call-context contract

The frozen helper PE has entry RVA1040, an earlier helper at1000..103a and five
INT3 bytes at103b..103f. The direct CALL at1083 targets1000 and returns to1088.
Current production rejection (`complete code extent`) correctly protects several
unimplemented semantics. A backward address is not itself recursion: the proposed
internal call graph must be acyclic, with bounded contexts and protected returns.
This document and Python prototype grant no production admission.

## Values, owner identity and read authority

Keep existing immutable scalar expressions and API-result path forks. A buffer
pointer is a capability `(allocation identity, generation, offset)` referencing
one live8-byte local allocation, never a numeric host pointer or scalar integer.
Capacity3 permits at most6 initialized bytes. API result1 initializes bytes0..3
(first UTF16 unit plus zero terminator), result2 bytes0..5 (two units plus zero).
Zero/oversize results grant no initialized bytes. Result/initialization facts are
paired fork states; a length guard cannot manufacture initialization.

A call may borrow a capability already readable in the caller context. The callee
receives read authority only for passed capabilities, with the same owner,
generation and initialized-byte facts. Aliases preserve identity. Copying/pushing
a capability does not transfer allocation ownership; no callee frees the owner.
No admitted internal memory operation writes through a borrow. Unknown external
calls/effects block the proof, invalidate initialization and generations; restoring
a scalar value cannot restore lost memory authority. The sole input API runs
before these helper borrows; repeat acquisition while borrowed is excluded.

For WORD MOVZX through the capability, validate both addressed bytes against the
live allocation and initialization on every path before reading. The first exact
forms are `[EDX]` and `[EDX+2]`; no arbitrary pointer arithmetic, memory write or
numeric pointer coercion. For `MOVZX EDX,WORD[EDX+2]`, capture the old EDX capability,
validate/read, then replace EDX with the zero-extended scalar. A later pointer read
from that scalar must reject. A one-character result permits a WORD terminator
read at offset2; its value is known zero, not an unconstrained second character.
The same offset DWORD requires6 initialized bytes and cannot inherit WORD authority.

## Exact stack and call transitions

Immediately after successful acquisition, the caller has local words at ESP+0/+4
and a protected entry return at+8. PUSH EAX stores the symbolic length in a caller
argument word. LEA EAX,[ESP+4] now refers to the original local base. PUSH EAX stores
the capability; CALL pushes a distinct protected internal return. The callee sees
capability atESP+4 and length atESP+8. Loads must validate the slots' argument tags
and parent frame identity, not just numeric offsets. The exact stack CMP uses the
immutable scalar length from the argument, preserving its original symbol.

RET requires the current return tag at the top and the original pre-call stack
shape beneath it, with required preserved registers restored. It pops only that
return and selects its recorded continuation. It never fabricates an EAX exit
at an internal RET. Only an entry return applies the portable process-exit gate.
The caller's first ADD ESP,8 removes exactly its two argument words. The second
ADD ESP,8 removes exactly its two local words and ends allocation lifetime.
Select cleanup mode by explicit tagged state; mixed/protected/wrong-owner slots
reject with no alternate-mode fallback. The numeric initial ESP remains unknown;
cleanup flags remain unknown until explicitly reset by supported instructions.

Internal calls execute the proven body, carrying path states and live caller
memory facts. Do not reset registers at CALL entry or invent values for caller-
clobbered registers. The first conservative return contract preserves the proven
scalar EAX result, marks other volatile registers unknown, and invalidates flags;
this can reject programs observing more internal effects. Check ESI preservation
(and forbid any unmodeled callee-saved register writes). Capabilities may not escape
through the return result or globals. Nested borrowers preserve the original
owner and parent return contexts; shared callees are analyzed separately for each
caller path. A callee refinement applies to the shared immutable input symbols
only on that returning path. Do not merge successful and failed API paths into a
single initialized state. Read summaries must be keyed by context/physical owner
or prove identical physical bindings before shared emission.

## Graph and resource proof

Start reachable decoding at the actual validated entry RVA. Include internal call
target and continuation, every conditional successor, and both returning paths.
Reject middle-of-instruction targets, overlapping decodes, out-of-section targets,
unsupported reachable instructions, indirect internal calls and recursion. Prove
acyclic call contexts independently of RVA order. Conditional branch cycles remain
excluded; no loop support is implied. Limit depth to4, tagged stack words to16,
decoded instructions to128, code extent to512 bytes and total symbolic steps to4096;
retain existing scalar expression63-occurrence/depth12 limits. Count before growing
state. The smallest implementation may reject nested/shared cases not yet proven,
but cannot admit them by reusing a context-free result.

Every executable byte must be accounted for. Proposed narrow padding rule permits
only maximal uncovered runs of 0xCC bytes unreachable from entry, calls, returns,
fallthroughs and branch targets after complete admitted graph discovery. A target
into such bytes becomes reachable INT3 and rejects. No dropping reachable unknown
code or ignoring arbitrary gap bytes. All relocations and metadata remain bound;
padding cannot hide an unbound pointer field. The Python ownership model does not
prove this decoder/graph property; independent production tests are mandatory.

Native emission should use statically resolved Rust functions for admitted blocks
and internal calls, with validated buffer access and explicit scalar state. Emit
real runtime input reads and mechanically decoded operations. Do not replace the
helper with a decimal-parser template or dispatch a PE instruction interpreter.
Emission must simulate protected return and ownership transitions without exposing
analysis tags as host pointers. No model certificate alone authorizes conversion.

## Prototype evidence and limits

Eight independently specified tests check the exact stack/cleanup trace, nested
and shared call contexts, owner/generation/lifetime failures, initialization and
WORD ranges, address capture before register overwrite, preserved returns/ESI,
path forks, cycles/depth/stack limits. Symbolic units and scalar placeholders are
ownership evidence, not executable arithmetic or a complete x86 interpreter.
The prototype call API takes graph-validated target/continuation as a precondition;
it does not establish instruction boundaries. Its `ret` scalar placeholders do not
establish exit bounds. The production scalar engine must provide those proofs.
Python constructors are test helpers; arbitrary constructed capabilities must never
be accepted from external input in a production port.

The artifact checker binds entry, padding and nine literal observed forms to the
unchanged compiler PE hash and verifies production still rejects. All17 original
Windows helper observations remain original-only. Existing15 compiler programs,
102 authored pairs and18 launch checks remain required. No new native acceptance
is claimed by this phase.

After medium review, the smallest implementation gate is private graph intake plus
bounded tagged calls, exact argument/LEA/WORD forms, read-only capabilities and
distinct cleanup. Require independent production owner/return/guard/target/cycle/
cap negatives, deterministic Rust from the same untouched PE on both hosts, actual
17 Windows/ELF input comparisons and unobserved input boundaries. Preserve all prior
comparisons and ordinary CRT rejection. General pointers, writable memory, arbitrary
recursion and broad ABI behavior remain excluded.

## Provenance and assumptions

Independently authored model under MIT OR Apache-2.0. Primary contracts are Intel
[SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
Volume2 CALL/RET/PUSH/LEA/MOV/MOVZX/CMP and Volume1 register/flags; Microsoft
[x86 ABI](https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions)
and [GetEnvironmentVariableW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew).
No Wine or proprietary implementation source is imported. Valid aligned sufficient
stack/no-fault, normal loader, unobserved actual load base, genuine procfs/stable
initial environment and prior encoding/resource restrictions persist. Windows
Server2025 is not XP/7 validation. Four historical timeout causes remain unexplained.
