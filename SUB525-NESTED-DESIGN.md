# SUB-525 nested compiler contract and implementation gates

Design/test-only; production continues rejecting nested.c at RVA1050. Source and
compiler flags remain frozen. CI40284109464 artifact12633278927 was downloaded
and its original disassembly inspected. Nested PE SHA256:
3bf69dd6774fe5dad828140840a40bdb7b8ba284a45e7d06c1272dcb61005027.
Original Windows Server2025 observation is Nested/empty stderr/exit0. Seven other
compiler programs already translate; this document adds no native equivalence claim.

## Exact observed prerequisite inventory

| RVA | Bytes | Meaning |
| --- | --- | --- |
| 1050,1054 | FF742408 | PUSH dword [ESP+8] twice |
| 1058 | E8E3FFFFFF | direct CALL1040, continuation105D |
| 105D | 83C408 | existing two-word cleanup |
| 1060 | 83F80C | existing CMP EAX,12 |
| 1063 | 7406 | forward JE106B |
| 1065,106A | B863000000 C3 | existing failure return99 |
| 106B | C744240803000000 | MOV [ESP+8],3 |
| 1073 | C74424040C000000 | MOV [ESP+4],12 |
| 107B | E9C0FFFFFF | direct tail JMP1040 |

Inner1040 has existing MOV EAX,[ESP+4], ADD EAX,[ESP+8], RET. Outer1050 is
called from1016 with continuation101B. The successful tail path returns directly
to101B; it must not return to1080 or invent an extra return word.

## Independent requirements

Intel SDM revision093 (September2026), Volume2B PUSH/MOV/RET and Volume2A
CALL/JMP/Jcc, accessed2026-10-26:
https://cdrdv2.intel.com/v1/dl/getContent/671241
https://cdrdv2.intel.com/v1/dl/getContent/671199
PUSH resolves an ESP-based source before decrementing ESP. Near CALL saves the
continuation, JMP does not; RET consumes the existing return. MOV/PUSH/transfers
preserve arithmetic flags; JE tests ZF. Microsoft x86 argument/ABI documentation:
https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions
provides right-to-left arguments, caller cleanup for cdecl, EAX results and saved
ESI obligations. Ownership restrictions below are project policy. Independent code,
MIT OR Apache-2.0; no source port or clean-room claim.

## Minimal stack policy

Represent a frame's protected Return position explicitly. Top-of-stack need not
be that Return during the two copies. Permit only zero or one current-owner Data
word above it for exact FF742408; source index is current_top-2, checked before
mutation. It must be one of the two complete immediate-caller Data arguments
below that Return. Validate Return owner/continuation, source bounds and owner,
then scalar tag and stack capacity, before appending current-owner Data(value).
Reject protected tags, foreign/ancestor ownership, Pointer and Unknown. This
scalar-only choice preserves the existing pointer provenance boundary by rejection.
It grants no numeric pointer reinterpretation or general stack access.

Concrete low-to-high words before copies: [Entry, b=5(owner0), a=7(owner0),
Return101B(owner1)]. First copy appends5(owner1); second appends7(owner1).
Those are independent values, not aliases, and source ownership stays0. CALL1040
then pushes Return105D(owner2); inner sees7 and5. Its RET plus cleanup2 restores
the outer Return to top. CMP resets cleanup's unknown flags; JE selects the tail
preparation or return99. Both successors must be checked even if one is untaken.

Admit only exact stores above, and only with the current Return at top and both
selected words within its two immediate-caller scalar arguments. Store is a bounded
borrowed write: caller ownership remains unchanged, only the Integer value changes.
Do not require restoration of cdecl argument contents; caller cleanup still owns
these words. Do require unchanged protected slots and ESI. Pointer/Unknown existing
slots reject even though hardware could overwrite them: deliberate conservative
policy. Values become b=3 and a=12, ready for the inner sum15. No stack address
escapes or writable aliases exist in this domain; future stack pointers would
require revisiting this argument.

## Calls, tail transfer, termination

Backward address order alone is not recursion. Decode direct targets with complete
code bounds and instruction-boundary/overlap checks. Assign disjoint routine
regions rooted at entry, CALL targets and proposed tail targets; reject ambiguous
shared regions, fallthrough into another routine, and non-returning continuations.
Build a routine graph with CALL and tail edges and require it acyclic; also keep
local branch CFG acyclic. Do not include RET continuation edges in that graph.
This allows entry->outer->inner even though inner precedes outer in memory.
A visited-target history per active frame provides an additional runtime/model
check; it does not replace static all-path graph validation.

Tail transfer requires a non-entry frame, Return exactly at top, two validated
caller scalar arguments, restored ESI and no local/saved words left above Return.
Reuse owner, Return, continuation, incoming-ESI snapshot and caller ownership;
update current routine/history only. It neither allocates a new frame nor pops
one early. Final inner RET checks the original ESI obligation and returns101B.
ECX/EDX and flags carry actual decoded effects; no external clobber is invented.
JE requires known ZF and preserves it; new stores/copies/transfers preserve flags.

Keep1024 decoded instructions,1024 path steps,4096 explored transitions,128 extra
words and32 nested calls. Tail edges consume path steps despite not increasing
call depth. Reject all transfer cycles, unknown targets and resource excess on
any path. Existing loader/relocation/output/terminal barriers remain mandatory.

## Prototype evidence and limits

`python3 -m unittest discover -s tools -p test_nested_stack_model.py -v` runs nine
independent test functions. Literal stack snapshots and continuations cover copy
ordering, value independence, borrowed stores, final return, protected/foreign/
pointer/unknown words, bad untaken state, ESI, flags, cycles and caps. The model
imports no production modules. Its caller supplies decoded operations; it does
not parse the PE, infer routine boundaries, compute full arithmetic flags, explore
a CFG automatically or emit native code. Acyclic graph tests use supplied graphs;
production graph recovery remains an explicit implementation gate. Tests are not
additional Windows comparisons or a proof of all x86 behavior.

## Smallest implementation after medium review

One bounded integration issue should cover these mutually required prerequisites:
exact FF742408, exact two store literals, short forward JE, direct acyclic backward
CALL and E9 tail transfer under the above frame contract. Retain old forward-call
behavior and exact restrictions; no generic stores, arbitrary offsets, recursion,
loops, general pointers or register families. First build/verify routine partition
and graph gates, then checked transitions shared by validator/emitter. Partial
stages must retain nested rejection; do not announce support after copies alone.

Require independent production byte/IR and malformed/owner/pointer/return/cycle/
limit tests, native traces for both JE outcomes and tail continuation, plus the
unchanged nested PE independent Windows/Linux conversion to identical Rust and
Nested/empty/0. Preserve seven prior compiler programs,102 authored pairs and18
mandatory launch diagnostics. No source/flag/PE surgery. Existing valid-stack,
no-fault and regular-file full-output assumptions apply. Two historical Windows
timeout causes remain unresolved; XP/7/general applications remain unvalidated.
Astra High is appropriate for graph/frame integration after medium contract review.
No external resource blocker identified. No merge/release.

## Medium contract review

Read-before-push indices and the preserved101B tail continuation match the exact
artifact. The original eight tests used literal independent stack expectations,
but protected/pointer/unknown mutations targeted only argument2. They now cover
both positions, including the second copy after ESP changes. A ninth function
checks that a valid destination beside a protected word grants no write authority.
The prototype now validates BOTH complete scalar caller arguments before either
exact store mutates a slot. This clarifies the narrow borrowed-write window and
rejects mismatched shapes atomically. Production remains unchanged/rejecting.

Ready for bounded Astra integration subject to production routine-region/acyclic
graph proof and shared checked transitions. The prototype tests supplied graphs
and explicit alternative states; it does not prove decoder graph recovery or
automatic all-path exploration. Those remain mandatory implementation gates.
