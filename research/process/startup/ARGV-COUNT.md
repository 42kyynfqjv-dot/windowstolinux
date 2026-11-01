# Original argument counting and checked storage arithmetic

## Connected path

Within the existing explicit native startup profile, original CALL
`0x406755 -> 0x406813` now executes the complete count-only argument parser.
The caller pushes its actual counts into original helper `0x406985`, which runs
its unsigned multiply/divide/add bounds checks. Connected execution rejects
**before original CALL `0x4069ba -> 0x407cf0`**, the calloc producer. No allocation
result is supplied. The later `0x407d50` free-wrapper effect and caller result
handling also remain unbound.

Actual narrow image bytes and the program-name pointer remain published by the
previous original instructions. Count locals now contain pointer slots including
the terminal NULL and byte storage including argument NULs. The argc/argv globals
remain zero; no argument vector has been allocated or published. This is original
instruction component execution, not complete PE conversion or rcedit support.

## Shared semantics and provenance

The parser, byte-classification wrapper and classifier are decoded from unchanged
original bytes at `0x406813`, `0x40b75b` and `0x40b70b`. Every call retains its
actual target and protected continuation. Full instruction bytes and live module
ownership are checked before execution. The classifier executes the existing
locale-view constructor, reads the actual live byte-classification table and
retains its original cleanup branch. It does not substitute a UTF-8 lead-byte
constant. Raw scalar table addresses can resolve only through canonical mapped
image storage; an existing checked heap pointer retains its allocation identity.
Unknown, expired or foreign data cannot supply pointer authority.

Original argv[0] quote handling remains distinct from later backslash/quote
rules. Parsing is byte-oriented; UTF-8 bytes are not counted as Unicode
characters. Actual stores initialize destinations, and the terminal pointer slot
is written only if the original instructions reach it. Source/output aliasing is
not assigned memcpy semantics: the original forward loads and stores execute in
order, with existing bounds and lifetime checks. A short output can retain earlier
bytes and counters when a later store rejects. No completed allocation, vector
publication or atomic failure is inferred from an internal rejection.

The new reusable `SETE/SETNE` memory form lowers to a checked one-byte store from
known ZF without changing flags or adjacent bytes. Unknown ZF rejects before the
store; stale mappings and protected tags still reject. Existing register forms
are unchanged. This is explicit guest state, not host condition-code execution.

Direct positive parser fixtures initialize the volatile ECX value as an unknown
scalar. This preserves all unknown bits. The original `push ecx` reserves a local
word; treating the fixture's default opaque saved-register token as ordinary
scratch would require erasing authority. That token remains rejected in a
separate negative case. Connected startup derives ECX through actual preceding
instructions; it does not use this fixture initialization.

Count arithmetic preserves x86 modular behavior; no unbounded mathematical
integer invariant is assumed. The parser has an explicit 32768-instruction local
budget, with separate helper budgets. Exhaustion rejects with prior effects
retained; it never returns partial counts as success. The storage helper returns
original NULL for its tested overflow branches. Divide-by-zero and actual
allocation/error/new-handler effects remain rejected, not simulated.

## Independent acceptance and limits

[Expectations](evidence/argv-count-expectations.json) were frozen before
implementation, using documented Microsoft argument rules and explicit byte
outputs. The replay checks that the Rust input/oracle vectors still match that
file. Sixteen vectors each run count-only and owned-buffer copy modes: empty
input, quoted/empty program name, whitespace, non-ASCII, even/odd backslashes,
doubled quotes and unmatched quotes. They check counts, pointer identities,
terminal NULL, exact bytes and unknown tails without publishing globals.

The component has 53 scenarios: 32 vector executions, two live-classification
mutations, successful in-place aliasing, one short-copy failure, eleven
stale/unknown/control/lifetime/changed-code failures, budget exhaustion and five
storage-boundary cases. Eighteen separate SETcc scenarios check both conditions,
known/unknown ZF, adjacent bytes, stale mappings and protected storage. These are
component tests, not newly observed Windows argument-parser outcomes.

The retained 158 Windows conversion observations remain separately hashed API
evidence. The previous five wrapper comparisons remain components; no new
whole-PE comparison is claimed. UTF-8 error-write/growth/free/errno paths,
default admission, full startup/rcedit, native close/EOF equivalence, XP/7 and
historical Windows timeout causes remain unresolved.

## Next bounded integration

Pass the existing live exception-registry and canonical process-heap authority
through the storage caller, then execute original `0x407cf0` calloc and its real
errno/failure/new-handler paths where supported. Reuse the existing checked
allocator producers. Do not provide a fixture allocation outcome or shadow errno
cell. Bind original `0x407d50` null-free branch and return before attempting the
second parser pass and actual argc/argv publication. Sol can review this change
and attempt that connection; a new ownership/exception-lifetime ambiguity would
justify a bounded Astra pass.

The next-call inventory identifies `0x407d50` as the existing free wrapper,
not a new-handler mode setter. Its original NULL argument branches directly to
return; non-NULL inputs reach HeapFree and its separate failure/errno contract.
Reuse the existing checked null-free body when connecting this call.
