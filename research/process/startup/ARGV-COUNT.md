# Original argument counting and checked storage arithmetic

This historical checkpoint is followed by [original calloc/publication](ARGV-CALLOC.md).

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

## Verified checkpoint

Implementation `6925ae95bb32b2dfdb0aa9bbaef0f31da676cce0` passes 182 root,
334 CRT and 185 unwind Rust tests. Both ignored artifact-dependent CRT gates
were separately executed by the full replay. Python suites pass 99 startup
tests (one skip), 106 tool tests and 18 corpus tests (one skip); Clippy with
warnings denied and formatting pass. All 53 focused scenarios and 18 SETcc
scenarios pass. [Verification and source fingerprints](evidence/argv-count.json)
retain the initial test-fixture/command errors and their corrections.

The complete corrected-source replay passes. Repeated generator invocations
advance the output timestamp while preserving Rust SHA-256
`c77e8f34af9e8843f78a93b626e8f50fa247a38cf3de0fe948b04efba11b6f7a`.
The frozen local PE remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
Five retained comparisons remain wrapper components, not whole-PE execution.

All three exact-head workflows for reviewed base `e080da1` passed. The new
implementation's three workflows were still running at this evidence snapshot;
later documentation-only commits need their own exact-head status. No CI pass
is inferred from the local replay or predecessor runs.

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

The allocator connection has these concrete obligations:

- Read the canonical process heap from the original `0x41d2c8` cell; do not
  acquire a descriptor allocator's separate authority.
- The original request is `(pointer_slots * 4 + byte_storage, 1)`. A successful
  calloc must use an actual checked allocation and its actual zeroing effects.
  Existing test-only `success_after` inputs are not runtime acquisition.
- Carry the live registry/normal-call epoch into original errno acquisition,
  using the existing UCRT PTD/FLS producer on failure. Keep the distinct PTD
  layouts and current fiber identity; do not insert a shadow errno cell.
- Preserve the original allocator mode/retry branch. A supported first success
  does not establish new-handler or resource-failure equivalence.
- Execute the original NULL free branch and caller cleanup before consuming the
  result. The second parser pass and final global stores remain later gates.
