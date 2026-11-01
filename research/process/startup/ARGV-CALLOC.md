# Original calloc, owned errno and argv publication

## Connected original path

The existing explicit native startup profile now executes original storage helper
`0x406985`, calloc `0x407cf0` and the existing original `free(NULL)` body at
`0x407d50`. The caller then executes its original second parser pass at
`0x40678d`. Original stores `0x40679e` and `0x4067a4` publish the actual allocated
argv pointer and argc. The caller performs its original cleanup and returns zero.
No expected argv output or allocation outcome is supplied to this entry path.

The next rejection is **before original `0x4015a6`**, the first C initializer's
post-argv continuation. Its original stack/frame remains live. This is guarded
original instruction component execution, not a whole-PE conversion or full
startup/rcedit admission. Default admission remains blocked.

## Shared heap and failure contracts

The storage helper's actual overflow checks produce the request
`pointer_slots * 4 + byte_storage`, then original calloc supplies element size 1.
The existing HeapAlloc adapter uses the canonical process-heap value from
`0x41d2c8`, flags 8, actual checked allocation and actual zero initialization.
The Buffer capability and heap allocation identity survive return, NULL-free and
publication. No descriptor role, copied allocation, `success_after` fixture input
or guessed numeric handle is used.

Original multiplication overflow reaches original errno acquisition at
`0x407ccd`, then the original store writes 12 and returns NULL. The mode getter
at `0x4071c0` is bound to its actual instructions. The new-handler call at
`0x40c9c0` remains unbound. Native budget/resource failure is still an internal
rejection, not a fabricated Windows NULL/error result. Windows allocation-failure
and retry equivalence are not established by the successful native allocations.

Original `free(NULL)` executes its actual conditional return; even an absent heap
handle need not be inspected on that branch. Non-NULL free and its separate
HeapFree/error effects remain rejected here. A changed free body after successful
allocation leaves that actual allocation live; no rollback, publication or
successful return is synthesized.

## UCRT errno ownership

The original errno router executes the existing native registered PTD getter and
its lazy producer under the live normal-call epoch. Registry/runtime owner and
thread identity, epoch lifetime and inherited C++ chain checks precede effects.
The current UCRT FLS object is the distinct **868-byte** layout, not the 40-byte
dispatcher PTD or a ThreadData object.

A checked view binds offset 16 of the existing heap allocation. It preserves the
capability, owner and Buffer role, checks the whole UCRT layout/slot and requires
that the current FLS value publishes that exact root pointer. Binding reads the
existing scalar knowledge and does not initialize bytes. Unknown bits stay
unknown until actual guest writes establish them. Writes overlapping a bound
Buffer errno cell revalidate publication/lifetime before updating bytes or the
canonical mirror; typed pointer writes remain rejected.

The original static fallback at `0x41c130` can bind only through canonical mapped
image authority and the exact original router branch. It does not create a new
mapping or shadow errno cell. Alignment and page permissions remain checked.
Original GetLastError/SetLastError operations preserve the getter's observed
state, including unknown values; no success-zero LastError is invented.

FLS mutation invalidates cached errno authority. An allocation can remain live
as ordinary owned heap storage after losing its UCRT/errno role; that does not
restore canonical errno authority. Retagging, shifted roots, foreign fibers and
stale slots cannot bind the field.

## Independent evidence

[Requirements](evidence/argv-calloc-expectations.json) were frozen before this
implementation. Eighteen new component scenarios cover actual zeroed requests,
independent allocation identities/reentry, multiplication overflow, resource
rejection, stale heap/registry/fiber/PTD state, unknown errno contents, code
mutations, NULL/non-NULL free and completed allocation retained on later failure.
Those standalone calloc cases cannot publish argc/argv.

Thirteen field-view scenarios independently check layout/capability identity,
unknown knowledge, typed writes, stale publication, cross-thread access and
readonly mapped fallback storage. The existing 53 parser/storage scenarios and
16 frozen quoting/non-ASCII vectors remain required.

The complete native-profile entry component compares its actual published argv
pointers and UTF-8/NUL bytes to the current native process arguments. It checks
the terminal NULL, allocation extent, argc, prior program-name publication and
actual stop at `0x4015a6`. This is not an original-Windows argument-parser
observation. Retained Windows conversion API observations and five wrapper
comparisons remain separate component evidence; zero new whole-PE pairs.

[Verification](evidence/argv-calloc.json) records tests, source/input hashes and
CI independently. Full startup/rcedit/default admission, wildcard argument mode,
zero-request calloc, native resource-failure/close-EOF equivalence, broader
UTF-8 error/growth/free paths, XP/7 and historical Windows timeout causes remain
unsupported or unresolved. No formal approval, merge or release is performed.

## Next bounded gate

Continue original `0x4015a6` pops and result test, then bind actual subsequent
helper calls beginning at `0x4015ac -> 0x401bc9`. The unchanged FIRST region has
171 bytes and SHA-256
`2dd83e44be5b5a6c72f6bea4afabf1252886a6b37c7a4f092e94f5483dae6344`.
This inventory does not assert those remaining instructions executed. Preserve
registration/cleanup and fatal paths; do not substitute successful C callbacks.
Sol can review this ownership integration and inspect that next gate. Escalate
only a concrete unresolved semantic issue.
