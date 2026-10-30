# Original startup process-heap publication

The explicit native profile executes callback `0x40c8f0` through its original
GetProcessHeap import, TEST, store to `0x41d2c8`, SETNE AL and protected return.
Entry retains the fifteen newly initialized locks and earlier bootstrap lock,
then selects table index 7 / callback `0x40a407` and rejects its unbound body.
The intervening null initialization entry is skipped by the original table loop.
Default admission remains blocked at `0x402b00`; this is component execution.

## One canonical heap

The runtime already has a process-owned allocator in `guest_memory::Space`.
`native_process_heap` acquires an opaque handle proof for that existing object;
it allocates no second arena and consumes no supplied availability result. The
handle now explicitly contains Space's `ProcessHeap` identity as well as the
runtime anchor and existing policy. Validation checks all three and the anchor's
live mapping. This prevents a foreign-space token from passing even if its anchor
and cached runtime handle are forged to look equal in an adversarial fixture.

Repeated acquisition returns the same proof and preserves any established policy
and allocations. A fresh acquisition leaves exception/failure policy unknown:
GetProcessHeap alone does not establish HeapAlloc flags or exception behavior.
Existing allocator adapters still reject unknown required policy. The producer
also preserves the existing errno-ownership state; it does not borrow the older
observation adapter's unrelated canonical-errno side effect. LastError becomes
unknown on success. Closed/stale runtime authority rejects.

The native profile has a process heap from successful Space construction. No
claim is made that arbitrary Windows GetProcessHeap failure or resource pressure
occurs at the same time. The public primary contract is
[GetProcessHeap](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap).
The original named import/IAT and complete callback bytes are checked, and the
shared API activation enforces the no-argument ABI, saved registers and protected
return. The original store occurs after acquisition: if the destination page is
read-only, rejection preserves the acquired heap proof and leaves the cell unchanged.
An independently injected failure after acquisition preserves the same ordering.

## Cleanup and opaque bit semantics

The original cleanup callback `0x40c910` executes `AND [0x41d2c8],0; MOV AL,1; RET`.
It clears the CRT's handle cell without destroying the process-owned heap or
invalidating other legitimate handle copies. The initializer table's heap cleanup
binding now executes that original body. Other unproved cleanup effects remain
rejected.

The existing scalar engine rejected AND on opaque heap values. The new bounded
rule permits full-width AND with a fully known zero, in either operand order:
the result and logical flags follow without exposing any unknown handle bits.
The resulting scalar carries no heap authority. Nonzero masks, partial knowledge,
partial widths and stale heap tokens remain rejected. Independent tests cover
these cases and flags; unknown data is not defaulted to zero.

## Independent validation and provenance

Twelve native cases cover fresh and repeated acquisition, existing known/unknown
policy, allocation identity across acquisition, foreign and same-anchor forged
process tokens, expired initialization, changed code, read-only destination,
actual original cleanup, an injected false API result, failure after real
acquisition, closed authority and the opaque AND rule. Success asserts AL's known
mask, exact heap identity, saved registers and stack return. The false result is a
conformance input and executes the original store and AL0 path; production does
not inject it. Cleanup verifies that later allocations still use the original
canonical heap.

The unchanged input PE and generated Rust hashes are retained in
[evidence/heap-initializer.json](evidence/heap-initializer.json). The five recorded
Windows wrapper comparisons remain component evidence; there are no new heap
Windows/ELF pairs or whole-PE translations. Full startup/rcedit and general CRT
support remain unproved.

Review of `2f65eb2` confirmed the original tail-call/cleanup activation and actual
page-write mutation target. All seven guard mutants were detected locally and
the CI mutation test job succeeded. Push workflow `41086548101` succeeded. The
parallel PR workflow `41086538322` failed in `authored-windows-fixture`, job
`124169062133`, when the original imported-output `one` fixture did not terminate
within 15 seconds. Its imported launch evidence artifact is `12992091647` and
output-probe evidence artifact is `12992391390`. The fixture PE hash was
`852e4add3173b4519d319231bca7d6e240a52755e6768739032ad0dd83170916`.
No passing parallel run resolves this original-Windows timeout. Its cause and
other historical timeouts remain unresolved; gates and deadlines are unchanged.

The next bounded connection is callback `0x40a407`; inventory its actual effects
and reuse existing contracts where applicable. Sol can continue. No concrete new
architecture question requiring Astra has yet been demonstrated.

Read-only inventory of the next callback: its first CALL targets `0x408136`,
which reads initially zero cache word `0x41e00c` and reaches resolver `0x407e41`
on that path. A later call targets the `FlsAlloc` tail thunk at `0x40803c` /
IAT `0x41509c`. These dependencies have been inventoried, not executed by this
new binding. Review should reuse existing resolver/FLS contracts and account for
the now read-only cache page and callback lifetime before admitting writes.

Verified locally: 285 CRT tests, both artifact tests in reviewed replay, 76 Python
tests with one existing skip, seven detected guard mutants, ten emitted-frame
vectors, Clippy and formatting. Predecessor inventory41086538015 also completed
successfully; PR workflow41086538322 retains the original-Windows timeout failure.
New commit CI remains a separate gate.
