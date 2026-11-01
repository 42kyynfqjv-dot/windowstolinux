# Original post-allocation stores and bounded REP copies

The explicit native entry executes the original caller from `0x40b289`:
it stores the fresh allocation pointer locally, pops the size argument, tests
the allocation, prepares the source and private stack ranges, and executes
the original `REP MOVSD` instructions at `0x40b2b6` and `0x40b2c2`.
The first copies 136 words from the existing multibyte table into the owned
aligned frame; the second copies those words into the 544-byte allocation.
Only copied source knowledge becomes destination knowledge. Original
`AND [EAX],0` initializes its first word.

Execution rejects at **0x40b2c7**, before the initializer call to0x40b485.
The actual entry retains its old PTD/global reference and the initialized flag
stays zero. No new semantic locale role or reference publication is issued.
Complete unchanged caller/epilog bytes and source addresses remain bound to
the authored PE. This is connected component execution, not whole-PE support.

## Shared instruction and effect contract

Only the exact32-bit forward-copy encoding F3 A5 is added to normalized lifting.
Other REP forms, size/address/segment overrides and STD remain rejected. Decoding
does not admit the memory effect. A dedicated emitter callback must explicitly
bind it; the existing generic/default and catch-all thread hooks reject it.
The production worker proof has no new general REP admission rule.

The runtime helper requires the existing `Cdecl32Forward` ABI (DF=0), a fully
known ECX and a consumer-bound maximum. The caller's maximum is136 words;
the reusable helper also caps its declared bound. It checks each current source
read and destination write, commits one complete word, advances ESI/EDI by four
and decrements ECX. Arithmetic flags and other registers are preserved.
Forward overlap follows those sequential reads and writes. Zero count accesses
neither cursor, including a stale, numeric or opaque cursor.

Unknown source masks replace destination knowledge without inventing initialized
bytes. Existing data-pointer values preserve their allocation identity; retired
values may still be transported, but dereferencing either copied alias rejects.
A replacement allocation cannot revive their old capability. Saved-register,
return, thread-head and dispatcher control tokens cannot be cloned by this
ordinary data-copy effect. Destination saved/return protections remain enforced.

For a later bounds, permission, lifetime, protected-word or internal instruction
budget failure, completed words and their exact ESI/EDI/ECX progress remain.
The current failed word is not reported completed. These component failures do
not issue a Windows exception context, interruption receipt or resumption proof.
The helper performs no guest callback or concurrent interleaving.

The [Microsoft direction-flag contract](https://learn.microsoft.com/en-us/cpp/c-runtime-library/direction-flag?view=msvc-170)
states the CRT assumes DF clear and callees preserve or restore it. This is an
explicit admitted ABI premise; unknown Windows direction state is not cleared
or inferred by this implementation.

## Independent verification and review findings

- Seven byte-oracle cases include disjoint ranges, overlap with either
  source/destination placement, identical ranges and unaligned addresses.
- Three zero-count cases require numeric, retired and opaque cursors to remain
  untouched. Unknown/partial source bytes remain unknown at their destinations.
- Pointer aliases keep exact identity through copying and reject dereference
  after retirement/reallocation; scalar data is not promoted to pointers.
- Ten rejection cases check later source/destination bounds, control-token
  copying, preserved progress at instruction-counter exhaustion, destination
  return-slot protection, stale cursors, forged scalar addresses, unknown count
  and exceeded bound.
- Forty declared entry/getter/reference cases include actual two-copy outputs,
  unknown and partial source words through both copies, changed caller/REP/tail
  code and the preceding allocation retained on rejection.

Review of1a9c0ab verified heap initialization/identity, original failure ordering,
checked native ABI and aligned returns. All three exact-head workflows passed.
A reporting gap was found: the full replay listed allocation coverage which had
actually run in the separate aggregate suite. The replay now explicitly executes
and requires the named allocation and both REP checks before reporting coverage.
Old evidence is retained; this corrects the scope of the report, not a claim that
the earlier allocation tests failed.

The initial stale-alias test expected transport itself to fail. Inspection showed
the established model deliberately permits retired pointer values while rejecting
dereference. The corrected test checks retained identity, dead dereference and
non-revival after a new allocation. A test-only import lint failure was also fixed
without changing checks. Failure logs and hashes are retained in the evidence.

## Next connected gate from actual instructions

At0x40b2c7, initializer0x40b485 constructs a cookie-guarded frame, calls the existing
selector and traverses its actual five-entry code-page table. For the explicit
65001 path, the next API is **IsValidCodePage at0x40b4e6/IAT4150cc**. Its positive
branch writes the original UTF-8 fields and invokes helper0x40b090.
That helper itself branches on65001 and executes its original built-in table
loops. The selected UTF-8 path bypasses GetCPInfo and NLS mapping calls.
Their other code-page branches remain separate unsupported domains.

The next coherent scope should connect this actual UTF-8 initialization path,
its table/helper writes and cookie epilogs, then the original caller's result,
reference/publication and cleanup flow. Establish API behavior with independent
conformance; a supported profile must not turn unimplemented code pages into
false IsValidCodePage results. The subsequent heap-reference/publication effects
need lifetime and exclusive-lease proof; freeing remains unbound.

The target PE's default Windows ACP is still not established by the separate
UTF-8-manifest observer. Matching unchanged-binary entry-to-exit comparisons need
actual target/environment evidence; do not change its manifest/source to force
the profile. Sol can review and inventory this bounded path; escalate a precise
API/ownership ambiguity if the next integrated implementation requires it.

Full startup/rcedit/default admission, malloc errno/new-handler effects, reference
freeing, exceptional EH4 cleanup, Windows delivery/collided unwind, native close/EOF,
broader encoding/resource equivalence and XP/7 remain unproved. Historical
Windows case19 timeout and earlier failures remain unresolved.

See [evidence](evidence/locale-rep.json), [dependency map](DEPENDENCIES.md) and
[prior allocation contract](LOCALE-MALLOC.md).
