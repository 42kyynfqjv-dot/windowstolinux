# Original startup lock initialization and rollback

The explicit native profile now executes the original `MOV AL,1; RET` callback
at `0x401bd5`, the lock initialization loop at `0x40bd8e`, its API tail thunk at
`0x408079`, and the cleanup loop at `0x40bde6` where reached. Original instructions
initialize fifteen 24-byte records starting at `0x41d150` and increment the live
counter at `0x41d2b8` after each successful return. Entry retains fifteen new locks,
the earlier bootstrap lock, and count 15, then selects callback `0x40c8f0` and
rejects its unbound body. That callback's first instruction calls the original
`kernel32!GetProcessHeap` import at `0x4150f8`, stores the handle at `0x41d2c8`,
and returns its zero/nonzero result in AL. Existing heap producers are the next
connection to inspect; no new architecture blocker has yet been established.

## Executed instructions and API authority

Both loops are decoded and emitted through the existing shared IR and arithmetic,
flag, memory and protected call/return machinery. The initializer requires a known
zero counter before entry. Cleanup admits a known counter up to fifteen. Original
branches, increments, decrements and return instructions determine control flow;
there is no replacement list of expected results.

The original tail thunk executes its six-byte MOV/prolog/POP prefix in a closed
emitted graph, then validates the original indirect JMP and actual named PE import.
The same protected activation continues into the API adapter; the tail transfer
creates no extra return slot or invented guest RET. The adapter validates saved
registers, stack cleanup and argument representations before effects.

Direct original imports are bound to the existing independently implemented native
synchronization contract. A unique live callable InitializeCriticalSectionEx
provider is required. The adapter revalidates provider/export lifetime and the
original import name/IAT, then allocates a free slot in the existing fixed global
object/tracking tables. Original scalar addresses are resolved through the live
canonical process image; typed pointers must retain that exact capability and
extent. No numeric conversion revives a stale pointer or arbitrary module.

Deletion resolves the matching live object/function identity and reuses checked
native deletion. Whole object write permissions are required for both operations.
No separate allocation tracker or fixture-specific slot number is added. Capacity,
unsupported flags, stale callable state and permission errors reject explicitly;
they are not Windows allocation-failure BOOL results. The explicit fixed native
resource profile and its remaining Windows resource-equivalence limitation persist.

## Partial effects and independent failures

Fourteen native scenarios execute the original loops. A success case initializes
all fifteen objects, checks AL and saved registers, then runs the original cleanup
and requires count zero and no remaining objects/tracking. Distinct stack entry
positions exercise shared activation handling.

Independent conformance cases inject false initialization outcomes at iterations
0, 1, 7 and 14. Exact API address traces verify reverse deletion of completed
records, no deletion of the failed record, original count decrements, AL zero,
stack restoration and no remaining constructed objects. Those injected outcomes
are test boundaries, not claims of native/Windows resource exhaustion. Production
uses the existing native successful-allocation contract and never injects them.

A cleanup callback runs the actual native deletion and then reports an independent
failure. The deletion remains visible while the not-yet-executed counter decrement
remains absent: count seven and six objects survive, with no successful return.
Altered cleanup code similarly preserves seven completed initializations. Other
negatives cover changed loop/thunk bytes, initial nonzero count, retired storage,
read-only object pages, missing/stale provider lifetime, and callable authority
invalidated after the first successful initialization. Every expected success
asserts success explicitly. Failure tests cannot pass merely because a positive
execution failed unexpectedly.

The first test version incorrectly required all EAX bits to be known after an
AL-only return. It now checks the known low-byte mask and original AL semantics.
A provider-destruction attempt was correctly blocked while borrowed; the stale-
authority negative now explicitly corrupts certainty in the adversarial fixture
and verifies rejection on the next call, preserving the first count/object.

## Independent review and CI repair

Review of `ed19128` retained page-granularity checks, all-page immutable snapshot
validation, typed-read revocation, atomic permission/output commit and rejection of
live opaque-lock page changes. Six original Windows observations remain separate:
on Windows 10.0.20348 an uncommitted-page failure changed old-protection output to
1 (error 487), while null output failed with error 998. Native failure paths remain
unsupported; unchanged failure output is not assumed.

Both prior Rust CI test jobs failed at `research/process/check_memory.py`, before
its writable mutant could compile: the harness still searched for removed
`!r.permissions.write`. The mutation now targets the actual per-page destination
guard and must still cause the independent memory tests to fail. Test counts are
read from the actual source files instead of stale constants. This is a harness
repair, not a waived mutation. The original CI failures are retained at jobs
124160837592 and 124160863776. No retry is used to erase them.

The retained five Windows wrapper comparisons and all new native scenarios are
component evidence. No fresh whole-PE translation or rcedit support is claimed.
Default admission remains blocked at `0x402b00`. Historical original-Windows timeout
causes remain unresolved. Final commit CI and independent production review remain
required; the PR stays draft.

Local validation: 284 CRT tests passed; both artifact tests passed in the reviewed
replay; 76 Python tests passed with one existing skip; Clippy/format passed. Seven
guard mutants were detected and all ten emitted-frame vectors passed.
[Source/artifact/test hashes](evidence/lock-initializers.json). Predecessor inventory
run 41084175198 passed; Rust runs 41084175194 and 41084182743 failed at the retained
mutation-harness defect. New commit CI is a separate gate.
