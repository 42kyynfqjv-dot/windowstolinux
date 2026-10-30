# Original second FLS initializer and protected-cache resolver

The explicit native profile enters the original callback `0x40a407`, executes its
selector `0x408136`, the second cold resolver at `0x407e41`, and loader helper at
`0x407f0e`. Unchanged entry now reaches the actual `LoadLibraryExW` call at
`0x407f1d` / IAT `0x415074`. Its first candidate is
`api-ms-win-core-fibers-l1-1-2`, flags `0x800`, reserved handle zero, while resolving
`FlsGetValue2`. This API-set is outside the current explicit native mapping. The
call rejects before publishing a module, function or second FLS index. Prior
cookie/page/lock/heap/FLS effects remain live. This does not complete the callback.

## Shared state and original control flow

The same `CrtNativePlatform` object is passed from original startup through the
table binding; no new loader, heap, process index map or fiber registry is created.
The actual candidate module indices (1 and 19), UTF16 module names, symbol name,
cache indices and branch instructions are read from mapped image storage.

Original scalar address arguments are converted only after full-known scalar,
canonical image and complete range checks. Retired typed values cannot be silently
converted into new authority. Candidate extent/alignment/index bounds reject
unknown or excessive domains. Existing checked module/function cache bindings are
reused and revalidated for kind, owner and lifetime. Initial function-cache binding
requires no write permission; actual publication still requires the original
VirtualProtect transition and checked XCHG, neither of which is skipped.

Both resolvers remain distinct original instruction graphs because their storage,
locking and protection protocols differ. API implementation and ownership state
are shared. Imported calls validate the actual named PE import and use existing
native producers. Load flags/search, unproved export names, release, retry-string
comparison, indexed-lock and abort effects reject where their composition has not
been established. The resolver's trailing INT3 is an explicit rejecting terminal;
it cannot become a successful graph fallthrough.

The original FLS allocation/free thunks validate their complete bytes and imports,
perform the actual saved-EBP stack push/pop, and preserve the existing protected
activation across the indirect tail transfer. Allocation uses the existing native
process-owned index producer and current executable callback identity. Allocation
itself does not bind a fiber value or grant PTD storage authority. Existing fiber
leases and slot checks remain the only value authority.

## Independent component evidence

Fifteen native scenarios use the same graphs and API state. The unchanged cold
case reaches the unsupported mapping with its earlier flag/index fields intact.
A conformance copy with a known missing-function sentinel executes the original
selector's AL0 result and then actually allocates/publishes a native FLS index with
callback `0x40a100`. It then rejects at the registered PTD getter call `0x40a428`.
This supplied cache state is not evidence that unchanged entry resolved the API,
allocated a second index or initialized PTD.

Cases cover changed initializer/selector/thunk/cleanup bytes, unknown cache bits,
stale provider and missing export publication, fixed index-capacity rejection,
foreign fiber/index leases, stale slot certainty and read-only index destination.
The destination failure preserves the earlier flag write and allocated process
index while leaving its old scalar field unchanged. A controlled missing-module
result executes original LastError comparison, publishes the first module failure
sentinel, then rejects a second attempt; no function or FLS result is fabricated.
Those injected outcomes are conformance inputs, not Windows failure observations.

Cleanup with a sentinel index executes the original no-call return. Cleanup of an
allocated index reaches the actual FlsFree tail and rejects its unproved callback/
teardown effect before the original sentinel store. The index and callback owner
remain live. No callback is silently run or dropped, and no completed cleanup or
normal return is certified from that rejected operation. Expected successes assert
success explicitly; partial cases assert the exact boundary and retained effects.

## Remaining coherent gate

Before admitting cold resolution, establish Windows-version evidence for both
candidate loads and `FlsGetValue2` lookup on the declared 10.0.20348 profile. Do not
invent a successful API-set alias, missing function or Windows error to force the
fallback. KernelBase is the second candidate, not proof of the first candidate's
availability. Reuse the process-owned provider/reference contracts once evidence
justifies the mapping and result classes.

The later resolver path takes original indexed lock 14, changes the function-cache
page to writable, publishes a function or missing sentinel, restores read-only
protection, and releases the same lock. Those effects remain unbound here. Their
implementation must normalize logical table indices to actual owned object slots:
the earlier bootstrap lock occupies one native tracking slot before the fifteen
records. Do not assume logical index 14 equals native slot 14. Partial failures
must preserve references, locks, prior writes and protection transitions accurately.

Then connect original FLS allocation/cleanup and the registered PTD getter to the
same live startup exception registry and process/fiber leases. Nonnull teardown,
unsupported callback bodies and missing context stay rejected. This is a coherent
next integration gate rather than a claim that cached conformance inputs close
actual acquisition. Sol can inspect/measure the missing mapping contract; no new
architectural no-go has been demonstrated that requires Astra now.

## Review and claims

Review of `276aa41` retained canonical Space process-heap identity, unknown
allocation policy, original stores and heap-cell cleanup without heap destruction.
The earlier page-write mutation harness still targets the actual guard and requires
a failing mutant. Both predecessor Rust workflows `41089875039` and `41089864372`
succeeded at review time; startup inventory `41089864506` also succeeded.
Historical original-Windows process timeout evidence remains unresolved, including
case `one` in job `124169062133` and its retained artifacts.

New native scenarios are component evidence. The five recorded Windows wrapper
comparisons remain separate; there are no new whole-PE translations or Windows/ELF
pairs for this initializer. Default admission/full startup/rcedit remain unproved.
Source/test/artifact hashes and actual local results are recorded in
[evidence/second-fls-initializer.json](evidence/second-fls-initializer.json).

A separately authored `second_fiber_probe.c` freezes the exact two names,
FlsGetValue2 query, x86 configuration and source hash before Windows execution.
The new workflow records load/lookup errors and matching owned-reference release;
it assumes no availability result and performs no retry. This observes only
Windows system modules, not user DLLs or drivers. Fresh observations remain a
separate evidence gate until the job report is inspected.

Verified locally: 286 CRT tests, both artifact tests in the reviewed replay,
76 Python tests with one existing skip, seven detected guard mutants, ten
emitted-frame vectors, Clippy and formatting. All three predecessor workflows
completed successfully. New commit CI and the fresh Windows candidate observations
remain separate gates.

Follow-up review: the first availability report from run41094560132/job124196834719
observed both loads succeeding and FlsGetValue2 missing/error127 on20348. The report
and source hash are preserved in evidence/second-fiber-windows-20348-v1.json. It did
not establish loaded-module identity. A separate version2 observer now records the
file-handle-resolved x86 module path and hashes that exact file; the old source,
freeze and observations remain intact. No mapping is admitted from equal missing
export results alone.
