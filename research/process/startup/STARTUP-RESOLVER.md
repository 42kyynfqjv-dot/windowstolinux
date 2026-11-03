# Startup resolver and FLS ownership boundary

The original entry component now executes the lock constructor's call at
`0x402c42` into the shared resolver at `0x402a53`, then the load helper at
`0x402af3`. Its first unsupported operation is **LoadLibraryExW at `0x402b00`,
IAT `0x415074`**. The original flags `0x800`, reserved null argument and selected
module-name pointer are present on the live protected call stack. No successful
load, export or lock construction is supplied on this connected entry path.
Earlier cookie, CPU-classifier and stack effects remain present at rejection.
Root activation, incoming thread chain and committed stack remain component
premises; this is not whole-PE conversion or full rcedit execution.

## Shared resolver execution

The mapped adapter uses the same decoded resolver, load helper and retry
comparator as the existing C++ path. It checks their original live bytes and
executable section permissions before each function, rather than implementing
another answer-selection routine. The mapped image supplies symbol, module-list
and name pointers; scalar addresses must resolve to the canonical image owner.
The admitted list is nonempty, at most three entries, with module indices below
three and export indices below five. These are explicit bounds on the observed
tables, not a claim that every possible resolver input is admitted.

The original code performs cache reads, module iteration, loader calls and
serialized full-word XCHG publication. Existing loader receipts still require
one matching acquisition, named export identity, live module generation and
appropriate initialization authority. Cached numeric addresses cannot become
function authority. The returned export must match the requested name even on
the cached path. The original retry comparator retains its loads and bounds.
Startup is exclusive here; concurrent cache races are not newly supported.

Fourteen independently varied mapped-resolver cases cover cold/cached success,
missing modules, missing exports, wrong symbol, stale export owner, wrong cache
kind, changed code, expired initialization, an out-of-image symbol, an out-of-
domain export index, failure after module publication and protected volatile
input rejection. A separately reproduced callback that retired code storage
previously allowed continued execution; the adapter now revalidates image and
initialization lifetime immediately after external effects, before further
original instructions. It retains the acquired module on that rejection.
Loader outcomes in these cases are explicit component
observations. Module publication survives a later export failure. They do not
establish actual Windows loader/DllMain/TLS effects.

## Process index and fiber value

`CrtFlsIndex` now owns process-local allocation identity separately from
`CrtFlsSlot`, which owns a particular fiber's value lease. Get/set and heap-PTD
allocation/view checks revalidate both lifetimes. A numerically reused index
cannot revive an old lease or cross into another runtime, including one with
identical numeric process/thread IDs.

`fls_allocation_result` records an **independently established allocation
outcome**, not a call to FlsAlloc. FLS_OUT_OF_INDEXES grants no owner. A successful
outcome records its optional main-image callback owner; permissions and image
lifetime remain checked. At most 64 indices are tracked, with explicit rejection
on budget or duplicate identity. This is a verifier resource bound, not a
Windows allocation limit. The method does not model LastError or loader effects.

The supported context remains one stationary live fiber per runtime. A null
value may be detached without callback work; a nonnull or unknown value may
not. A process index can survive that fiber's validated retirement and be used
by a subsequently bound fiber, which receives its own initial null value.
This does not introduce arbitrary fiber switching, parallel threads or hidden
values belonging to untracked fibers. Those require a wider context contract.

Explicit-input legacy bindings retain their separate component-retirement
operation. It cannot retire an index issued by the allocation-outcome path.
Allocated index retirement requires all fiber/callback effects closed; a free
failure preserves the record but revokes certainty rather than promising
failure atomicity. No heap allocation is implicitly freed. Failed setters
continue to invalidate value knowledge and errno authority.

Four mapped callback cases check executable owner identity, narrowed aliases,
data-section rejection and stale mappings. The original module-control cases
now tie their supplied allocation observation to a process index and fiber
lease before the original global slot store. The actual setter still rejects
at its explicit boundary. The module-backed bootstrap object `0x41ccc4` remains
in its original storage; it is not retagged as heap/ThreadData. Its publication
and destructor `0x4028a7` have not been implemented.

## Evidence and remaining integration

The focused connected test and process-index regression passed. The latter
checks allocation failure without publication, duplicate allocation, attempted
value reset, callback-bypassing retirement, failed setter uncertainty, cross-
fiber/process authority, stale/reused indices, uncertain free and resource
limits. Full regression/replay results and hashes are recorded in
[evidence/startup-resolver-review.json](evidence/startup-resolver-review.json).
The replay retains five previously recorded Windows component comparisons;
there are **zero new Windows pairs** and no full startup claim.

Review of `223786b` found no demonstrated defect in its closed CPU exposure or
module control. All three exact-parent workflows passed: 41035066582,
41035056834 and 41035057015. During this integration, a test used a protected
opaque value for volatile ECX, which the original resolver legitimately reuses
as local storage; that input now remains an explicit negative case while the
positive case supplies unknown scalar ECX. A strict negative test initially
expected an unknown-scalar error for an out-of-image address; the correct earlier
section-range rejection is now asserted. Non-test compilation exposed a
component-module configuration mismatch, fixed by keeping this test/replay-only
generator in that scope. A stale PTD ticket now retains the earlier slot-lifetime
diagnostic before the additional process-index check. Initial failure logs are
preserved. Historical Windows timeout causes remain unresolved.

Next executable gate: bind the requested module load and export to a justified
native API implementation while preserving acquisition, API-set resolution,
initialization side effects, failure and release lifetime. Do not pretend a
host Windows DLL was loaded or invent success from a named-export token. Then
execute the remaining constructor guard/call and actual FlsAlloc wrapper with
a checked producer. The process-index/fiber distinction is ready for that
binding; module bootstrap PTD initialization, callback execution and original
setter/free rollback still need closure. Sol can review this bounded change;
Astra High is warranted only for a concrete unresolved loader/API-set or
bootstrap-object ownership contract. No Ultra is needed.

Primary contracts, retrieved 2026-10-30:

- [FlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc): process-wide index, initially zero per-fiber values, failure sentinel.
- [FlsSetValue](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flssetvalue): current-fiber value and documented failure classes.
- [FlsFree](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsfree): process-wide retirement and callbacks for nonnull values; no automatic freeing of pointed-to blocks.

Final local validation: 260 CRT tests passed; the two artifact-dependent tests
passed in replay. Python ran 60 tests with one existing skip; strict Clippy and
format checks passed. Generated Rust SHA256: `1688063bc1f90c257d2014237e5c8257b1bd31e5f0202f0fe2cdb4b6bba8f76c`.
