# Bounded synchronization resource contract

## Decision and admission boundary

The native operation now owns fixed storage for the existing limit of 32 global
objects and 32 simultaneously held recursive leases. This removes both former
per-call allocation sites (`native_sync` vector and `global_objects` tree), the
lease vector growth, and temporary typed-read/alias-query vectors on this path.
The limit is a checked converter domain, not a guest Windows resource limit.
Index 32, a 33rd lease, or unsupported object authority rejects without fabricating
a BOOL-zero result or changing LastError knowledge.

This establishes a native storage contract. It does **not** prove that the
original Windows call cannot fail when the native implementation has capacity.
The [primary Ex return contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex),
reviewed 2026-10-30, still permits zero with GetLastError. It supplies no complete
failure-trigger/error-code/object-poststate relation. Stronger guarantees for
other critical-section constructors cannot silently replace this contract.
The two successful Server 2022 observations do not close that relation.

Consequently the original entry still rejects LoadLibraryExW at **0x402b00**
(IAT **0x415074**). No API-set acquisition was enabled in this change. A native
successful component call cannot issue a whole-program effect certificate.

## Installation, failure ordering and lifetime

The runtime contains inline arrays before the operation begins. There is no
partially reserved vector/map state to roll back during initialization. Creating
the surrounding runtime, mapping guest memory and publishing providers still
allocate, and are outside this claim; exhaustion of the process stack/initial
runtime allocation is not modeled as a Windows API failure either.

Initialization validates phase, provider and actual target lifetime, full writable
24-byte storage, role/alignment/index, duplicate/overlapping objects and typed
aliases. It constructs the bounded view before changing bytes. Guest memory's
`forget` checks permissions and reserves its epoch increment before changing
initialization bits. After that succeeds, removal of partial-byte facts,
LastError invalidation and installation in the two checked inline slots cannot
allocate. There is no later fallible allocation to leave half an object published.
Previous objects and writes remain intact when a later object's validation fails.

Recursive acquisition validates owner, live object and capacity before advancing
the serial and publishing a lease. Deletion validates exact source function,
index and pointer, plus absence of active leases, before removing either table
entry. Removing one sparse slot cannot shift another object's identity. Retired
mapping authority rejects and retains its provider borrow; it does not silently
recover a stale object. Provider teardown remains rejected while any object
borrows its source or actual export target.

Typed loads now inspect the matching tag iterator directly. They still reject
partial-width, displaced and multiple-tag reads and perform the same pointer,
module, function, heap, dispatcher, descriptor and thread-head lifetime checks.
This is needed for the actual checked stdcall arguments and protected RET12,
not only a direct call to the initialization helper.

## Independent checks

The allocator-denial native test installs a global allocator that returns null
for every allocation/reallocation after setup and counts all attempts. It uses
all 32 object slots, reaches the 32-lease bound, tests over-limit rejection,
rejects a typed alias, deletes/reuses a sparse slot, drains all objects and runs
the actual stdcall adapter through protected RET12. It requires zero allocation
attempts and explicit expected success. The allocator is restored before test
reporting. This is native resource evidence, not a Windows OOM experiment.

A separate partial-construction test creates one live object, then rejects a
truncated second view and a read-only mapped object. It verifies prior object and
lease identity, untouched second bytes, unchanged error knowledge, stale lease
rejection after reuse, and retained ownership after mapping retirement. Existing
provider tests cover failed publication/rollback and stale source/target identity.
Existing original-code mutation cases remain required by PE component replay.

The earlier conformance report had an obsolete top-level “pending” artifact-check
sentence beside a completed cross-host result. It now distinguishes local stdout
extraction from the Linux CI job's actual downloaded-executable hash check.
The two original Windows/native traces remain successful component comparisons,
not translated PEs. Current results are in [sync-resource-review.json](evidence/sync-resource-review.json).

## Next executable gate

The next semantic decision is the admitted external resource/failure relation:
either establish a justified Ex failure contract (including LastError and object
state), or explicitly define and review a resource-sufficient compatibility domain
whose premises are enforceable. Available success observations cannot prove that
premise for arbitrary original Windows states. An invented failure code or a
supplied “success” token is not a producer. Further identical success probes add
no evidence for this decision.

Then connect the declared process-owned system-provider initial state and API-set
mapping to actual loader acquisition, preserving separate load-reference and
export-target lifetimes. Provider registry initialization alone still does not
close Windows initialization effects. Bind the original constructor's checked
CALL/target, mapped lock address and index only after those contracts hold.
Actual FLS publication and complete formatter/startup/rcedit remain unsupported.
No XP/7 support, whole-PE execution, or historical timeout diagnosis is claimed.

Local validation passed: 273 CRT tests, two artifact-dependent tests exercised by
unchanged-PE replay, 12 focused provider/resource tests, 73 Python tests (one
existing skip), Clippy and formatting. Replay retained five recorded Windows
component comparisons. The two native synchronization traces also match their
recorded Windows counterparts. An independent mutation inserting a fallible
allocation into initialization made the positive allocator-denial test fail with
its injected allocation error (exit101); the production implementation passed
with zero attempts. No failure was reclassified as a successful comparison.
