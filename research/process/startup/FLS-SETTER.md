# Original FLS setter and opaque current-fiber publication

The explicit native profile plus enabled FLS service now executes original setter
wrapper402bef, its resolver CALL402c04, guard CALL402c1a, indirect CALL402c20 and
stdcall cleanup8. The original FLS initializer completes, retaining process index0
at41c060 and publishing opaque value41ccc4 to the current stationary fiber. The
module initializer returns through its original RET. No expected result callback,
retagged PTD or copied guest allocation supplies the publication.

The next exact rejection is initializer continuation40195f (TEST AL,AL). Static
inventory shows its next success-arm CALL at401967 ->407653, but those instructions
are not yet lifted into this prefix. The prefix now rejects explicitly at its end;
it cannot return internal fragment success as a completed protected CALL. Earlier
publication, lock/count, caches and guest frame effects remain visible on rejection.
Default admission remains blocked at LoadLibraryExW402b00; this remains component
execution rather than complete unchanged-PE startup/rcedit support.

## Opaque values and authority

The documented FlsSetValue API stores PVOID bits for the calling fiber. The native
allocation marker now distinguishes actually produced indices from supplied-state
adapters. For a live native index, known scalar bits can be stored and retrieved
without becoming a pointer, PTD view, initialized-memory capability or callable
address. Retrieving41ccc4 passes the original bits but `CrtCpu::pointer` rejects it.
A separate downstream memory proof is still needed before dereferencing it.

Supplied/observed allocation adapters retain their prior restricted value rules.
Typed heap PTD views retain their allocation, slot and initialization checks. The
marker grants no permission to unknown values, protected control words, stale
indices or cross-fiber leases. Reused numeric API indices may identify the new live
allocation, as an index-based API permits; old generation-bearing leases cannot.

The enabled native service prepares its current stationary fiber during bootstrap,
with thread ownership checked, and publishes implemented FlsAlloc/FlsSetValue
exports transactionally. It neither captures Windows fiber state nor supports
arbitrary host/guest fiber switching. Values and process indices now share generic
fixed64-entry bootstrap-owned tables behind Box storage. No publication allocates
tracking nodes or enlarges runtime stack values. Unbound current-fiber authority,
stale provider/export and unsupported resource states reject before publication.

For an allocated native index, first publication either uses its checked current
fiber lease or issues a fresh lease. Null initialization can still be observed
through the existing checked bind/get path; first setter publication atomically
replaces that logical null without a guest-observable intermediate state. Success
returns nonzero and makes unspecified LastError unknown. Index FLS_OUT_OF_INDEXES
cannot be an allocated index: the native API returns zero/ERROR_INVALID_PARAMETER
87 without changing values. Other stale/unsupported indices reject this bounded
domain; they are not all mapped to Windows failure87. Windows ERROR_NO_MEMORY and
resource-failure equivalence remain open, despite native fixed storage.

Primary source, checked2026-10-30:
[FlsSetValue](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flssetvalue).
Non-null callbacks/teardown, generic fiber switching and native FlsFree are still
separate gates. The existing explicit successful-free adapter is used only by
reuse tests; no new callback execution claim follows.

## Recovery, review and independent tests

Workspace recovery found five unpublished files at HEAD ddd780e; the provider and
wrapper edits were present despite the earlier failed transport response. No reset
or duplicate replacement was used. Independent objdump inspection corrected the
unverified offsets: resolver402c04, guard402c1a/continuation402c20, indirect402c20,
and fallback402c24/IAT415064 with cleanup8. All62 original setter bytes are checked
against the unchanged PE. Fallback behavior remains explicitly rejected.

Thirteen native setter scenarios assert real success, failure and preserved state:
null initialization, opaque value retrieval without pointer authority, real fiber
replacement and stale lease rejection, numeric index reuse with fresh identity,
invalid-index failure87, wrong fiber/thread, unknown value, aliased FILE pointer,
stale/uncertain/supplied allocation, wrong cleanup, corrupted saved registers and
return identity, replay and protected argument words. The allocator-denial harness
also performs native publication/get under denied allocations. Original-entry
cases assert publication or changed-setter-code rejection with the earlier index,
callback and lock/count intact.

Adversarial review reproduced a new adapter defect: an invalid index set LastError87
before `finish_pop` rejected an OpaqueSaved argument. The pre-fix test fails against
prior LastError1114. The CPU adapter now rejects protected argument words before
any API effect; the strict post-fix test passes. The full suite also exposed two
snapshot-test compilation failures after the table substitution; fixed tables
retain Clone/Debug/equality support for those independent state comparisons. Neither
failure was hidden or reclassified as success.

[Machine-readable evidence](evidence/fls-setter.json) records hashes, tests and the
retained five recorded Windows prolog/epilog comparisons. No fresh Windows setter
observations or whole-PE pairs are claimed. All three predecessor ddd780e workflows
41067674960/41067661881/41067662045 passed, including fresh Windows confirmation of
the prior native stack repair. Historical original-Windows timeouts remain unresolved.

## Next connected scope

Lift original initializer40195f..40197d through its success/failure branch and bind
CALL401967 ->407653 only after establishing its original effect contract. Preserve
original failure cleanup4024e9 when applicable and keep process/fiber/callback
ownership live through return. Later consumers of opaque41ccc4 must establish its
actual memory role independently; no PTD retagging follows from this setter. Sol
can review and continue the bounded initializer inventory; escalate a concrete
lifetime or external-effect uncertainty rather than routine verification.

Read-only inventory of the next call:407653 pushes table bounds415fb8/416038,
then calls40c926. That original body walks16 eight-byte init/cleanup pairs,
executes non-null initializers through the guard, tests AL, and on failure calls
completed entries' non-null cleanup functions in reverse order. This is an
instruction-derived inventory, not a completed callback/effect proof. The next
cohesive gate should cover table ownership, actual callbacks and ordered rollback;
do not infer its behavior from a CRT routine name or skip failed initialization.

Validation:282 CRT tests passed; both artifact tests passed in final replay;75
Python tests passed (one existing skip); Clippy/format passed. New-head CI is a
separate gate and is not inferred from successful predecessor workflows.
