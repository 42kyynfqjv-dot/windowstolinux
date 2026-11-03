# Original FLS allocation wrapper with an explicit native service

## Connected execution and admission limits

With the existing native profile plus explicitly enabled FLS service, original
entry executes initializer402963, wrapper402b3e, resolver402a53, checked named
lookup/cache publication, original guard401bf9 and indirect CALL402b6c. The actual
native producer chooses an unused process index. Original wrapper RET and store
40296d publish that index at41c060. No supplied allocation result is used.

The next exact boundary is setter CALL402981 ->402bef. The process allocation and
its executable callback owner remain live; no fiber-value lease or sentinel/PTD
value is published. The retained mapped synchronization object/count1 remain live.
Native tests assert this state rather than accepting any rejection as success.

The optional service is enabled before entry by `enable_fls`, separate from the
existing synchronization-only profile. It constructs an owned native kernel32.dll
provider and binds only the implemented FlsAlloc export. Its declared native
namespace accepts kernel32 with optional.dll and api-ms-win-core-fibers-l1-1-1,
case-insensitively, flags0x800/reserved0. These are explicit native environment
choices grounded in the original import/name inputs and documented kernel32 API;
they are not fresh Windows API-set mapping observations or a general loader.
Synchronization-only execution rejects when this service is absent. Default
admission still stops at LoadLibraryExW402b00. Nothing is selected by an application
name/hash or expected result.

The bounded native allocator remains allocation-free after bootstrap, with64
process indices. Exhaustion rejects the component without inventing Windows
FLS_OUT_OF_INDEXES/LastError. Arbitrary Windows resource-failure equivalence remains
open. The new root and export are bootstrap operations; host OOM outside their
existing fallible contracts remains an execution limitation. No arbitrary Windows
DLL entry point is executed by preparing this native provider.

## Identity, ABI and failure ordering

The provider's construction transaction publishes its own namespace/export only
on success. Failure removes that namespace/root while preserving the earlier
synchronization provider. Duplicate enablement and stale roots reject. Actual
reference acquisition, named-export lookup and function cache use the existing
owned mechanisms. The implementation whitelist now includes the already tested
FlsAlloc native operation. Descriptors alone still cannot become callable.

The wrapper checks all59 original bytes, including its unexecuted fallback tail,
on every entry. Its original guard cell/code, ECX/ESI target identity and local
single-use receipt bind the eventual call. The native effect revalidates the exact
service function, source/export publication and target lifetime. Stdcall cleanup4
and callee-saved/protected-return checks precede allocation. Callback authority
comes from canonical executable image storage. The process index is distinct from
fiber-local values and retains its own generation/callback lifetime.

If lookup selects the missing-export arm, original ESI/EBP restoration executes.
At402b73 the wrapper rejects before the unimplemented TLS tail jump through41505c.
The closed emitter exit returns only inside a checked internal closure; its outer
wrapper requires an actual protected RET before returning to the guest caller.
It therefore cannot turn the fallback boundary into successful guest completion.
Generic indirect-JMP decoding was not widened or replaced with RET.

Independent tests cover original allocation and index store, stale service module,
incomplete export publication, mutated wrapper code and exhausted slots with prior
lock/count/cache effects retained. Three additional original-wrapper cases inject
missing or scalar targets and changed fallback bytes: fallback restores registers
without consuming the caller's protected return, no allocation occurs, and altered
full code rejects before callbacks. These injected outcomes are internal rejection
experiments, not original Windows observations. Provider tests cover failed
bootstrap rollback, duplicate enablement, exact/case-sensitive export lookup,
reference ownership, incomplete publication and stale targets. Existing callback
alias/lifetime, cross-fiber, allocator denial and native ABI cases remain mandatory.

## Reproduced Windows stack regression and repair

Predecessor a916446 CI run41064618055 failed job124092655895 at the original CRT
component step. Generated native test
`original_native_lifecycle_executes_fallback_and_interleaved_teardown` overflowed
its **Windows native** main stack;279 tests passed and one failed. Artifact
12981578280 (startup-unwind-slice, zip SHA256
ce0011dba169070fc133fa6dbac897ff310206556b2a28d0cc3792d357f0f15f)
retains the evidence. This is separate from the historical original-Windows
output-present/process-alive timeouts.

The inline64-entry FLS table increased copied runtime stack values. The unchanged
Linux lifecycle binary from that checkpoint independently aborts at a1MiB stack
limit. Moving the fixed table behind bootstrap-owned Box storage makes the same
lifecycle test pass at the same1MiB limit. The fixed capacity and allocation-free
operation tests still pass. Linux's existing lifecycle regression now runs the
binary under that explicit stack limit as well as its normal execution; failure
to set the limit is itself a failure. Windows retains its default test stack.
No timeout or stack threshold was relaxed. The old Windows failure remains failed;
new Windows CI is required to validate this repair on that host.

## Evidence and next connection

[Machine-readable evidence](evidence/fls-allocation-wrapper.json) records source,
artifact and test hashes, exact failed CI provenance and the constrained-stack
before/after experiment. Recorded wrapper comparisons remain prolog/epilog
components: no new Windows observations or whole-PE Windows/ELF pairs are claimed.

Next execute setter402bef through checked resolution and the actual service with
the original index and bootstrap value41ccc4. That address has a distinct role
from an ordinary heap PTD; do not retag it or copy memory to manufacture value
validity. Establish process slot/current fiber ownership, original failure cleanup
and callback/teardown behavior before continuing. Sol can review and implement a
bounded connection; a concrete sentinel-role or callback-lifetime uncertainty may
warrant Astra. Full startup/rcedit, Windows resource-failure equivalence and
historical timeout causes remain unresolved.

Primary API contract: [FlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc).

Validation:281 CRT tests passed; both artifact tests passed in replay;75 Python
tests passed (one existing skip); Clippy/format passed. Predecessor push41064618160
passed. Predecessor PR41064628433 failed original fixture `one` with a15-second
process-wait timeout (job124092694135, fixture SHA256
852e4add3173b4519d319231bca7d6e240a52755e6768739032ad0dd83170916).
Its cause remains unresolved. Startup inventory41064618055 retains the separate
native stack failure above. New-head Windows/full CI remains required.
