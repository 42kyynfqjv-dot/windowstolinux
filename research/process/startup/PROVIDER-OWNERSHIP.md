# Process-owned native provider registry

This implements native registry construction and lifetime in the emitted CRT
runtime. It does **not** implement a Windows loader, DllMain, TLS callbacks,
InitializeCriticalSectionEx, or API-set admission. Original entry still rejects
LoadLibraryExW at `0x402b00` / IAT `0x415074`.

## Concrete transitions

`provider_begin` validates the process initialization owner, reserves a unique
identity/handle and allocates the native export-index vector with `try_reserve_exact`.
Until `provider_publish`, the pending handle cannot be acquired as a module.
Publication creates one process-owned root reference and a new module generation.
No caller-supplied success Boolean controls construction. A pending ticket can be
aborted, cannot be replayed after publication/abort, and cannot cross runtimes or
outlive its initialization phase. Ending initialization with pending construction
rejects. Publication validates namespace conflicts again, since another effect
may have occurred after preparation.

Process roots are distinct from acquired load references. Ordinary acquisition
increments the existing reference table; ordinary release cannot consume the
process root. Destruction requires no acquired references and no outstanding
export borrows from another provider. It removes the source's descriptors before
retiring its root/generation. It cannot erase unrelated earlier memory writes.
All supported rejection conditions are checked before registry publication or
teardown. Bounds are 64 providers, 64 descriptors per provider, and the existing
64-module/256-reference/256-export runtime limits. Serial overflow rejects.
Vector reservation failure is propagated; ordinary Rust map/string allocation
OOM can still terminate the process and is not modeled as a Windows load error.

These transitions initialize the **native registry**, not Windows process state.
They neither infer ERROR_MOD_NOT_FOUND nor translate a native allocation failure
into a guessed Win32 LastError. The existing independently supplied release-failure
contract still invalidates module knowledge; the new provider cannot repair that
uncertainty by destroying and recreating a supposedly equivalent live handle.

## Export target and call authority

`CrtExport` now retains both its source module and actual target module. Existing
non-forwarded observed exports set both to the same identity. New native provider
descriptors borrow a separately live provider target; the borrow is not counted
as another Windows LoadLibrary reference. Target destruction rejects until the
source descriptors retire. Dependency cycles reject because their destruction
semantics are not implemented. Every descriptor access revalidates both generations.

A published descriptor is deliberately `CrtProviderExport`, **not callable
CrtFunction authority**. Inspection found that reusing the existing callable token
would let a name/address pair pass existing FLS dispatch checks without an API
implementation. The new descriptor therefore has no callable issuer yet;
`function_identity`, typed memory transport and loader-cache exchange reject an
attempt to retag it. The old observed-export entry point also cannot bypass the
native provider publisher. An independent test uses the real `FlsGetValue` name
to ensure a plausible symbol does not manufacture authority.

The constructor accepts generic provider identities and symbolic guest addresses,
not application hashes/names or host function pointers. This is a reusable resource
and ownership prerequisite. It adds no arbitrary dynamic library execution.

## Evidence and review boundaries

The four recorded Windows observations in [api-set-observed.json](evidence/api-set-observed.json)
remain observational evidence: synchronization/FLS load and export hosts were x86
KernelBase; HeapAlloc loaded through KernelBase but exported through x86 ntdll.
This motivates separate ownership, not a universal mapping or XP/7 claim. The
Windows observer also held an export-host reference, so it did not prove final
unload semantics. The native root/borrow policy here is explicit, not inferred
from that sample.

Six independently authored native test functions cover publication, rollback,
cross-runtime/thread ownership, intervening namespace mutation, replay, root versus
load reference counts, target borrowing, dependency cycles, stale generations,
serial/capacity failure, prior-write preservation and noncallable descriptors.
A separate-source/target failure case proves that a still-live source cannot
substitute for a target whose release effects became uncertain.
No native allocator OOM or Windows initialization failure is claimed to have been
forced. Existing unchanged-PE replay retains changed-code, original-call and
prior component comparisons; it is not a new end-to-end Windows/ELF result.
See [provider-ownership-review.json](evidence/provider-ownership-review.json) for
verified counts/hashes and completed-versus-pending CI at publication.

## Next executable gate

The native namespace lifecycle is now available. The first original-entry load
still needs an evidence-backed system-provider mapping and a real native
synchronization implementation, including initialization failure/error effects
and opaque lock lifetime. Only a reviewed implementation/ABI binding may issue
callable export authority. Connect that producer to the existing checked resolver
and original constructor, retain unknown/unsupported effects as rejection, and
then address FLS allocation/publication. No successful initialized resident input
or descriptor name can substitute for this step.

Sol can independently review this ownership boundary and exact-head CI. Further
provider/export-effect integration may warrant a bounded Astra High pass. PR #45
remains draft; full formatter/startup/rcedit and historical Windows timeout causes
remain unresolved. No formal PR approval, merge, release or deployment occurred.

## Final local validation and retained failure

The final runtime passes 267 CRT tests, with two artifact-dependent tests run
separately by the successful unchanged-PE replay. That replay retains five recorded
Windows component pairs; it adds zero new Windows observations. Python ran 70 tests
with one existing skip. Strict Clippy and formatting checks passed. All three
parent 5d7c93b CI workflows completed successfully; the changed head requires new CI.

A local full-suite attempt failed when the 32G overlay filled: 27 tests reported
ENOSPC and one linker reported SIGBUS at the same time. The full log is retained
as [provider-disk-full.txt](evidence/provider-disk-full.txt). Cleanup removed only
inactive generated ELF binaries older than one hour under the task temporary build
directory, retaining source/logs/evidence, and restored 17G. The same-code rerun
passed all 267 tests. This establishes disk exhaustion for the explicit ENOSPC
failures; the precise linker SIGBUS mechanism is not independently established.
It establishes no cause for historical original-Windows timeout failures.
