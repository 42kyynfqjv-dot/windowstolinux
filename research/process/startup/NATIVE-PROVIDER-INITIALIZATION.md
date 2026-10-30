# Native replacement provider initialization

This change implements native construction, failure cleanup and owned references
for the existing bounded synchronization implementation. It supplies actual Rust
operations rather than an observed Windows load-success input. It does not execute
Windows DLL entry points or certify their absence/effects. The original entry
still rejects LoadLibraryExW at0x402b00/IAT0x415074.

`provider_initialize_sync` takes an owned pending construction ticket. It checks
address/export/serial bounds, publishes the process-owned native namespace,
registers the exact InitializeCriticalSectionEx descriptor and binds the existing
implemented operation. No arbitrary symbol, host function pointer or application
identity selects semantics. There are no external callbacks between these steps.
The initialization lease limits this transaction to the existing exclusive domain.

On a returned failure it removes only this attempt's published root/exports/module
or aborts its own unpublished ticket. It retains unrelated namespace entries,
previous guest writes, LastError knowledge and monotonic serials. An invalid
thread/runtime/phase is rejected before cleanup and cannot destroy another
owner's pending state. If cleanup itself fails, the operation returns failure;
it does not issue successful initialization authority. Provider String/tree
allocations still have Rust host-OOM limitations; this is not a recoverable
Windows resource-error model or an extension of the allocation-free API call.

`native_provider_acquire` accepts only a live implemented synchronization function
and issues a fresh reference from actual bounded native bookkeeping. Its typed
reference retains the implementation and source module. Release revalidates
implementation/source/actual-target lifetime and exact reference identity before
removal. Root references and replay reject. Final acquired-reference release leaves
the process-owned provider root live. Explicit provider teardown remains blocked
by acquired references, live critical sections or export-target borrows, and then
retires the root and code authority. This resident native-root policy does not
imitate unloading an arbitrary Windows DLL after its last external reference.

## Independent review and tests

Review of61662d8 retained original-source and host-version qualifications. The
failed6aa46e1 link and successful44a1bd6 observer are separate evidence. On the
pinned Windows host, ordinary authored DllMain failure returned1114 and removed
the failed module; accepting control references retained/unloaded the ordinary
DLL as measured. These outcomes do not authorize native-provider initialization
or make all Rust failures error1114. The original raw report remains unchanged.

New native tests execute successful provider construction through the actual
critical-section operation and teardown. Negative cases cover invalid addresses,
intervening namespace collision, corrupted export limit after root publication,
retained prior bytes/error state, stale tickets, cross-runtime/thread references,
root forgery, duplicate release, live-object teardown and stale code after handle
reuse. The post-publication failure retires this attempt without rolling serials
back or removing an intervening foreign module. All expected-success paths unwrap
and assert effects; failure cases assert rejection and preserved state.

## Remaining original-entry gate

This is native component implementation progress, zero new original Windows
observations or whole-PE comparisons. It does not advance entry instructions.
The closed component can replace the manual begin/publish/export/bind sequence
in a future declared native platform environment. Before binding0x402b00, require:

1. A supported API-set/version mapping to this process-owned native provider,
   including exact loader flags, identity and permitted initial-state assumptions.
2. A justified Ex resource/failure domain; spare native capacity does not prove
   original Windows success. Returned Windows failure needs its real error/object
   effects, not a Rust rejection converted into1114.
3. The original loader/constructor CALL and export target certificate, with the
   actual mapped lock address/index. Registry readiness alone grants none of these.
4. Explicit rejection of unmodeled DLL attach/detach, TLS, reentrancy and exceptions.
   The DllMain FALSE/exception notification distinction remains relevant to any
   future ordinary-DLL path; this initializer runs no Windows DllMain.

Sol review should inspect transaction cleanup and native-reference authority,
including preservation of prior effects. The next bounded Astra question is the
API-set/native-platform initial-state relation, not another successful DLL probe.
Full startup/rcedit and historical Windows timeout causes remain unresolved.

Validation:275 CRT tests passed; the two artifact-dependent tests passed during
unchanged-PE replay, retaining five recorded Windows component comparisons.
Fourteen focused provider tests,75 Python tests (one existing skip), Clippy and
formatting passed. Exact hashes and scope are in
[evidence/native-provider-initialization.json](evidence/native-provider-initialization.json).
