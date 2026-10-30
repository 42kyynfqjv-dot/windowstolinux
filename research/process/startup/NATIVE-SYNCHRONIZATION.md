# Bounded native synchronization implementation

The emitted CRT runtime now implements initialization of an owned x86 global
critical-section object. This is an experimental startup-exclusive, single-thread
component. It does not admit a complete Windows program or perform API-set loading.
The original entry remains rejected at LoadLibraryExW402b00/IAT415074.

## Contract and native effects

The primary [InitializeCriticalSectionEx contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initializecriticalsectionex)
(accessed 2026-10-30) requires caller-owned storage, a nonzero successful result,
opaque object bytes and deletion before reinitialization. The implementation
accepts only flags zero, writable aligned Module storage with a complete 24-byte
range, and a distinct index in the existing bounded global-lock table. The index
is compiler-owned bookkeeping, not an additional guest argument. Other object
roles, unsupported flags, overlap, duplicate construction and typed aliases reject.
Spin count has no scheduling effect in the admitted thread-exclusive domain;
contention and general concurrent use remain unsupported.

`native_sync_initialize` reserves actual native tracking storage, then installs
the existing checked global-lock object and makes its guest bytes unknown/opaque.
Success returns one because this construction completed, not because a test
supplied an API success value. Adjacent bytes retain their earlier values. The
existing global-lock implementation supports recursive acquisition by the owned
thread and checked reverse-order release. Cross-thread use and deleting a held
lock reject. Native deletion removes the owned object before releasing its
provider borrow. [DeleteCriticalSection](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-deletecriticalsection)
requires an unowned object and leaves later use invalid; tests enforce that
boundary. The deletion adapter is internal, not a newly bound guest export.

Supported validation failures occur before object writes. Allocation failure is
propagated as an unclosed effect, not translated into an invented Win32 error.
The BOOL-zero/GetLastError resource-failure behavior is therefore **not closed**.
No forced allocator OOM or new Windows initialization failure observation is
claimed. Rust map allocation can still abort on OOM. This limitation blocks
unconditional whole-program admission and needs an explicit resource/failure
contract before API-set integration can rely on this implementation.

## Callable authority and ABI

The specific `bind_native_sync` issuer consumes a live descriptor for the exact
InitializeCriticalSectionEx symbol and binds it to this implemented operation.
It does not promote arbitrary symbols or the legacy observed-export result.
The export retains source and actual target lifetimes. Provider destruction
rejects while its native objects live. Retired or uncertain source/target identity
cannot authorize another operation.

`native_sync_call` validates the active protected guest call, reads the three
checked arguments, clobbers volatile state and performs RET12. A corrupt protected
return rejects before construction; repeated return rejects. The symbol/address
is not a host pointer. Original caller instruction certificates and module
mapping must still bind this adapter before original entry can use it. The
existing changed-code original-call cases remain mandatory in PE replay.

## Review and evidence

Independent inspection of 8fb4634 retained pending/ready root protection,
forwarded target revalidation, strict expected-success assertions and rejection
of noncallable descriptors. Three new native tests cover real initialization,
recursive ownership, opaque/adjacent bytes, held-lock deletion, wrong thread,
stale provider, wrong symbol, observed-only symbol, foreign runtime, protected
alias, truncated range, protected return and argument cleanup. These are native
component tests; they add zero Windows API executions or PE/ELF pairs.

Counts and hashes are recorded in
[evidence/native-sync-review.json](evidence/native-sync-review.json). Disk health
was checked without deleting retained evidence; 17G remained free. Historical
Windows timeouts and the separately retained preceding disk-full/linker event
are not claimed resolved by this work.

Next: independently review this operation and its ABI; close resource-failure
and native deletion/shutdown contracts; then justify the system-provider/API-set
initial state and connect the existing original load/constructor path. No
registry-ready token alone proves these effects. The minimum API version in the
primary documentation is Vista; this work establishes no XP/7 compatibility.
PR45 stays draft, with full formatter/startup/rcedit unsupported.

Final local validation: 270 CRT tests passed; both ignored artifact tests passed
in unchanged-PE replay, retaining five recorded component comparisons. Python
ran 70 tests with one existing skip; strict Clippy and formatting passed. The
first stdcall test failed because it tried an overwrite already prohibited by
the memory guard. Its corrected negative case changes the return identity and
checks absence of effects before the valid call. Logs and hashes are retained.
