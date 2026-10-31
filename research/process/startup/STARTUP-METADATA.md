# Bounded native launch metadata and shared process handles

## Frozen contract before original-entry evaluation

This slice adds an optional **`w2l-native-startup-metadata-v1`** launch ABI,
explicitly enabled in addition to the existing second-fiber profile. A native
launch through this ABI supplies no Windows CRT serialized inheritance block.
This is a declared native launch policy, not an observation or acquisition of
Windows GetStartupInfoW data, and does not cover a Windows parent passing CRT data.
The previous profiles continue to reject GetStartupInfoW without this opt-in.

The output is exactly the 68-byte x86 STARTUPINFOW layout. `cb` at offset 0 is 68,
`cbReserved2` at offset 50 is zero, and `lpReserved2` at offset 52 is null. All
other fields remain unknown, including standard handles. No unknown pointer or
handle gains authority. A repeat call removes stale knowledge of unknown fields.
The complete output is checked for writable live stack storage and typed aliases
before any write. The static import, stdcall argument/return discipline and actual
original caller bytes remain checked. GetStartupInfoW has no Boolean result.

The original caller's empty-inheritance branch is expected to return to callback8
and stop before the original standard-handle initializer at 0x4085e7. Actual
GetStdHandle/GetFileType producers and nonempty inherited data remain separate,
unimplemented gates; supplied component inputs are not runtime acquisition.

## Shared handle lifetime

CRT descriptor number, descriptor lock and descriptor-record identity remain
separate from process handle lifetime. Different descriptors can bind the same
handle value and share its generation. Successful close invalidates every cached
alias of that handle generation. An observed failed close preserves existing ownership. An unavailable observation
revokes alias authority because an external close may already have occurred; it
does not invent a successful guest result or roll back external effects. The close
backend does not supply LastError, so a call also invalidates prior LastError
knowledge; it never retains an unrelated old error as the close result. A reused numeric value gets a new generation and cannot revive old
pointers, descriptors or leases. Distinct duplicated handle values have independent
close lifetimes even if a backend directs them to the same underlying file.

Binding remains an explicit declared-endpoint input, not validation of an arbitrary
GetStdHandle return or acquisition of a host endpoint. Retrieval must neither create
ownership nor validate a process standard-handle table entry. Native fd 0 must not
be confused with Windows NULL. A later producer must distinguish absent/invalid
entries, handle reuse, table replacement and cached aliases.

## Requirement provenance and limits

- Microsoft GetStartupInfoW and STARTUPINFOW documentation: process creation data,
  output layout and CRT-reserved fields.
- Microsoft GetStdHandle documentation: process-table retrieval, no implicit handle
  validation, and process-wide effects when a shared handle is explicitly closed.
- Actual authored original x86 instructions at 0x408537/0x408543 determine which
  reserved fields this caller reads; this is not a claim about every CRT version.

Independent tests must assert shared/duplicated/reused handle lifetimes, failed
close ordering, exact layout/canaries, unknown fields, stale output, typed aliases,
permissions and cross-runtime initialization. No new Windows observation, actual
Windows/ELF pair, full startup/rcedit, default admission or XP/7 claim follows.


## Next executable producer scope

The next original body is 0x4085e7, called by callback8 after inheritance returns.
Its GetStdHandle selectors are -10/-11/-12; GetFileType is a separate subsequent
query. The body must retain inherited descriptor entries, original classification,
FILE stores and partial effects when a later query fails.

A native producer must acquire and retain real owned host endpoints, assign
nonzero generational guest handle identities independently of host fd numbers,
and publish them to one process table. A failed native acquisition must release
only unpublished native resources and reject without inventing Windows NULL,
INVALID_HANDLE_VALUE or error equivalence. A successful retrieval copies the table
entry and neither duplicates the underlying resource nor validates arbitrary
entries. Shared table entries require one handle lifetime; genuinely duplicated
handles have separate lifetimes. A later table replacement cannot rewrite cached
CRT references. Close and reuse must agree with the shared descriptor model.

This remains an implementation gate. No current supplied handle-array fixture or
new startup-metadata policy is evidence that those host producers ran. Sol can
implement the bounded native producer; any escalation should concern a concrete
unresolved backend/handle lifetime question rather than routine CI.

Primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getstartupinfow
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-startupinfow
- https://learn.microsoft.com/en-us/windows/console/getstdhandle
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfiletype

## Completed local validation

294 CRT tests passed, with two artifact-dependent tests omitted in the ordinary
suite and both passed by the completed artifact replay. Three new tests cover an
independent shared-handle lifetime sequence, 11 metadata-output scenarios and 10
profile/ABI scenarios. The latter include disabled/unrecognized profiles, duplicate
enabling, saved-register/return/cleanup corruption, output aliasing, ended
initialization, stale provider and wrong thread. Unknown fields and repeated output
are checked explicitly. The complete suite was rerun after the close/LastError fix.

76 Python tests ran with one existing skip; Clippy and formatting passed. A fresh
later emission advanced the artifact mtime and matched the replay Rust hash.
Five comparisons retain the recorded Windows prolog/epilog wrapper observations;
there are **zero new Windows observations, Windows/ELF pairs or whole-PE pairs**.
The new metadata and handle tests are native contract/component tests.

[Source, PE, Rust, report and log hashes](evidence/startup-metadata.json) preserve
the exact provenance. Both predecessor engineering CI and the authorization-only
head's three workflows passed. New-head CI must be read separately after push.
Historical Windows case19 timeout (run41107853543/artifact13002965454) remains
unresolved. Only regenerable Cargo incremental caches were cleared for disk space;
source and retained evidence were preserved. No merge, release or formal approval.
