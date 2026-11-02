# Original environment conversion and snapshot release

Within the explicit controlled-environment and native UTF8 launch profiles, the
original producer0x40b966 now returns its narrow buffer. Actual instructions
execute both CALLs to0x40b8c5, the original malloc0x408730, the NULL-free wrapper,
matching FreeEnvironmentStringsW, register restoration and RET. The caller stops
at **0x406a22**, before its environment-result continuation. No environment
pointer table or complete startup/application execution is admitted.

## Shared contracts and original effects

The scanner's byte difference and shift supply a positive UTF16 unit count.
The existing original conversion wrapper executes its flags helper and real
WideCharToMultiByte import. CP_ACP0 must resolve through the checked process
command-line/codepage token to the explicitly selected65001 profile. No Windows
ACP or locale is assumed universally UTF8. Missing, stale or mismatched authority
rejects. Actual Linux entry uses its existing native command-line producer;
direct cross-host artifact tests explicitly supply a synthetic component token.

The size query reads the live immutable snapshot; it initializes no destination.
Original malloc obtains a distinct canonical heap allocation with unknown bytes.
The second original call reacquires source-read provenance and initializes only
the copied bytes. The original positive count preserves embedded entry NULs and
the final NUL. Nonempty buffers therefore retain two final NUL bytes. The empty
scanner's original fast path supplies count1, so its narrow allocation contains
one NUL byte. No extra terminator or initialized data is invented.

Original NULL-free and matching wide-snapshot release then execute. Matching
release retires only the exact acquired process block and its readable aliases;
the returned narrow allocation stays live under its original heap identity.
The producer restores its saved registers and consumes its protected return.
No environment table/global publication is inferred from returning that buffer.

Unsupported resource failures remain conversion rejection, not fabricated guest
NULL/LastError outcomes. Insufficient-capacity/unsupported conversion-error writes,
nonnull CRT free/errno and exceptional cleanup remain unbound. Their original
branches are retained and reject at missing contracts. No success callback or
exception suppression replaces them. A later code-guard failure preserves prior
copied output and leaves the wide snapshot live when release has not executed.

## Independent checks and provenance

Sixteen unchanged-artifact cases cover normal, Unicode/empty-value and empty
results; original prolog/import/scanner/conversion/malloc/free mutations; missing
ACP/declaration; stale command-line/init/process ownership; protected returns;
and real guest region-capacity exhaustion between snapshot and heap allocation.
All success cases require actual RET, exact independent UTF8 bytes, distinct
allocation identity and expired source aliases. A corrupted later NULL-free
helper must reject after copying, retaining both output and live source.

Twelve direct checked-API cases cover positive counts across embedded NULs,
empty input, query-to-copy source expiry, insufficient capacity, readonly/stack
aliases, stale destination, narrowed source bounds, invalid count values,
initialization expiry, unknown destination tails and a changed query/copy count.
Rejected copies leave fresh output unknown; a successful query grants no cached
copy authority. These native children retain the512KiB stack limit.

Existing retained Windows WideCharToMultiByte observations include positive
embedded-NUL, Unicode and invalid-surrogate/flags/capacity cases. Existing two
synthetic Windows environment observations cover layout, independence and release.
They ground the reused API contracts; **zero new Windows differential or whole-PE
pairs** are claimed by this integration. No actual host environment is read or
logged. [Evidence and hashes](evidence/environment-conversion.json).

## Replay review correction

Review reproduced two false pin qualifications in the old guard: ignored source
inputs and modified tracked inputs marked assume-unchanged could evade status.
The guard now also matches the complete included path set and normalized Git
blob identities against HEAD, without changing the index or writing Git objects.
Ignored/hidden changes cannot claim a pinned commit. Normal CRLF checkouts remain
valid. Raw source hashes must still remain unchanged throughout replay.
The actual f6cd2af manifest contained only tracked files, its replay matched its
canonical hash, and independent comparison of all551 manifest hashes against exact commit blobs
found no hidden edit in that evidence.

Next lift the original result continuation at0x406a22 and its table construction
only where allocation, pointer-vector lifetime, entry boundaries, error effects
and publication ordering are proved. Full environment propagation, default
admission, startup/rcedit, resource-failure equivalence and historical Windows
timeout causes remain unresolved. No merge or release is authorized here.

Final local checks:350 CRT passes (two artifact gates separately handled),
canonical original-entry/artifact checks,114 Python tests(one skip), all-target
Clippy warnings denied, formatting and all152 word cases at512KiB plus64KiB
environment padding pass. New pushed-head replay/CI completion is a separate gate.
