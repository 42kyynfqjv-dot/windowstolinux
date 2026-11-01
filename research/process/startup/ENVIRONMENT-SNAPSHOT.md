# Controlled process environment snapshots

This page records the ef59eb6 acquisition checkpoint. The subsequent original
scanner and current boundary are documented in [ENVIRONMENT-SCAN.md](ENVIRONMENT-SCAN.md).

The selected `w2l-controlled-environment-v1` launch profile defines a process
environment from caller-declared entries. It **never reads the host environment**.
Original GetEnvironmentStringsW now allocates a separate immutable guest block
from that process state, returns its typed pointer and executes the original
pointer move, null test and pushes. Startup reaches CALL0x40b980→0x40b92f, before
its original UTF16 scanning helper. No narrow environment table is published.

## Ownership and layout

The declaration is process/arena owned and immutable for this scope. Each get
creates distinct mapped storage, independent of earlier blocks and heap objects.
The block is UTF16LE entries `name=value\0` plus the final NUL; empty environment
has two UTF16 NULs. Values preserve Unicode, including surrogate pairs and empty
strings. ASCII names are ordered case-insensitively; duplicate names differing
only in ASCII case reject. Non-ASCII names/collation, hidden drive entries,
embedded NULs and mutation APIs remain unsupported. No entry is silently dropped.

The bounded domain allows at most256 entries/32767 UTF16 units and16 live
snapshots. Metadata, mapping, capacity and address failures reject before
publishing a block or fabricating a Windows NULL/error code. These are supported
resource bounds, not a claim of Windows out-of-memory equivalence.

ProcessData storage is read-only at both typed and memory layers. It cannot be
retired as a temporary region or released through CRT heap free. The matching
FreeEnvironmentStringsW success contract accepts only the exact live acquired
root with the original capability/process identity. Interior/narrowed/foreign,
stale and repeated frees reject. Releasing a block expires its read facts and
aliases; other snapshots and declaration remain intact. Returned BOOL is known
nonzero symbolically; no undocumented numeric success value is invented.
Get/free success LastError becomes unknown, consistent with the documented
contract's lack of a preservation guarantee. Observed seed preservation is not
promoted to a universal guarantee. Valid-free failure and acquisition NULL/error
outcomes are unmeasured and explicitly excluded. No original free instruction
has executed on the newly extended startup path yet.

## Independent Windows evidence and tests

[Retained metadata](evidence/environment-windows-15442b7.json) and
[raw redacted rows](evidence/environment-windows-15442b7.jsonl) come from run
41360553403, artifact13105235411, head15442b7. MSVC14.44 PE32 /W4 /WX /O2 /MT
probe children receive only fixed synthetic environments or an empty environment.
The probe never prints entries, unknown names/values or worker environment.
It verifies known Unicode/empty values internally and reports counts/units,
snapshot independence/stability and successful frees. Source, executable and
raw output hashes are verified. Both cases pass; no failed-API/XP7 or whole-PE
claim follows. The primary GetEnvironmentStringsW/FreeEnvironmentStringsW
contracts specify process block, read-only treatment and matching release.
Primary source URL/hashes are retained with the final evidence record.

Five resource/lifetime cases, eight declaration/mapping failure cases and ten
get/free ABI cases cover exact UTF16 bytes, empty layout, duplicate declarations,
case collisions, stale/cross-process/interior pointers, heap-free rejection,
read-fact expiry, independent snapshots, failure atomicity, stack/return identity
and replay. Seven original-artifact cases cover code/import-byte mutation,
missing declaration, expired initialization, foreign process ownership and
protected returns. Inputs are synthetic; body/component tests remain separate
from ordinary translated-program evidence.

Review of50d4f66 found no additional boolean/query/lifetime defect. Its local
pending replay completed but contains the later snapshot method, and its emitted
hash differs from the recorded50d4 canonical. That mixed-source run is not
pinned-head evidence. The isolated CI runs are authoritative for that head:
push41359554170 passed; PR41359557511 failed authored-windows-fixture job125006824119,
original imported `changed` fixture timed out15seconds. Launch artifact13104642897
is retained. Cause remains unresolved; a passing run does not erase this failure.
Inventory41359554028 remained pending at the review read.

## Next connected scope

Lift original UTF16 scanner0x40b92f against the live snapshot extent, preserving
count units, double-NUL handling and alias lifetime. Then reuse original
conversion0x40b8c5 and establish allocation/copy/free ordering before environment
table publication. No host propagation, unsupported free success, resource-error
code or full startup/rcedit/default support is implied. Historical original
Windows timeout causes remain unresolved.

Local validation passes348 CRT tests (two artifact-dependent gates handled
separately), seven original artifact cases and the canonical controlled-entry
path,110 Python tests with one skip, Clippy warnings denied and formatting.
The152-case stack gate retains512KiB plus64KiB environment padding. New emitted
Rust SHA256bdd8aaecb9abbd390e579bc15cc033f87f66d359e0aca683957a4a55045c9038.
[Final evidence](evidence/environment-snapshot.json) records exact source hashes
and limitations. Final-head workflow/replay completion remains a separate gate.
