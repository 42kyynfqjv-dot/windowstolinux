# Original environment table construction and owned cleanup

Under the explicit native launch, encoding, FP and controlled-environment profiles,
the unchanged entry now reaches **0x4015ee**, after original environment construction
and temporary-buffer release. Both the empty block and three synthetic entries
reach this boundary. Full startup, application execution and default admission
remain unsupported.

## Executed original path

The caller executes CALL 0x406a36 → 0x406a65. The builder counts entries, skips its
original leading-equals entries, calls original calloc for the pointer vector and
each selected string, and calls the unchanged copy body at 0x407770. Each actual
string store completes before the original pointer-slot publication. The vector
has an independently checked final NULL slot. The original caller then publishes
the same vector to 0x41ce54 and 0x41ce48 and frees the converted temporary through
0x406a59 → 0x407d50 → HeapFree at 0x407d66. Its saved registers and protected return
are restored by the original instructions.

The vector and every selected string have distinct allocation capabilities. They
remain readable after the temporary narrow buffer and wide snapshot are retired.
The empty block publishes a NULL-only vector and releases its temporary as well.
No replacement parser supplies entries or publishes pointers.

## Checked subtraction and recomposition

Original SUB ESI,EDI at 0x4077a8 produces a scalar displacement and the original
subtraction flags. A compiler qualifier checks the decoded SUB and MOV operands;
a local relation additionally binds both original pointer operands to the live
call arguments. It does not change general pointer subtraction or convert numeric
registers into pointers.

At the original source read, 0x4077b0, that relation revalidates the runtime,
thread/fiber, protected activation and continuation/return ABI, arguments, scalar displacement and destination
cursor. It resolves the read through the original source capability and its
bounds. It never searches allocations by raw address. The subsequent original
LEA, destination store and branch still execute in order. An unknown later byte
or invalid later range preserves earlier stores. The relation is local to one
emitted invocation and cannot be returned, stored in guest memory or transferred
to another frame. Ordinary numeric cancellation still fails to authorize a read.

The generic qualifier also executes an independently authored word-load function
with different registers and both address orderings. Narrowed aliases, changed
arguments, stale/reused roots, altered displacement, wrong cursor, thread/fiber
changes and completed/replaced calls reject. Frozen original code guards continue
to reject mutated builder, copy, calloc, cleanup and free instructions.

## Native release and supported failure boundary

The native binding releases actual storage in the canonical owned heap. It checks
the live initialization and heap authority, flags, full allocation identity and
absence of conflicting record/FILE ownership, and reserves retirement metadata
before release. Only successful release creates a nonzero result fact; no exact
Windows BOOL bit pattern is fabricated. Original TEST/branch, ABI cleanup and RET
then execute. Completion is validated only after the original free body has
returned through its protected RET, not after the nested API return. Stale aliases and prior read facts expire; repeated release rejects.

This binding is used by the environment caller, table and cleanup. Other users
of the existing NULL-only wrapper retain their prior rejection boundary.

This is the declared native implementation, not a supplied successful Windows
observation. Unsupported requests, bookkeeping exhaustion or other native resource
failures reject without manufacturing Windows FALSE, LastError or errno. Existing
independent supplied-HeapFree-failure/errno tests remain separate. Windows resource
failure equivalence and exceptional cleanup are not established.

Original cleanup 0x406b4a executes per-string frees and then the vector free. A
stale second string rejects after the first string was actually released, keeping
later strings and the vector live. A rejected later allocation preserves the
first published slot and zeroed remaining slots. The failed registry epoch cannot
be reused to authorize cleanup; this test does not pretend the rejected allocation
returned a guest NULL. Copy-error termination 0x407b5f remains unsupported.

## Evidence and next review

There are 18 original-builder cases, two connected entry variants, eight original
checked-copy cases, 17 relation lifetime/operand cases, two independent word-load
cases, nine native-release cases and retained six numeric-only rejection cases.
Inputs are synthetic. Leading-equals data appears only in direct builder tests;
controlled launch declarations do not admit hidden-drive environment behavior.
No host environment is read or logged, and no new Windows/whole-PE comparison is
claimed. Five retained Windows wrapper comparisons remain component evidence.

[Recorded evidence](evidence/environment-table-owned.json). Local checks passed: 356 distinct CRT tests, the canonical entry gate, 114 Python
tests (one skip), Clippy with warnings denied, formatting and all 152 word cases
at the existing 512 KiB limit plus 64 KiB environment padding. All 555 predecessor
replay input hashes independently match its exact commit blobs. Final committed-source
replay and CI are separate gates; historical Windows timeout causes remain
unresolved.

Independent Sol review should audit the compiler qualifier against the emitted
SUB/load, relation lifetime and exact source bounds, native release preflight,
partial cleanup and all strict success/failure assertions. The next connected
implementation begins at **0x4015ee**, the original post-environment continuation
in the first C initializer. Inventory its control flow/callees before admitting
any new effect. Broader environment propagation, mutation APIs, startup/rcedit,
default profiles and exceptional/resource-failure equivalence stay unproved.
