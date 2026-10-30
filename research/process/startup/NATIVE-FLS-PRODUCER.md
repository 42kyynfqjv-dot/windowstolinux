# Bounded native FLS allocation and original startup call boundary

The original entry now executes the FLS initializer at `0x402963`, including
its callback argument push, and stops at `0x402968 -> 0x402b3e`. The previously
constructed mapped lock and count1 remain live. The allocation wrapper and API
are not yet executed on this entry path; neither index nor value is published.
Default admission still rejects LoadLibraryExW at `0x402b00`.

## Actual producer, without supplied allocation outcomes

`native_fls_allocate` chooses an unused process index from the native domain
0..64 and issues a fresh allocation identity. It takes no supplied index, BOOL or
success result. A registered callback must retain the actual executable main-image
owner. Registration proves pointer/lifetime only; it does not certify callback
body execution, exception effects or teardown of non-null values.

The process index table now uses fixed 64-entry storage. Existing observation
adapters retain their independently supplied arbitrary keys and rejection rules;
physical slots do not become keys. Native allocation therefore performs no heap
allocation after runtime construction. A full table or serial exhaustion rejects
the component domain before mutation, preserving prior indices and LastError.
It does not invent `FLS_OUT_OF_INDEXES` or a Windows allocation error. Actual Windows
resource-failure equivalence remains open. A successful native operation makes
LastError unknown rather than promising an unspecified value.

Allocation does not create a current-fiber lease or publish a PTD. Existing checked
fiber binding initializes the new fiber's slot to null only under a live process
allocation. Slot ownership includes fiber and allocation generation; reused numeric
indices do not revive old leases. Non-null callback teardown remains rejected
unless separately established. The original publication value `0x41ccc4` is still
an unsupported sentinel/PTD role, not a pointer that may be retagged to fit.

The new native stdcall adapter validates active/protected return, stack identity,
callee-saved registers and cleanup4 before allocation. Callback integers may resolve
only through canonical executable image storage; unknown, non-executable, stale
or unrelated pointer authority rejects. The adapter is internal component machinery;
no unimplemented provider descriptor becomes callable through this change.

Primary behavior source, checked 2026-10-30:
[FlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc).
The documented process-wide index and fiber-local value distinction is retained.
No Windows version or numeric index-selection guarantee follows from this native
allocator policy.

## Review and independent validation

Review of dbb60a2 confirmed that saved-register validation precedes synchronization
construction; protected return and exact stdcall cleanup remain checked. Its twelve
strict profile tests remain mandatory. No further defect in that slice was found.

Ten artifact-bound native FLS cases cover actual allocation and optional callback,
null fiber initialization, cross-fiber rejection, free/reuse with stale identity,
replay, callee-saved corruption, wrong cleanup, capacity failure, serial failure,
wrong thread, non-executable/unknown callback and retired image storage. Expected
success is asserted explicitly. Failure cases preserve serial, index/value tables
and LastError. A separate changed-original-FLS-code case rejects after retaining
the earlier lock and count. It adds no FLS allocation authority.

The existing rejecting-global-allocator harness now also fills the independent
FLS table to64, rejects the next allocation, frees a middle index and reuses it
with a fresh identity while all host allocations are denied. The successful
allocation returns indices produced by the allocator, not observed inputs.

[Machine-readable evidence](evidence/native-fls-producer.json) records validation,
source/artifact hashes and retained component comparisons. Reuse tests use the existing explicit successful-free adapter; this change does
not implement native FlsFree or execute a non-null callback. No new Windows
observations or whole-PE Windows/ELF pairs are claimed.

## Exact next connection

The unchanged 59-byte wrapper `0x402b3e..0x402b78` calls resolver `0x402a53` at
`0x402b53`, using function index0, name `FlsAlloc` at `0x415d30` and module list
`[0,2]` at `0x415d28`. Its success arm executes the original guard and indirect
stdcall call with cleanup4. Its missing-export arm restores ESI/EBP and tail-jumps
through IAT `0x41505c`; this must remain an explicit TLS fallback boundary until
that separate contract is implemented. The decoder's existing bounded indexed-JMP
form is not this tail jump; do not replace it with a successful RET.

The current explicit profile implements synchronization acquisition/export only.
It does not authorize FlsAlloc by recognizing its name. Next bind these original
wrapper instructions and its kernel32/module/export path, then call the checked
producer under actual target authority. Preserve changed-code, fallback, stale
export and ABI rejection. Only after that may original store `0x41c060` and setter
`0x402981 -> 0x402bef` publish the allocated index and value. Sol can implement this
bounded wrapper work; escalate a concrete provider/fiber-lifetime uncertainty if
one arises. Full startup/rcedit, arbitrary Windows resource failures and historical
Windows timeout causes remain unresolved.

Validation: 280 CRT tests passed; both artifact tests passed in replay;75 Python
tests passed (one existing skip); Clippy/format passed. All predecessor dbb60a2
workflows41061939658/41061932319/41061932550 completed success. Changed-head CI
is a separate gate.
