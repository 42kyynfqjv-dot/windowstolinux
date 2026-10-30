# Bounded data-page protection in the original initializer

The explicit native profile executes the original callback at `0x408113`, its
`VirtualProtect` call at `0x408129`, the original `TEST`/`SETNE` and protected return.
The call makes the page containing `.fptable` at `0x41e000` read-only, writes the
first page's old protection to the original owned stack local, and preserves the
mapping's capability, bytes and aliases. The first two initializer callbacks,
all cookie stores, FLS publication and lock/count writes remain live.

The original table then selects index 3, target `0x401bd5`, where the current
body binding rejects. This target's inventoried bytes are `b0 01 c3` (`MOV AL,1;
RET`); it has not been admitted by this change. The following callback at
`0x40bd8e` loops over fifteen 24-byte lock records, calls `0x408079`, publishes
count `0x41d2b8`, and runs cleanup `0x40bde6` on a false result. This is the next
connected integration scope, using existing synchronization ownership machinery.
Sol can review this change and attempt that scope; no new hard architecture
question has yet been demonstrated there.

This is original instruction component execution under an explicit native
profile. Default admission remains blocked at `0x402b00`. There are no new
whole-PE Windows/ELF pairs or full startup/rcedit claims.

## Primary contract and declared subset

The [Microsoft VirtualProtect contract](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)
requires committed pages within one reservation, rounds the requested byte range
to all intersecting pages, returns the first page's old protection, and requires
a valid old-protection output. An uncommitted page causes failure without changing
any page permissions. Executable transitions have additional cache-coherency
requirements. Those transitions are not implemented here.

The native component's supported domain is deliberately narrower:

- Fixed 4096-byte pages; one canonical, page-aligned process-image section per
  operation. Requests spanning distinct sections/reservations reject, even when a
  larger Windows image reservation could make them valid.
- Data permissions `PAGE_NOACCESS`, `PAGE_READONLY`, and `PAGE_READWRITE` only.
  An executable source page or any requested execute/guard/cache/COW modifier
  rejects. This changes logical guest storage permissions, not host protections.
- The request itself must lie in mapped bytes. Protection covers the containing
  pages but does not make absent section-tail bytes accessible. A second mapping
  sharing an affected page rejects. Protected page tails also block future
  mapping/heap placement until the original mapping is released.
- The ABI adapter requires an owned scalar stack output outside its return and
  argument slots. An output in any target page, protected typed slot, unobserved
  context or different role rejects. Broader Win32 output alias behavior is not
  guessed. The lower memory transaction additionally supports a disjoint output
  page in the same allocation, with one coherent epoch update.
- Invalid inputs and unsupported effects reject the component before mutation;
  they do **not** return a fabricated Windows `FALSE` or `GetLastError` code.
  Success supplies a nonzero BOOL for the original caller's zero/nonzero test.
  Successful LastError preservation is not assumed.

The image mapping profile supplies data protection classes from supported PE
section characteristics. The original callback does not observe its old output
before discarding the local. Arbitrary Windows image COW classification or memory
pressure equivalence is not inferred from the new VirtualAlloc observer.

## Memory, proof and effect ordering

Each region now has a page-permission vector. All byte reads, writes, definition,
forgetting, writable checks, executable checks and typed reads consult it. A
permission change does not retire an allocation, replace its capability, copy its
contents, initialize unknown bytes or manufacture pointer authority. Existing
numeric aliases observe the same permissions. Read facts expire on a successful
protection transaction; uninitialized bytes remain uninitialized after permission
restoration.

Live opaque lock bytes are excluded over the **whole intersecting page envelope**,
including an object outside the requested bytes but inside the same page. Without
this restriction, a prototype allowed page revocation while metadata-only lock
operations still considered the object live. An independent new regression
reproduced that acceptance; the repaired adapter rejects before output or
permission mutation. Cases cover a global lock at the target, a neighboring
same-page global lock and a FILE lock. Broader lock behavior on protected storage
requires a separately supported contract.

The transaction preflights target identity/range, page overlaps, requested
protection, output identity/range/permission/alias and both epoch budgets. It then
changes page metadata and writes the first page's old protection without a
remaining allocation or fallible operation. Thus rejection leaves permissions,
output bytes, initialization and read epochs unchanged. Prior guest instructions'
effects remain intact. The stdcall adapter checks active return authority, saved
registers, argument representations, output aliasing and stack permissions before
the effect, then uses shared protected return cleanup.

Review found that typed loads previously returned pointer tags before checking
read permission. That was harmless only while the old memory model had no
revocable read permissions. The new check covers tags as well as scalar bytes.
An independently compiled mutant removes just this check; the new no-access
pointer test fails because the mutant incorrectly returns pointer authority.
Retired pointers can still travel as opaque data; dereferencing them remains
rejected. A test expecting transport itself to reject was corrected accordingly.

Immutable initializer snapshots now require **every** page to be non-writable,
not merely a failed all-pages-writable check. This matters for mixed permission
ranges. Table permissions are revalidated at callback boundaries as well as bytes
and lifetime. Scalar stores preflight writable permission before any FILE buffer
claim or other typed-store metadata effect.

The API binding validates the actual original named import in mapped PE32
headers/descriptors/thunks, including lookup termination, name, IAT value and
bounded traversal. Changed name/IAT/code rejects before the effect. A loader-
modified IAT needs a separate supported binding; this helper does not infer a
callable export from arbitrary numeric values.

## Independent validation and evidence

Seven new memory tests cover page-boundary rounding, differing old permissions,
read-fact expiry, same-allocation output, unmapped range/overflow, invalid and
read-only outputs, stale/cross-process identity, executable/guard rejection,
unknown initialization, partial page tails, future alias mappings, mixed snapshot
permissions and epoch exhaustion. Failure cases assert unchanged output and
permission state.

Twenty-two native API/original-body scenarios cover actual callback success,
protected returns and saved registers, invalid ABI/output aliases, stale/narrowed
mapping authority, unknown arguments, permission restoration, altered original
code/name/IAT and typed-read revocation. Success is asserted explicitly; an error
cannot silently count as a passed positive case. The existing eighteen original
initializer-loop cases retain early/late failure, reverse rollback and prior-write
preservation. The full CRT tests and original artifact replays remain required.

`protect_probe.c` and `protect-frozen.json` freeze six independently specified
Windows observations before executing the observer: single-page, cross-page,
mixed-first-old, no-access, uncommitted-page failure and null-output failure.
Only an authored process's own temporary data allocation is used. No executable
permissions, user files, security settings, drivers or storage workloads are
involved. The workflow preserves stdout/stderr on failure/timeout and does not
retry. Failure old-output/LastError values are observations, not pre-guessed
native contracts. `MEMORY_BASIC_INFORMATION.Protect` is undefined for reserved
pages; the observer checks their reservation state and preserves protection bits
without using them as an equality oracle, per the
[primary structure contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information). Fresh results must be read from CI before being claimed; this
observer is not a translated PE and creates no whole-program comparison.

Local verification and source/artifact hashes are recorded in
[evidence/virtual-protect.json](evidence/virtual-protect.json). Five retained
recorded Windows wrapper comparisons remain component evidence. Historical
original-Windows process timeouts remain unresolved. CI for a predecessor cannot
validate this commit.

Verified locally: 182 root tests, 283 CRT tests (both artifact tests separately
passed in the reviewed replay), 76 Python tests with one existing skip, Clippy
and formatting. All three predecessor workflows for `d193e00` passed. New-head
CI and fresh Windows protection observations are separate pending gates.
