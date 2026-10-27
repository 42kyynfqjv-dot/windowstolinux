# SUB-576 checked-memory integration

The Rust core in `src/guest_memory.rs` is compiled into generated streaming
programs. The compiler's existing normalized load/store/LEA and frame/solver
admission gates remain authoritative. This is a storage integration, not a new
ordinary CRT loader, Heap API implementation, or permission to skip startup.

## Contract and integration boundary

- Numeric PE32 addresses and wrapping effective-address arithmetic stay numeric.
  Full accesses use nonwrapping 64-bit endpoints; an access ending exactly at
  2^32 is valid if mapped. Null, zero-length core accesses, and crossing even two
  adjacent distinct regions reject. This deliberately conservative region rule
  does not claim complete Windows virtual-memory behavior.
- Disjoint regions have process identity, owner kind/instance, fresh generation,
  read/write/execute metadata, bytes and per-byte definedness. Writable/executable
  mappings reject. Execute permission is metadata, not execution admission.
  Image construction copies specified bytes and defines loader zero-fill only;
  unknown storage is never read as a fabricated zero.
- Proof capabilities are opaque and process-bound. Read facts additionally bind
  a region mutation epoch and full range. Writes invalidate facts conservatively
  for the whole region. Free/reuse invalidates tokens, but a raw address can read
  its new mapping. Generations are not substituted for guest pointer bits.
- A moving storage transition preserves the common prefix and its definedness;
  only the new tail is zero-defined when requested. Invalid/budget-failed moves
  leave the original mapping and facts intact. This primitive deliberately does
  not implement HeapReAlloc flags, LastError, zero-size, in-place reallocation,
  exceptions, concurrency or Windows allocation placement/alignment.
- Trusted effect adapters may borrow writable storage and commit a promised
  initialized prefix. Borrowing bumps the epoch but does not erase physically
  defined old bytes. Defining bytes is an explicit trusted postcondition, not an
  operation guest code can invoke. Unresolved external effects still reject.
- Per-space ceilings are 64 regions and 1 MiB backing bytes, with separate
  definedness storage. Allocation uses fallible reservation. Counter exhaustion
  and budget errors reject explicitly. These are implementation limits, not
  Windows limits; out-of-domain failures are not Windows exception equivalence.

The existing streaming profile proves a relative 4096-byte stack frame. It keeps
those register coordinates and LEA arithmetic; its wrapper maps backing at private
base 0x10000, translates only already-checked frame offsets, and retains separate
fresh-prefix facts. That backing base is **not** an observed Windows ESP or an
application-visible claimed guest layout. Unknown initial ESP, saved-return and
ABI obligations remain governed by the existing proof. No new absolute frame
pointer, image/heap access or address-dependent output is admitted. Other existing
translation profiles are not silently migrated. This is a concrete shared access
seam; general process-address composition remains a next gate.

ReadFile invalidates freshness before lending a destination. Success defines only
its validated returned prefix; old tail bytes can remain physically defined but
cannot satisfy fresh-read proof. Failed reads leave that freshness invalid.
Frame sub-allocation likewise invalidates freshness. Empty frame slices allow a
checked one-past endpoint without creating a zero-size core mapping. Runtime
contract violations retain diagnostic/exit125, not a fabricated successful result.
No unsafe host pointer, Wine, interpreter, AI or solver runtime is introduced.

## Independent validation and measured acceptance

Seven new Rust test functions use literal bytes and invalid transitions. Temporary
copies with seven omitted guards (process, generation, definedness, epoch,
32-bit endpoint, writable permission, W+X) must fail those tests. Ten checks compile
the actual emitted runtime and exercise aliases, stale tails, failed-read freshness,
unknown bytes, complete widths, zero slices and count/output overlap. These are
component tests, not Windows translation evidence. Two further import-table test functions check all 11 subsets of size 2–4 in both
orders (22 tables), plus malformed extents, aliases, early nulls, unknown and
duplicate names. Only the existing four-function allowlist is available; importing
a supported subset no longer requires an unused GetLastError. The existing
one-import legacy profiles remain separate. The prior 129 root tests remain.

`conformance/` freezes two independently authored algorithms before measurement:
leftward overlapping copy and adjacent-pair permutation. The custom-entry MSVC
/O2 artifacts are unmodified; one read selects a runtime length and offsets in a
32-byte frame buffer. Twelve independent binary file vectors per program cover
empty, odd/even and capacity boundaries; real read/write failures are separate.
These are memory conformance programs, not independently developed third-party
utilities or general heap allocation tests. Windows observations precede conversion;
Linux consumes exactly their hashed PE files, compares deterministic Rust and runs
accepted results. Rejected programs retain exact diagnostics and untouched output.
See `conformance/RESULTS.md` after CI for actual outcomes; no pending run is counted.

Reproduce with `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`,
`python3 research/process/check_memory.py`, Windows `conformance/measure.py OUT`,
then Linux `conformance/check_native.py OUT`. The complete existing cross-host
workflow remains required. Modern Windows evidence is not XP/7 validation.
Eight historical original-Windows timeout causes remain unresolved.

## Reuse, provenance and remaining gates

Independent Rust and authored tests: MIT OR Apache-2.0. No implementation source
from Wine, Microsoft CRT or third-party utilities was imported. Primary PE,
VirtualAlloc and HeapReAlloc contracts are linked in `DESIGN.md`. ISCC/rcedit
require shared region/heap/module lifetime, not app-specific identities. Their
ordinary startup, TLS/SEH, dynamic modules, managed objects and API effects remain
unresolved and conversion remains rejected. VirtualDub and CrystalDiskMark/DiskSpd
families stay reserved. Wine reproduction is a separate evidence gate.

A future device backend would bind a process-owned handle to a device/interface
identity and versioned operation contract: input/output buffer direction, complete
bounds, initialized output counts, errors, ordering, async completion/cancellation,
privilege and lifetime. An existing Linux driver/interface is usable only where
those observable semantics match. Software-only driver services may have a
user-mode native implementation; Windows-kernel-specific/hardware-dependent work
is a separate track. This boundary grants no device access, driver loading,
storage workload or security-setting change, and promises no universal adapter.
