# SUB-552: mechanically translated runtime environment input

The new freestanding input program is admitted by a private production proof in
`src/linker/input.rs` and `input/proof.rs`. The unchanged source, compiler flags,
and 17 expected vectors remain frozen. Ordinary CRT startup and the four older
held-out programs remain rejected. This capability does not close their startup
or argument contracts.

## Intake and instruction boundary

The strict three-section linker parser checks all file/RVA ranges, permissions,
metadata aliases, allowed directories, import descriptor/ILT/IAT terminators,
initialized data, debug records and HIGHLOW relocations. It selects exactly
`KERNEL32.dll!GetEnvironmentVariableW` or the existing `_write` profile by validated
import spelling. Failure has no fallback. The input hint is a search optimization,
not function identity. Every relocation must bind to the decoded name PUSH or IAT
CALL. The complete immutable name is the 20-byte UTF-16 `W2L_INPUT` literal.

The code section must start at entry, fit 512 bytes, and consist entirely of the
reachable decoded graph (no unaccounted bytes). At most 128 instructions and 4,096
symbolic transitions are allowed. iced-x86 determines boundaries; a separate exact
byte-form allowlist supplies IR. Branches must move forward to instruction starts;
overlap, truncation, cycles and unsupported forms reject. The frozen artifact has
47 instructions in 129 bytes. Import selection cannot issue an emission certificate.

Forms are the observed SUB-550 forms: allocate/clean eight local bytes; form ESP
buffer address; PUSH immediate/EAX/name; indirect imported CALL; specified EAX,
ECX, EDX and ESI MOV/TEST/CMP (including CMP AX); specified local DWORD loads;
PUSH/POP ESI; MOVZX of DX/SI; SUB EDX; specified scaled/displaced LEAs; forward
JNE/JBE/JA and RET. The decoder is the exact form list. This is not general register,
addressing, stdcall, stack or memory support. Safe changes to immediates, guards or
reads may be accepted only if the same independent proof obligations hold.

## Symbolic ownership and value proof

Runtime data is never read during conversion. Values are unknown, affine scalars
modulo 2^32, the owned local-buffer pointer, immutable name, or original ESI.
Return, local, saved-register and argument words have distinct tags. Allocation
occurs once; the API call must have precisely the live owner, capacity three and
literal name above the two owned local words. The API consumes its 12 argument
bytes and preserves ESI; EAX becomes a symbolic result and ECX/EDX/flags unknown.
No pointer is coerced into a scalar or numeric ESP. No environment mutation or
additional external call is admitted anywhere in the complete graph.

The API forks into return classes 0, 1, 2, 4..65 and 66..UINT32_MAX. Only 1 and 2
initialize respectively four and six bytes, including the terminator. Zero and
oversize expose no buffer bytes. Each path retains its own state through joins.
A DWORD read checks all four byte owners and initialization, including the
unaligned read at ESP+6 after saving ESI (local offset two). Saved words, return
words and partially initialized tails cannot be read as local data. Cleanup must
consume exactly the two local words; return requires original ESI and a balanced
stack. Subsequent ESP-dependent flags are unknown and cannot control a branch.

The two UTF-16 units and API return are symbolic variables, not samples. Modular
unsigned comparison preimages split intervals exactly. CMP AX after subtraction
therefore refines a unit to 48..57 without assuming its unknown upper bits are
zero. Word loads retain the second unit in the high half. MOVZX discards that half
only for a proven projection. LEA uses wrapping 32-bit arithmetic and preserves
flags; in particular the intermediate -24 for a leading zero wraps to FFFFFFE8.
Final return values must be proved in 0..255. Conservative losses of precision
reject; unknown flags or unproved predicates do not become constants.

## Native runtime and assumptions

Only the reviewed acquisition/API effect is shared from `input/acquisition.rs`.
The standalone example's `program_exit()` is never embedded. Each decoded
instruction emits its own Rust operations and direct successor calls; branches
use the decoded flags. There is no runtime decoder, opcode interpreter, original
PE execution or AI runtime. Source is identical regardless of converter host or
converter environment. Multiple invocations of the same ELF acquire different
input at execution.

Address materialization and validated stack bookkeeping are replaced by owned
native storage. Initial zero placeholders for unobservable registers/local bytes
are not proof facts: reads of unknown values or bytes must pass the symbolic
checks first. Numeric ESP, ESI's incoming value and return addresses are never
exposed. The conditional flat, valid-stack, no-fault domain and sufficient native
stack still apply; the headers do not establish arbitrary process safety. Original
Windows binding and HIGHLOW relocation must succeed; RVA binding is invariant to
a valid rebase. This new artifact has no independently observed actual load base.

The Linux reader requires genuine available procfs and a stable **initial** process
environment, without relocation or mutation, including external asynchronous
mutation. The complete admitted application graph has no mutator, but this is not
proof of arbitrary host behavior. Names must be nonempty ASCII; the target has one
canonical uppercase spelling with no alias/duplicate. Target bytes must be UTF-8,
without embedded NUL, at most 64 UTF-16 units. Other values are opaque. Snapshot
limits remain 65,536 bytes, 256 records, 4,096 bytes per record, 1,024 read attempts
and a final NUL. Full snapshot validation continues after finding the target.

Unavailable procfs, non-Linux execution, I/O, encoding, malformed or resource
failures produce host unsupported exit 203 with empty output. They never become a
raw API-zero result (application exit 200). This boundary is outside the admitted
Windows equivalence domain. Raw error/empty/missing zero remains conservatively
uninitialized. Last-error details, Windows allocation faults, mutation races and
lone surrogate inputs are not emulated. Fixed component storage is not a bound
on all Rust startup memory, and the read-attempt cap is not a syscall latency
promise. See [ACQUISITION.md](ACQUISITION.md) for primary procfs/Read references and
[CONTRACT.md](CONTRACT.md) for the Microsoft API contract; instruction semantics
follow the independently implemented Intel x86 contracts referenced by the prior
[model](MODEL.md). No third-party implementation source was imported.

## Reproduction and evidence accounting

- `cargo test --locked`: 86 root functions, including seven new input-proof functions.
- `cargo test --locked --example bounded_input`: eight inherited acquisition tests.
- `python3 tools/check_input_production.py`: 18 authored native executions and 83
  rejected images. These do not use the unchanged compiler artifact.
- Windows `research/input/check.py`: builds the unchanged C source with frozen
  flags, hashes the PE, runs all 17 original vectors and emits Rust using production.
- Linux `research/input/check_translation.py evidence`: verifies the same PE and
  Windows-emitted source hashes, converts under two environments, compiles generated
  Rust, and compares the same ELF's 17 stdout/stderr/exit outcomes. It also checks
  110 independently specified native boundary cases and five host-domain rejections.
- The old model and separate prototype/component comparisons retain their own
  labels; none are counted as new translation pairs.

CI retains 12 previous compiler programs, 102 authored pairs, 18 original-only
launch checks and four held-out rejections. The input adds one compiler program
with 17 runtime scenarios, not 17 new programs. Windows Server 2025 evidence does
not establish XP/7 or general application compatibility. Four historical fixture
timeout causes remain unexplained; existing failure diagnostics are preserved.

Substantive medium review must inspect the private certificate, modular predicates,
join ownership, generated operations, shared acquisition and exact artifact hashes
before merge. Remaining architecture gates include general runtime unknown-state
composition, ordinary CRT effect closure, general loops/memory and PE32+.
