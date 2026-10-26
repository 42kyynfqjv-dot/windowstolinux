# SUB-533: native byte-local compiler program

The unchanged frozen buffer.c MSVC artifact is now an execution acceptance gate:
Windows original and independently converted Linux ELF must produce empty stdout/
stderr and exit132 from the same hashed PE and byte-identical generated Rust. Original
source/configuration and PE bytes remain untouched. conversion.json separately requires
buffer and structure acceptance; the other six held-out programs remain rejected.

## Shared checked semantics

Implement only the exact forms in SUB532-BYTE-LOCAL-DESIGN.md. The compiler-profile
State shared by proof and emission adds Partial([Option<u8>;4]), normalized to Integer
only when every byte is known. Opaque Unknown yields four unknown bytes; Pointer byte
access rejects. Full scalar consumers still use integer(), which rejects partials.
MoveEsi rejects partial scalars to preserve existing saved-origin proof. No new path
stores partials into caller Data. XOR self deliberately establishes known zero from
unknown scalar bits while retaining the existing pointer exclusion.

Allocation explicitly selects Words(token) or Bytes(token). ByteLocal is one protected
owned word with four independently known/unknown bytes. PUSH ECX copies its scalar
bytes; POP ECX loads the modified word before release. Both preserve flags. Complete
boundary, shape, owner and token checks precede accesses. Byte offsets0/1 are the only
forms; word/Data/byte aliases, mixed allocations and cleanup fallback reject. New
PUSH allocation requires a balanced boundary. Nested parameterless calls suspend
caller locals with separate ownership. Existing limits and balanced ESI/return rules
remain enforced. Failed transitions commit no machine-state changes.

INC AL requires known AL, preserves upper24 bits and CF, and defines byte ZF/SF/OF.
MOVZX establishes a full zero-extended Integer; byte MOV preserves flags. Knowledge
stores each tracked flag as Option<bool>. Whole scalar arithmetic defines all four;
ESP arithmetic and output calls invalidate all four. JZ/JNZ read only ZF; CMOVGE
requires known SF and OF. No new conditions or AF/PF consumers are introduced. The
other authored-program decoder/flag path retains its existing semantics.

Private importless PE eligibility, metadata exclusion and full graph/state proof
remain unchanged. No absolute pointer/memory, heap/global, loops, CRT or PE32+ support
is added. Valid aligned sufficient stack, no wrap/fault/asynchronous mutation and
unobservable absolute ESP/return address remain explicit assumptions. Windows evidence
is Server2025 only; it does not establish XP/7 or ordinary application compatibility.
Independent implementation/provenance follows the Intel/Microsoft sources in SUB532;
no Wine or AI runtime and no decoder dependency in emitted ELF.

## Verification and review

76 root Rust test functions (73 prior +3 byte-state functions): literal byte trace,
partial AL and carry truth tables, full-read/ESI rejection, MOVZX, modified POP/PUSH
reuse, scalar normalization, CMOV/JZ flag prerequisites, nested/shared ownership,
protected/foreign/mixed/token failure, uninitialized path isolation and atomic errors.
Test-only compatibility adapters compare legacy Option<Flags> expectations against
Knowledge without adding runtime conversions or weakening expected flag values.

Independent CLI/native byte cases use literal instruction bytes and expected results:
11 deterministic native programs and121 rejection cases, including prefixes inserted
into valid controls, unsupported registers/widths/offsets, unknown reads and untaken
uninitialized paths. The synthetic PE shell is reused from the reviewed local tests;
no model/production-derived behavioral oracle. Earlier local10 native/95 rejections,
compiler suites and nine byte-model functions remain separately counted.

CI adds unchanged buffer as the tenth compiler comparison, preserving102 authored
pairs and18 launch diagnostics. check_byte_local_contract.py checks exact34 compiler
bytes/hash and independent model trace; compiler/heldout/check_native.py independently
converts twice, verifies Windows-generated Rust identity and actually compiles/executes
ELF. The model trace does not stand in for execution. No retries/timeout changes;
three historical original-Windows timeout causes remain unresolved.

Reproduce with cargo fmt --check, rustfmt --check src/linker/state.rs, cargo clippy
--all-targets --locked -- -D warnings, cargo test --locked, cargo build --locked,
python tools/check_byte_production.py, and .github/workflows/ci.yml for Windows evidence.
Next medium review: partial scalar normalization and every full-value consumer,
per-flag migration/condition inputs, byte/word cleanup isolation, POP/PUSH modified
contents, independent regressions and exact compiler-artifact provenance. Draft only;
no merge/release or broader capability expansion in this slice.

Medium review adds a native full-known POP normalization/compare case from a real
caller scalar argument. The unknown-ECX full-read rejection now initializes EAX,
so it cannot pass merely because the other ADD operand was also unknown. These
close evidence gaps; no production defect was reproduced. Partial AL preservation,
per-flag consumer knowledge and distinct allocation-kind cleanup remain as specified.
Next proposed design is frozen held_array read-only use of initially writable image
data: whole-program no-write proof, relocation-bound scalar reads and initial-data
provenance before any eligibility change. Ordinary CRT/loop support remains separate.
