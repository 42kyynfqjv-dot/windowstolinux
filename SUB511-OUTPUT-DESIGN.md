> Historical design and review: production implementation now follows SUB512-OUTPUT.md.

# SUB-511: one imported output function — design only

Decision: trial `msvcrt.dll!_write(1, immutable_ascii, count)` as a narrowly
specified cdecl import. Production still rejects this image and all imports.
The authored Windows PE and separate native Rust support probe are **not a
mechanically translated pair**. They test prerequisites for SUB-512. Medium
contract review must precede that implementation; no application/XP/7 claim.

## API choice and provenance

Primary references (consulted 2026-10-26):

- [Microsoft `_write`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/write?view=msvc-170): fd, buffer, unsigned count; byte count or -1;
  LF translation, CTRL-Z and Unicode modes, invalid-parameter handling and errors.
- [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile):
  native handle, output byte-count pointer and overlapped argument; synchronous
  success/failure and partial pipe writes. This requires handle acquisition and
  writable guest output storage; it exceeds this one-import/immutable-data slice.
  GetStdHandle plus WriteFile would already be two APIs.
- [cdecl](https://learn.microsoft.com/en-us/cpp/cpp/cdecl?view=msvc-170) and
  [x86 arguments/returns](https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions?view=msvc-170):
  right-to-left arguments, caller cleanup, EAX return, volatile registers.
- [CRT library features](https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-library-features?view=msvc-170):
  modern UCRT/startup split. **`msvcrt.lib` in modern documentation is not proof
  of the legacy OS `msvcrt.dll` contract.** DLL availability, startup initialization
  and fd1 behavior are explicit experimental assumptions. Record actual PE32
  SysWOW64 DLL file version and OS in CI. No redistributed Microsoft DLL.
- [PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format):
  import descriptors, lookup/address tables, hint/name entries and data directories.
- Intel SDM vol2, CALL/RET/PUSH/LEA instruction contracts (existing instruction
  provenance applies). An API call does not promise our arithmetic flags survive.

Implementation/model and fixtures are independently authored MIT OR Apache-2.0.
No copied Wine/Microsoft implementation or tests; no claim of a clean-room process.
Native support uses Rust std only. The converter's iced dependency stays out of
emitted programs. This API introduces no new third-party library dependency.

## Observation and environment contract

First program: push count5, buffer0x402000, fd1; call through exact IAT cell;
three LEA ESP,[ESP+4] cleanups; CMP EAX,5; return0 if equal, otherwise99.
Expected stdout bytes `48 65 6c 6c 6f`, empty stderr, exit0. No newline/NUL.

Initial equivalence domain: PE loaded at preferred base, valid native stack,
legacy CRT initialized with valid fd1 in byte text or binary mode; stdout is an
empty writable **regular file**, separate from stderr, with no concurrent writer,
append behavior or external offset changes. One full successful write, sufficient
resources, no signals/interruption, disk-full or native faults. Native Linux fd1
must name the corresponding regular output file. Console, terminal, pipe, Unicode
CRT mode and arbitrary CRT global state are outside this contract. The probe's
Python subprocess uses real file handles, avoiding PowerShell output transcoding.
The source program does not itself establish CRT mode; CI observations on one OS
cannot guarantee it on other Windows versions. Runtime metadata can check Linux
regular-file type, but cannot prove the Windows CRT mode or every resource assumption.

Buffers contain 1..64 bytes, each 0x20..0x7e; excludes LF, CR, CTRL-Z, NUL and all
non-ASCII bytes. There is no implicit terminator or encoding conversion. Count is
known from validated stack values, not read from arbitrary guest memory. Lengths
0 and >64 are explicitly unsupported even if `_write` could handle them.

Success returns exact count in EAX. CF/ZF/SF/OF all become unknown. No promise
about volatile ECX/EDX; their use is already unsupported. Validate continuations
using unknown flags, requiring CMP/XOR/ADD before a dependent branch. MOV/LEA
cannot restore flag knowledge. `_write` leaves caller arguments for cdecl cleanup.

A native support operation uses **one unbuffered write**, without write_all or
retry. Duplicate inherited fd1 into an owned Rust File (checked duplication and
regular-file metadata); Rust std has no new runtime package dependency. The
standalone prototype borrows the descriptor through Stdout::as_fd and duplicates
it into an owned File, without unsafe code or buffered Stdout writes. Future
emitted code must preserve that ownership/lifetime and never close/replace fd1.

Short/zero writes, I/O errors, broken pipe, metadata/duplication failure or wrong
file type terminate the translated program with converter diagnostic on stderr
and exit125. Partial stdout can remain. This is an **explicit unsupported-runtime
failure**, not emulated `_write` -1/errno/invalid-parameter behavior or equivalence
to Windows failure paths. Do not synthesize success or continue with EAX=count.
SIGPIPE handling must be checked for the generated Rust entry point before any
pipe-domain claim; no such claim is in scope. The diagnostic itself is best effort.
No guarantee of durable disk storage beyond normal write completion.

## Proposed image/import policy (not implemented)

Extend only the existing two-section profile to exactly three ordered sections:
RX code (0x60000020), immutable R data (0x40000040), loader-managed RW import
metadata (0xc0000040). Names are labels, not permission evidence. Preserve checked
file/RVA/VA bounds, alignment, non-overlap, aggregate sizes and exact image extent.
Third section must be fully file-backed, no virtual tail. No guest reads/writes
into import metadata; loader IAT mutation is a special external operation, not
permission for general guest writable memory. Existing A1 still accesses only
immutable section2. Headers/code/imports/raw padding/gaps cannot supply buffers.

Only data directories1 (import) and12 (IAT) may be nonzero. Import directory is
exactly two20-byte descriptors: one live then one all-zero terminator. Fields
TimeDateStamp/ForwarderChain=0; OriginalFirstThunk nonzero; exactly one ILT and IAT
entry plus zero terminator, each four-byte aligned, each8 bytes. IAT directory
exactly matches that table. Both on-disk entries equal one hint/name RVA, no
ordinal/bound/delay imports. Hint0; exact case-sensitive bytes `msvcrt.dll\0` and
`_write\0`. Every metadata span lies wholly in third section's virtual and raw
extent, using checked arithmetic; bounded fixed-length string checks. All live
metadata spans (descriptor pair, ILT, IAT, DLL and hint/name strings) are disjoint;
reject aliases, duplicate descriptors, missing terminators, overflowing offsets,
extra imports and all other directories. Padding is not another inferred table.
This strict subset need not accept general linker output.

Only `FF 15 <absolute IAT-cell VA>` is proposed, six bytes, no prefix, exact
32-bit indirect memory CALL metadata; preferred-base VA must resolve to the sole
validated IAT slot. Never dereference a host pointer or execute the original PE.
Represent a typed imported-call IR operation; no general indirect-call fallback.
Reject call into ILT, names, neighboring cells, code/data or rebound addresses.
Check instruction boundaries and executable range as for existing branches.
At most one imported call in the whole decoded graph, and at most one per executed
path (shared helpers can otherwise revisit the same instruction). Track invocation
count in abstract and emitted state; reject repeated reachable invocation.

## Tagged stack and validation

Before call, top-to-bottom: Data(current,fd1), Data(current,bufferVA),
Data(current,count); three contiguous current-owner words. Reject protected tags,
ancestor ownership, missing/unknown values. Validate buffer from **this same Pe's**
immutable-section mapping, complete count-byte raw AND virtual span, checked
VA-base subtraction and final-address addition. Snapshot the validated bytes into
IR; no cross-image cache or guest pointer in native support. Decode and validate
all reachable import arguments/targets, including unsupported cases on untaken
branches under the existing conservative policy.

The hardware CALL temporarily pushes a return address. Model an atomic protected
external return tag, checking the existing128-word/32-depth limits for that
transient entry; it must not consume/remove the three arguments. Do not model CRT
internal stack activity; valid-stack/no-fault remains a conditional assumption.
The external call returns to the next instruction, never a guest-supplied target.
Existing LEA cleanup removes arguments one word at a time; RET still rejects any
uncleaned current-frame Data. Shared/nested contexts retain ownership rules.

Validation performs no I/O. It models the full-success domain (EAX=count, flags
unknown), records the explicit runtime failure edge and validates deterministic
success continuations. Emit the call only at actual runtime control flow, exactly
once. An untaken valid call produces no output. Merged states must retain invocation
count and unknown flags; reject ambiguity not representable by the current model.
No unconditional pre-execution of effects during conversion.

## Evidence and limits of this change

- `scripts/make_output_probe.py`: authored three-section PE, one legacy CRT import.
- `scripts/check_output_probe.py`: literal independent layout/argument/branch
  assertions, optional actual Windows execution with raw byte/exit assertions.
- `tools/decoder-eval/src/output_design.rs`: four new test functions, exhaustive
  256-byte ASCII-domain check, count/range/owner/tag cases, exact success and
  injected short/zero/broken-pipe outcomes with one-call/no-retry assertions.
- `tools/output-probe.rs`: separately compiled native support prototype emitting
  Hello to a regular file; rejects /dev/null with diagnostic/125. **Hand-authored,
  not converter output.** Import parsing, full graph/stack integration and native
  instruction execution are not implemented by this model.
- CI preserves all63 original Windows/Linux production cases and requires the
  production converter to reject the output probe. The Windows experiment must
  pass before treating the legacy CRT startup assumption as observed on that OS.

## SUB-512 implementation gates after medium review

1. Strict image/import parser with independent literal expected structures and
   table-driven adversarial mutations: truncation at every byte, VA/RVA overflow,
   raw/virtual tails, overlap/alias, permissions, ordinal/bound/delay/extra imports,
   wrong names/hints/terminators/IAT extents. Preserve every old loader rejection.
2. Exact iced call form and typed IR; no other FF form/prefix admitted. Wrong slots,
   code/data targets, boundary overlaps and repeated imported-call contexts reject.
3. Unified validator/emitter ownership, transient depth/capacity, balanced cleanup,
   EAX/count and flag invalidation. Independent nested/shared/join/untaken fixtures;
   missing argument, stale flag, uncleared words, wrongowner/protectedtag negatives.
4. Same-image complete buffer provenance, first/last valid bytes, length1/64,
   off-by-one/cross-section/overflow and disallowed-byte negatives. Same code with
   different immutable payload must change output, not reuse earlier image data.
5. Independently specified original-versus-**mechanically translated** fixtures:
   Hello, another payload, valid boundary length and untaken output. Compare exact
   stdout/stderr/exit; compile generated Rust standalone, deterministic source on
   repeat conversion; no decoder/Wine/AI dependency in emitted ELF.
6. Inject runtime full/partial/zero/error outcomes, verify no fabricated success,
   no retry, explicit failure exit/diagnostic, retained possible partial output.
   Review fd lifetime and resource limits. Do not claim Windows error equivalence.
7. fmt, Clippy, all existing tests and63 baseline comparisons, new targeted cases,
   exact-head GitHub CI and recorded OS/DLL version. If legacy startup experiment
   fails, fix/report that blocker before production work; do not widen API scope.

Astra High is appropriate for parser/effect/stack integration. Medium should first
review this contract and test independence, then review the bounded implementation.
No merge/release, general handles, APIs, memory writes, relocation or console modes.

## Medium contract review

Review confirmed the printable byte domain excludes documented LF expansion and
CTRL-Z termination; it does not make Unicode mode equivalent. That mode remains
an external exclusion. The native prototype now rechecks length/bytes at its effect
boundary as well as argument preparation, preventing bypass through direct invoke.
This check does not establish PE provenance: production must still bind that proof
to the parsed image. Existing exhaustive byte tests exercise preparation; direct
invoke regressions check empty/newline/CTRL-Z/oversize rejection before any write.

The Microsoft contract does not promise preservation or clearing of errno on
success. Neither errno nor _doserrno is part of the supported observation: access
to their storage/functions, invalid-parameter handlers, CRT stream state and later
CRT operations must remain rejected. File-position effects match only under the
stated isolated initial-offset/full-write assumptions. _write is descriptor I/O;
there is no supported FILE stream to fflush. Native File writes add no user-space
output buffer. Neither dropping the duplicate nor successful write proves durable
storage; do not add an fsync or fflush compatibility claim.

One call-site IR snapshot must not accidentally reuse the first context's bytes:
if a shared call site has differing validated count/payload across contexts, reject
that program in SUB-512. Context specialization is outside this initial slice.
Require an independent negative fixture for this case. Untaken-call validation
must propagate a hypothetical stack state through both decoded successors with
bounds; do not describe today's constant-path evaluator as already proving it.
If that conservative analysis cannot represent a state, reject it. Include tests
for no output on the selected untaken path, and invalid arguments on its decoded
alternative. These are implementation requirements, not prototype evidence.

EAX is replaced, ECX/EDX and four flags cannot be assumed preserved. The current
ISA subset cannot observe other volatile registers or CRT global state. API return
must invalidate modeled flags before every successor/join; no probe observation
of coincidental preservation can substitute for that rule. Caller cleanup and
protected return-tag limits require production-path tests, not this buffer model.

Ready for bounded Astra High SUB-512 implementation after this review: the legacy
CRT startup/byte-mode/valid-stack/preferred-base/full-success domain remains
conditional. Production must prove strict metadata/buffer rejection and actual
mechanically translated observations before announcing imported-output support.
