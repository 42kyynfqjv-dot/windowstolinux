# WindowsToLinux

WindowsToLinux is an early research project for deterministic Windows PE to Rust static recompilation. The long-term target is Windows XP through Windows 7 SP1 applications on native Linux, without Wine at runtime. No general application compatibility has been demonstrated.

## Current prototype

`w2l` accepts only a narrow PE32/x86 console profile: one executable code section with optional adjacent read-only initialized data under [SUB509-MAPPING.md](SUB509-MAPPING.md), no PE data directories in the one/two-section profile, no DLL characteristics, a file-backed entry point, and instructions limited to `mov eax, imm32`, `add eax, imm32`, `xor eax, eax`, `cmp eax, imm32`, `ret`, forward short `JC/JNC/JZ/JNZ/JL/JGE` branches, and forward direct `CALL rel32`. Internal RET resumes a saved continuation; entry RET terminates. The exact forms `PUSH imm32` (`68 id`), `MOV EAX,[ESP+4]` (`8B 44 24 04`) and `LEA ESP,[ESP+4]` (`8D 64 24 04`) support one caller-owned argument and flags-preserving cleanup. A unified tagged stack isolates return addresses, caps data plus return words at 128 and internal calls at 32, and rejects unbalanced returns. `ADD ESP`, POP, other memory forms and general ABI support remain excluded. ADD, XOR and CMP model carry, zero, sign and overflow flags; MOV preserves them and CMP preserves EAX. Both branch successors must decode, all targets must be instruction boundaries, and decoding and execution are limited to 1,024 instructions. The returned EAX value must be in 0–255 so a Linux process exit status can represent it without truncation. Unsupported instructions, imports other than the SUB-512 profile, TLS, relocations, other declared directories, and images outside this profile cause an error. This prototype does not implement general PE loading, Windows APIs, memory, general stack access, backward branches/calls or other conditions/CPU flags. See [M2-CONTRACT.md](M2-CONTRACT.md) and [SUB502-CONTRACT.md](SUB502-CONTRACT.md) for the arithmetic/branch subset and [SUB506-CONTRACT.md](SUB506-CONTRACT.md) for calls and returns, extended by [SUB507-DESIGN.md](SUB507-DESIGN.md) and [SUB508-IMPLEMENTATION.md](SUB508-IMPLEMENTATION.md) for bounded arguments.

The stack contract assumes flat 32-bit addressing, an aligned incoming ESP, a valid entry return and 512 bytes of accessible stack below it, without wrap, faults or asynchronous interference. Numeric ESP is unknown and never exposed. These are conditional execution assumptions; PE headers do not establish them for arbitrary programs.

```sh
cargo run -- sample.exe translated.rs
rustc translated.rs -o translated
```

Only use independently authored or appropriately licensed fixtures. See [ARCHITECTURE.md](ARCHITECTURE.md) and [ROADMAP.md](ROADMAP.md) for boundaries and validation gates.

The authored `scripts/make_pe32_fixture.py` builds import-free PE32 cases within that profile. CI runs them on a GitHub hosted Windows Server 2025 runner and compares their exit status and empty stdout/stderr with generated Linux ELFs. These are small modern Windows fixtures, not evidence of Windows XP–7 compatibility.

Exact unprefixed `A1 moffs32` loads EAX from four validated immutable data bytes under [SUB510-IMMUTABLE-LOAD.md](SUB510-IMMUTABLE-LOAD.md). Reads require the preferred image base, flat DS and fault-free immutable data; unaligned reads require alignment checking disabled. General memory and rebasing remain unsupported.

## Status

Current active work: SUB-576 integrates a reusable checked-memory core into
proved streaming-frame accesses. [Contract and conformance gates](research/process/IMPLEMENTATION.md)
separate byte definedness, read freshness and process-bound proof identity.
Work through SUB-575 is reviewed and merged, including LLVM streaming validation
and original ISCC/rcedit measurements. Neither third-party utility translates yet;
ordinary CRT startup and general process/API composition remain blocked.
Z3 is compiler-only; generated binaries require neither Z3 nor Wine. Eight
historical original-Windows launch timeouts remain unexplained. Earlier status
paragraphs below are historical checkpoints.


Reviewed work is merged through SUB-561. SUB-562's cohesive
[runtime-input composition](research/input/heldout/COMPOSITION.md) is in draft review:
shared operand/frame/owner-offset/capacity semantics target all eight frozen O1/O2
artifacts and 112 same-PE Windows/Linux input scenarios. Final-commit CI evidence
is recorded in the PR; local acceptance alone is not a merge gate. Earlier status
paragraphs below are historical checkpoints.
The existing 16 compiler-program baseline, 51 input-variant comparisons,
102 authored comparisons and 18 original-only launch checks remain required.
Runtime arguments through ordinary CRT, ordinary CRT startup, file I/O and PE32+
remain unsupported. This selected freestanding corpus is not general application
compatibility. The 99% compatibility objective remains aspirational.

SUB-546 records a [no-go accessor closure decision](research/crt/ACCESSOR-CLOSURE.md).
The isolated option, sentinel and external-cell research components do not close
ordinary CRT startup. The later lifetime/context analysis still leaves original startup blocked. Historical checkpoints below describe earlier scopes; the latest linked
implementation contracts govern each added profile. Four historical Windows
fixture timeouts remain unexplained; diagnostics and failure propagation remain enabled.

## License

Original code is licensed under either MIT or Apache-2.0, at your option. Converter dependencies carry the notices in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

SUB-512 adds one strict three-section `msvcrt.dll!_write` profile with exact FF15
call, immutable printable ASCII1..64 and regular-file/full-success assumptions.
See [SUB512-OUTPUT.md](SUB512-OUTPUT.md) for validation, runtime failures and limits.

Linker-produced minimal MSVC images have bounded structural intake and typed
all-path validation before emission. See
[SUB516-INTAKE.md](SUB516-INTAKE.md) for exact limits and instrumented load-base evidence.

SUB-518 replaces the linker-image emission block with typed all-path validation
for the exact observed minimal MSVC program. See [SUB518-IMPLEMENTATION.md](SUB518-IMPLEMENTATION.md)
for supported forms, conditional ABI assumptions and unchanged-compiler CI gate.
Ordinary CRT applications remain unsupported.

SUB-520 adds exactly ADD EAX,[ESP+12] and ADD ESP,24 to that linker profile.
The third argument must be caller-owned scalar data; cleanup removes six owned
words and invalidates tracked flags. See [SUB520-THIRD-ARGUMENT.md](SUB520-THIRD-ARGUMENT.md).
The frozen four C variants now have mandatory same-PE Windows/Linux conversion
and execution gates, in addition to the baseline and102 authored comparisons.

SUB-522 adds exact83 C4 08 two-word cleanup under the same protected-stack and
unknown-ESP flags contract; see [SUB522-TWO-WORD-CLEANUP.md](SUB522-TWO-WORD-CLEANUP.md).
The unchanged shared-helper compiler program is now a mandatory acceptance gate.

SUB-524 adds six exact scalar ECX/EDX and signed conditional-selection forms to the
linker profile; see [SUB524-CONDITIONAL-IMPLEMENTATION.md](SUB524-CONDITIONAL-IMPLEMENTATION.md).
CI requires seven unchanged compiler-built programs, including conditional.c,
alongside102 authored comparisons and18 original launch checks. Nested stack-copy/
tail-transfer and ordinary CRT support remain open.

SUB-526 implements the reviewed bounded nested compiler path; see
[SUB526-NESTED-IMPLEMENTATION.md](SUB526-NESTED-IMPLEMENTATION.md).
CI now requires eight unchanged compiler programs, including nested.c, alongside
102 authored comparisons and18 launch samples. Medium production review is next.

SUB-527 froze eight held-out compiler configurations before measurement; all eight
initially rejected. The recorded first results remain historical evidence in
[compiler/heldout/RESULTS.md](compiler/heldout/RESULTS.md). SUB-528/529 introduced
checked non-emitting inspection, and SUB-530 reviewed the local-frame contract.

SUB-531 implements two owned scalar local words and a private importless execution
path under [SUB531-LOCAL-IMPLEMENTATION.md](SUB531-LOCAL-IMPLEMENTATION.md). The frozen
structure.c PE must now independently convert on Windows and Linux to identical
Rust, then execute as Linux ELF with empty stdout/stderr and exit12, matching the
same hashed Windows artifact. Source, compiler flags and PE bytes are unchanged.
The other seven held-out programs retain explicit conversion rejection gates.

Inspection always reports `emission_allowed: false`; it is independent of the
complete graph/ABI/local proof required for conversion. Writable/global/byte memory,
loops, ordinary CRT and PE32+ remain unsupported. CI preserves eight earlier compiler
comparisons,102 authored comparisons and18 launch checks alongside the one new
structure-program comparison. Three historical Windows timeout causes remain
unresolved; persistent diagnostics and failure propagation remain enabled.

Next: medium production/provenance review of local-versus-argument byte-form dispatch,
protected ownership and uninitialized state, importless proof isolation and the
unchanged structure artifact. Subsequent capability work requires a separate bounded
gate driven by the remaining held-out failures. XP/7 and general apps remain unvalidated.

SUB-532 proposes owned byte-local storage and partial-register/per-flag semantics
in [SUB532-BYTE-LOCAL-DESIGN.md](SUB532-BYTE-LOCAL-DESIGN.md). Nine independent model
functions and exact unchanged-buffer artifact checks are design evidence only.
Production still rejects held_buffer; medium contract review precedes implementation.

SUB-533 implements the reviewed byte-local contract. See
[SUB533-BYTE-IMPLEMENTATION.md](SUB533-BYTE-IMPLEMENTATION.md): the unchanged buffer
program now requires same-PE Windows/Linux empty output/exit132. Ten compiler
comparisons,102 authored pairs and18 launches are required; six held-out conversions
remain rejected. Next is medium production/provenance review of partial values,
per-flag knowledge, ownership and exact artifact evidence.

SUB-535 adds the bounded initialized image-read profile documented in
[SUB535-IMAGE-READ-IMPLEMENTATION.md](SUB535-IMAGE-READ-IMPLEMENTATION.md).
Writable data is read only after complete no-write/relocation proof for a five-form
straight-line body. The frozen array program joins ten previous compiler comparisons;
five held-out programs remain unsupported. Conditional execution assumptions apply.

SUB-537 adds only the exact proven finite summation loop in
[SUB537-FINITE-LOOP-IMPLEMENTATION.md](SUB537-FINITE-LOOP-IMPLEMENTATION.md).
The unchanged held-out loop must match Windows empty output/exit10; twelve compiler
comparisons are now required, with four remaining held-out capabilities rejected.
This is a narrow recognized graph with explicit ranking, resource and exit bounds.

The streaming corpus integration extends the shared proof/emitter to frozen O1/O2
ROT13, reverse-XOR and NUL-compaction programs. See
[its bounded contract and evidence gates](research/cli/corpus/INTEGRATION.md);
scripted backend tests and Windows/ELF process comparisons are counted separately.

Stateful CRLF normalization now uses shared conditional selection and independent
input/output initialization proofs. See [integration and evidence gates](research/cli/crlf/INTEGRATION.md).
The unchanged O1/O2 artifacts must match 78 Windows/ELF observations; scripted and
partition executions remain separately counted.
