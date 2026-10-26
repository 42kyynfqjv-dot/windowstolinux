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

M0, M1 and the bounded M2 slice are in draft review. CI exercises 63 original arithmetic/data cases plus six imported-output Windows/Linux cases, including taken and untaken outcomes for each supported branch. The [strict iced production adapter](docs/DECODER-INTEGRATION.md) preserves the exact subset and is compared against a handwritten test oracle. The 99% compatibility objective is aspirational and has no measured corpus result.

## License

Original code is licensed under either MIT or Apache-2.0, at your option. Converter dependencies carry the notices in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

SUB-512 adds one strict three-section `msvcrt.dll!_write` profile with exact FF15
call, immutable printable ASCII1..64 and regular-file/full-success assumptions.
See [SUB512-OUTPUT.md](SUB512-OUTPUT.md) for validation, runtime failures and limits.
