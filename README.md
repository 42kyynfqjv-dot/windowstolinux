# WindowsToLinux

WindowsToLinux is an early research project for deterministic Windows PE to Rust static recompilation. The long-term target is Windows XP through Windows 7 SP1 applications on native Linux, without Wine at runtime. No general application compatibility has been demonstrated.

## Current prototype

`w2l` accepts only a narrow PE32/x86 console profile: one executable section, no PE data directories, no DLL characteristics, a file-backed entry point, and instructions limited to `mov eax, imm32`, `add eax, imm32`, `xor eax, eax`, `cmp eax, imm32`, `ret`, and forward short `JC/JNC/JZ/JNZ/JL/JGE` branches. ADD, XOR and CMP model carry, zero, sign and overflow flags; MOV preserves them and CMP preserves EAX. Both branch successors must decode, all targets must be instruction boundaries, and decoding and execution are limited to 1,024 instructions. The returned EAX value must be in 0–255 so a Linux process exit status can represent it without truncation. Unsupported instructions, imports, TLS, relocations, other declared directories, and images outside this profile cause an error. This prototype does not implement general PE loading, Windows APIs, memory, stack, backward branches or other conditions/CPU flags. See [M2-CONTRACT.md](M2-CONTRACT.md) and [SUB502-CONTRACT.md](SUB502-CONTRACT.md) for the precise accepted subset.

```sh
cargo run -- sample.exe translated.rs
rustc translated.rs -o translated
```

Only use independently authored or appropriately licensed fixtures. See [ARCHITECTURE.md](ARCHITECTURE.md) and [ROADMAP.md](ROADMAP.md) for boundaries and validation gates.

The authored `scripts/make_pe32_fixture.py` builds import-free PE32 cases within that profile. CI runs them on a GitHub hosted Windows Server 2025 runner and compares their exit status and empty stdout/stderr with generated Linux ELFs. These are small modern Windows fixtures, not evidence of Windows XP–7 compatibility.

## Status

M0, M1 and the bounded M2 slice are in draft review. CI exercises 34 authored Windows/Linux cases, including taken and untaken outcomes for each supported branch. An isolated [iced adapter trial](docs/DECODER-ADAPTER-TRIAL.md) checks exact current-subset parity; production still uses the original decoder. The 99% compatibility objective is aspirational and has no measured corpus result.

## License

Original code is licensed under either MIT or Apache-2.0, at your option.
