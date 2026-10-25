# WindowsToLinux

WindowsToLinux is an early research project for deterministic Windows PE to Rust static recompilation. The long-term target is Windows XP through Windows 7 SP1 applications on native Linux, without Wine at runtime. No general application compatibility has been demonstrated.

## Current prototype

`w2l` accepts only a narrow PE32/x86 console profile: one executable section, no PE data directories, no DLL characteristics, a file-backed entry point, and instructions limited to `mov eax, imm32`, `add eax, imm32`, `xor eax, eax`, `ret`, and forward short `JC/JNC/JZ/JNZ` branches. ADD and XOR model carry and zero flags; MOV preserves them. Both branch successors must decode, all targets must be instruction boundaries, and decoding and execution are limited to 1,024 instructions. The returned EAX value must be in 0–255 so a Linux process exit status can represent it without truncation. Unsupported instructions, imports, TLS, relocations, other declared directories, and images outside this profile cause an error. This prototype does not implement general PE loading, Windows APIs, memory, stack, backward branches, signed conditions, or other CPU flags. See [M2-CONTRACT.md](M2-CONTRACT.md) for the precise accepted subset.

```sh
cargo run -- sample.exe translated.rs
rustc translated.rs -o translated
```

Only use independently authored or appropriately licensed fixtures. See [ARCHITECTURE.md](ARCHITECTURE.md) and [ROADMAP.md](ROADMAP.md) for boundaries and validation gates.

The authored `scripts/make_pe32_fixture.py` builds import-free PE32 cases within that profile. CI runs them on a GitHub hosted Windows Server 2025 runner and compares their exit status and empty stdout/stderr with generated Linux ELFs. These are small modern Windows fixtures, not evidence of Windows XP–7 compatibility.

## Status

M0, M1 and the bounded M2 slice are in draft review. CI exercises 15 authored Windows/Linux cases, including taken and untaken outcomes for each supported branch. The 99% compatibility objective is aspirational and has no measured corpus result.

## License

Original code is licensed under either MIT or Apache-2.0, at your option.
