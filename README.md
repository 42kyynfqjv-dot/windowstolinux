# WindowsToLinux

WindowsToLinux is an early research project for deterministic Windows PE to Rust static recompilation. The long-term target is Windows XP through Windows 7 SP1 applications on native Linux, without Wine at runtime. No general application compatibility has been demonstrated.

## Current prototype

`w2l` validates basic PE32/x86 headers, finds a file-backed executable entry point, and translates a single straight-line sequence of `mov eax, imm32`, `add eax, imm32`, `xor eax, eax`, and `ret` into Rust. Unsupported instructions cause an error. This prototype does not implement PE loading semantics, imports, Windows APIs, stack behavior, or a Windows process entry contract. Its generated `main` maps the translated return value to a Linux exit status solely for a narrow compiler experiment; it is not behavioral equivalence with a Windows executable.

```sh
cargo run -- sample.exe translated.rs
rustc translated.rs -o translated
```

Only use independently authored or appropriately licensed fixtures. See [ARCHITECTURE.md](ARCHITECTURE.md) and [ROADMAP.md](ROADMAP.md) for boundaries and validation gates.

## Status

M0 is in progress. M1 requires an executable Windows baseline and comparison of output and exit status. The 99% compatibility objective is aspirational and has no measured result.

## License

Original code is licensed under either MIT or Apache-2.0, at your option.
