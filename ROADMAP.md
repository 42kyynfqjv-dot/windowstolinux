# Roadmap

- M0: Rust workspace, strict PE parsing, CI, project governance, licensing.
- M1: one actual PE32 program translated to Rust, built to ELF, and compared with its Windows execution.
- M2: bounded carry/zero/sign/overflow flags, CMP and forward JC/JNC/JZ/JNZ/JL/JGE slice in draft review; wider instruction semantics remain open.
- M3: executable structure, imports and relocation semantics remain open.
- M4–M7: Windows compatibility runtime, dynamic observation, and desktop behavior.
- M8–M10: PE32+/x86-64, measured corpus expansion, optimization and reproducible releases.

No milestone is complete merely because generated Rust compiles. Each compatibility claim needs a versioned corpus, original execution baseline, and published comparison method.

Next bounded M2 step: use the reviewed [gated decoder adapter trial](docs/DECODER-ADAPTER-TRIAL.md) to decide on a separately scoped integration that preserves the current accepted subset. Broad x86 semantics and later milestones remain open.
