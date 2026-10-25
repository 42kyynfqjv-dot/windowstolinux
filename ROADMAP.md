# Roadmap

- M0: Rust workspace, strict PE parsing, CI, project governance, licensing.
- M1: one actual PE32 program translated to Rust, built to ELF, and compared with its Windows execution.
- M2–M3: instruction semantics and executable structure.
- M4–M7: Windows compatibility runtime, dynamic observation, and desktop behavior.
- M8–M10: PE32+/x86-64, measured corpus expansion, optimization and reproducible releases.

No milestone is complete merely because generated Rust compiles. Each compatibility claim needs a versioned corpus, original execution baseline, and published comparison method.
