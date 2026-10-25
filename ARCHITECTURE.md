# Architecture

The target design separates PE parsing, instruction lifting, typed intermediate representation, Rust emission, and a Rust-native Windows compatibility runtime. This repository currently contains a narrow entry-path experiment in one Rust binary. That shape is temporary; unsupported semantics are rejected instead of guessed.

The loader checks DOS and PE signatures, COFF machine type, optional header shape, section table bounds, and executable file-backed entry bytes. It does not yet validate imports, relocation tables, TLS, overlapping sections, image memory layout, or execution permissions beyond the section flag.

The decoder recognizes four x86 forms and requires `ret` within 1,024 instructions. The generator implements 32-bit wrapping addition. It does not model flags, memory, stack, calls, branches, exceptions, or the process entry ABI. Generated Rust returns EAX from a function and maps its low byte to an ELF process exit code for compiler experimentation. This mapping is not a claim about original PE process behavior.

Architecture decisions: favor explicit machine state and deterministic translation; preserve unsupported cases as errors; use versioned, independently authored fixtures; compare original and translated behavior only when both are actually executed. Research candidates for later evaluation include Remill, McSema, DDisasm, Ghidra, Wine, and ReactOS, subject to technical and license review. No third-party source has been copied.
