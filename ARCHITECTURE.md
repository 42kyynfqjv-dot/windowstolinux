# Architecture

The target design separates PE parsing, instruction lifting, typed intermediate representation, Rust emission, and a Rust-native Windows compatibility runtime. This repository currently contains a narrow entry-path experiment in one Rust binary. That shape is temporary; unsupported semantics are rejected instead of guessed.

The loader checks DOS and PE signatures, COFF machine type, optional header shape, section table bounds, and executable file-backed entry bytes. It does not yet validate imports, relocation tables, TLS, overlapping sections, image memory layout, or execution permissions beyond the section flag.

The decoder recognizes four x86 forms and requires `ret` within 1,024 instructions. The generator implements 32-bit wrapping addition. It does not model flags, memory, stack, calls, branches, exceptions, or the process entry ABI. Generated Rust returns EAX from a function and maps its low byte to an ELF process exit code for compiler experimentation. This mapping is not a claim about original PE process behavior.

Architecture decisions: favor explicit machine state and deterministic translation; preserve unsupported cases as errors; use versioned, independently authored fixtures; compare original and translated behavior only when both are actually executed. Research candidates for later evaluation include Remill, McSema, DDisasm, Ghidra, Wine, and ReactOS, subject to technical and license review. No third-party source has been copied.

## Wine and Proton as references

Wine and Proton are useful sources of compatibility questions, API edge cases, and comparative test ideas. They do not define this converter's execution architecture. The intended deliverable is a native Linux ELF compiled from mechanically translated Rust application logic plus Rust-native Windows API support where needed. A native API implementation is distinct from a dynamic fallback that executes original x86 bytes; any fallback must be identified and measured separately.

Before reusing implementation code or tests, review the exact component and file license and record provenance. [Proton's license notice](https://github.com/ValveSoftware/Proton/blob/proton_11.0/LICENSE) says its components carry separate licenses; [Wine's LGPL 2.1 text](https://github.com/wine-mirror/wine/blob/master/COPYING.LIB) is another relevant constraint. Translating code into Rust does not erase license obligations. Keep original project code under MIT OR Apache-2.0 and independently author tests from documented behavior unless reuse is reviewed. Wine behavior can guide investigation, but a genuine Windows execution remains the reference for compatibility claims.
