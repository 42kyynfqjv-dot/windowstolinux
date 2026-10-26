# Architecture

For the current implementation audit, profile boundaries and next integrated
milestone, see [CLI critical path](docs/CLI-CRITICAL-PATH.md). The milestone entries
below include historical checkpoints; later entries supersede earlier barriers.

The target design separates PE parsing, instruction lifting, typed intermediate representation, Rust emission, and a Rust-native Windows compatibility runtime. This repository currently contains a narrow entry-path experiment in one Rust binary. That shape is temporary; unsupported semantics are rejected instead of guessed.

The authored-image loader checks DOS and PE signatures, PE32/x86 console shape, section table and image bounds, and executable file-backed entry bytes. It accepts one executable code section, optionally followed by one adjacent read-only initialized-data section under [SUB509-MAPPING.md](SUB509-MAPPING.md), and requires all 16 PE data directories to be empty. Outside the SUB-512 extension it rejects imports; it always rejects TLS, relocations, exports, resources, and every other declared directory rather than ignoring their startup effects. It also rejects DLL characteristics and mappings outside that exact profile. This is a deliberately restricted image profile, not a general PE loader.

The production adapter in `src/control/decoder.rs` applies an exact byte/form whitelist over iced-x86 1.21.0. Graph validation and emission are in `src/control.rs`. They support MOV/ADD/XOR/CMP/RET, forward direct CALL and forward short JC/JNC/JZ/JNZ/JL/JGE, with carry, zero, sign and overflow flag semantics. Both successors are decoded; overlapping instructions, unknown entry state on the deterministic execution path, unsupported code, and backward branches are rejected. Non-return edges form an acyclic graph. Internal RET restores its saved continuation; entry RET marks the entry sentinel terminal and exits. Exact PUSH imm32, MOV EAX,[ESP+4] and LEA ESP,[ESP+4] use one tagged stack for caller-owned data and opaque return words. `src/control/stack.rs` implements checked transitions shared by validation and generated Rust; independent literal and concrete-byte tests check that implementation. Capacity is 128 additional words. Absolute ESP and return-address values remain unobservable. Conservative all-path call nesting is capped at 32; decoding and dynamic execution are capped at 1,024 instructions. Generated Rust contains statically decoded operations and fixed successors. No original bytes are decoded at runtime.

The converter evaluates the deterministic accepted path before emission and rejects return values above 255. Linux cannot faithfully represent larger Windows process exit codes. Memory access is restricted to the caller-argument load and exact immutable A1 EAX loads under [SUB510-IMMUTABLE-LOAD.md](SUB510-IMMUTABLE-LOAD.md). The validated Pe resolver checks whole-width VA/RVA/file provenance and lowers immutable loads to flags-preserving constants before validation/emission. General stack/memory access, APIs, other conditions and other flags remain unsupported. Flat aligned valid stack storage, no address wrap/faults and no asynchronous interference are explicit preconditions, not loader-proven guarantees; see [SUB508-IMPLEMENTATION.md](SUB508-IMPLEMENTATION.md). The precise boundaries are in [M2-CONTRACT.md](M2-CONTRACT.md) and [SUB502-CONTRACT.md](SUB502-CONTRACT.md). Sixty-three authored cases compare output and exit status on Windows Server 2025 and generated Linux ELFs; XP/7 behavior remains unvalidated.

Architecture decisions: favor explicit machine state and deterministic translation; preserve unsupported cases as errors; use versioned, independently authored fixtures; compare original and translated behavior only when both are actually executed. Research candidates for later evaluation include Remill, McSema, DDisasm, Ghidra, Wine, and ReactOS, subject to technical and license review. Third-party dependency notices are included; no dependency implementation source is vendored.

## Wine and Proton as references

Wine and Proton are useful sources of compatibility questions, API edge cases, and comparative test ideas. They do not define this converter's execution architecture. The intended deliverable is a native Linux ELF compiled from mechanically translated Rust application logic plus Rust-native Windows API support where needed. A native API implementation is distinct from a dynamic fallback that executes original x86 bytes; any fallback must be identified and measured separately.

Before reusing implementation code or tests, review the exact component and file license and record provenance. [Proton's license notice](https://github.com/ValveSoftware/Proton/blob/proton_11.0/LICENSE) says its components carry separate licenses; [Wine's LGPL 2.1 text](https://github.com/wine-mirror/wine/blob/master/COPYING.LIB) is another relevant constraint. Translating code into Rust does not erase license obligations. Keep original project code under MIT OR Apache-2.0 and independently author tests from documented behavior unless reuse is reviewed. Wine behavior can guide investigation, but a genuine Windows execution remains the reference for compatibility claims.

The Windows API support library should be independently implemented in Rust from documented contracts and independently authored observable tests. Record the source of each behavioral requirement and compare against genuine Windows execution where possible. Studying Wine or Proton can reveal questions to test, but a rewrite informed by implementation details is not automatically independent; do not claim a clean-room process unless one was actually followed. No Wine or Proton source is requested for import. If source reuse is proposed later, review the exact component license and distribution obligations before changing this policy.

## Decoder reuse evaluation

[SUB-503 evaluation](docs/DECODER-EVALUATION.md) cross-checks iced-x86 and yaxpeax against the current subset in an isolated tool workspace. The reviewed trial now underpins the [production integration](docs/DECODER-INTEGRATION.md); the handwritten decoder remains a test-only regression oracle. Execution policy remains the same.

[SUB506-CONTRACT.md](SUB506-CONTRACT.md) defines the restricted return-address abstraction and its excluded stack/memory behavior.

SUB-512 extends the loader with one strict import/IAT in a third loader-owned
section. Image-aware FF15 decoding, hypothetical branch-state validation and
native output emission are described in [SUB512-OUTPUT.md](SUB512-OUTPUT.md).
General indirect calls and guest access to import memory remain rejected.

SUB-516 adds a separate strict linker-image Candidate (src/linker.rs), selected
before parsing by DLL characteristics8540. Its only terminal API rejects emission;
metadata acceptance never grants access to the authored-image emitter. It validates
imports/debug/HIGHLOW ranges under SUB515-LINKER-DESIGN.md. Typed pointer provenance
and compiler ABI semantics remain required before translation; see SUB516-INTAKE.md.

[SUB517-TYPED-ABI-DESIGN.md](SUB517-TYPED-ABI-DESIGN.md) specifies the proposed
image-owned typed values and saved-ESI/return ownership. Its Python model is
test-only; production has no new ABI forms or relocation-aware emission.

SUB-518 supersedes the design-only/unconditional-barrier checkpoint above with
private per-Candidate typed validation and static Rust emission. See
[SUB518-IMPLEMENTATION.md](SUB518-IMPLEMENTATION.md). Every graph path and relocation
operand must validate before output; no conversion to the old scalar Pe emitter.

SUB-524 extends only the linker-profile shared typed State with ECX/EDX and the
six exact scalar forms in [SUB524-CONDITIONAL-IMPLEMENTATION.md](SUB524-CONDITIONAL-IMPLEMENTATION.md).
Internal calls retain decoded effects; external _write invalidates volatile
ECX/EDX and flags. New argument loads and arithmetic require scalar tags, with
complete separate all-path states and unchanged ownership/resource barriers.

SUB-531 adds a private owned `Importless` intake capability distinct from inspection
JSON. For the existing DLL8540 family, an absent import directory explicitly selects
semantic importless intake; an advertised import selects the strict imported profile.
Failures are never retried against another parser. Closed debug13 is the only optional
directory; only file-backed RX code and immutable sections are permitted. Only code
bytes reach the existing graph/state proof: no absolute data or IAT capability is
exposed. All paths must validate before constructing private `ProvenProgram` for
emission. Inspection still always reports false emission eligibility.

The shared validator/generated runtime adds Local(owner,token,Option<u32>) and explicit
per-invocation boundary/allocation state. Eight-byte allocation, exact scalar stores,
load/add and cleanup follow SUB530-LOCAL-FRAME-DESIGN.md. Overlapping [ESP+4] load/store
and ADD ESP8 operations select local versus argument semantics from allocation state,
never by fallback after a failed check. Transitions commit machine state only after
success. Bounds, tags and initialization are checked on every path. This adds no
observable absolute ESP, general memory or Windows loader runtime. See
SUB531-LOCAL-IMPLEMENTATION.md for validation and conditional execution assumptions.


The [SUB-552 input profile](research/input/INTEGRATION.md) adds a separate private
production certificate after linker metadata validation. Its IR carries symbolic
unknown runtime values and tagged stack ownership; path-specific modular predicate
refinement proves initialized full reads before deterministic native emission.
Acquisition is a shared native API effect, while application operations come from
decoded instructions. No test model/report can confer this capability.
