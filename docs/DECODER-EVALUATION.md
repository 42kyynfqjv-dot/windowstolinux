# SUB-503 decoder evaluation

Decision: recommend iced-x86 1.21.0 for a bounded, separately reviewed adapter trial. Keep the current production decoder until that adapter preserves the exact accepted subset and rejection policy. This evaluation adds no production dependency or execution semantics. Both candidates matched the present small corpus; the recommendation is about integration fit, not a broad correctness ranking.

## Reproduction and measured evidence

```sh
python3 scripts/export_decoder_cases.py
cargo test --manifest-path tools/decoder-eval/Cargo.toml --locked -- --nocapture
cargo tree --manifest-path tools/decoder-eval/Cargo.toml --locked
```

The isolated workspace pins iced-x86 1.21.0, yaxpeax-x86 2.2.0 and yaxpeax-arch 0.3.3, including transitive checksums in Cargo.lock. It imports the real production control module in tests and obtains its decode records through a test-only bridge. The corpus is exported directly from the authored fixture generator; no hand-maintained byte copy is used. Entry-offset PE mapping remains covered by the production suite and Windows/Linux matrix; this harness examines instruction streams, not PE loading.

Observed: 34 authored streams, 209 statically reachable decoded records, zero mismatches in length, mnemonic/condition, EAX operands, 32-bit immediate bit patterns and branch targets. Both branch successors are checked. Both candidates produce identical metadata when repeated on the same bytes/IP. Seven empty/truncated encodings fail in both candidates and the subset decoder. Four valid-but-unsupported samples (NOP, operand-size prefix/MOV AX, backward JMP, JLE) decode in both libraries but remain rejected by the production policy.

The evaluation suite has three new comparison tests and twelve inherited production-control tests (15 functions total). Do not add the inherited tests to the separate 23-function production test count as unique new coverage. Runtime evidence remains 34 authored Windows Server 2025/Linux ELF cases; this is neither an application corpus nor XP/7 validation. This bounded comparison is not exhaustive fuzzing, a throughput benchmark or proof that either library handles every malformed stream safely.

## Primary sources and licensing

| Candidate | Primary versioned sources inspected | License and distribution implications |
| --- | --- | --- |
| iced-x86 1.21.0 | [published package](https://crates.io/crates/iced-x86/1.21.0), packaged README/API source; [tagged license](https://github.com/icedland/iced/blob/v1.21.0/LICENSE.txt) | MIT, copyright iced project and contributors. Preserve copyright and permission notice in distributed copies/substantial portions, including a future binary distribution using the library. The crate archive declares MIT but omits a license file; consult the tagged upstream notice. |
| yaxpeax-x86 2.2.0 | [published package](https://crates.io/crates/yaxpeax-x86/2.2.0), packaged README, protected_mode API and LICENSE; [canonical repository](https://git.iximeow.net/yaxpeax-x86/) | 0BSD per Cargo metadata and packaged permission/disclaimer text, copyright iximeow. No copyleft/relinking requirement. Retain provenance even where attribution is not mandated. |
| yaxpeax-arch 0.3.3 | [published package](https://crates.io/crates/yaxpeax-arch/0.3.3), packaged LICENSE | 0BSD, iximeow. |

Selected dependency graph: iced -> lazy_static 1.5.1; yaxpeax-x86 -> cfg-if 1.0.5, num-traits 0.2.19 and yaxpeax-arch; yaxpeax-arch -> num-traits -> build-time autocfg 1.5.1. The packaged manifests declare MIT OR Apache-2.0 for these transitive crates. No dependency is added to the root Cargo.toml; no third-party source is vendored. Exact dependency notices are now assembled in [THIRD-PARTY-NOTICES.md](../tools/decoder-eval/THIRD-PARTY-NOTICES.md); no binary is committed here. Original harness code remains MIT OR Apache-2.0.

## Engineering comparison

| Aspect | iced-x86 | yaxpeax-x86 |
| --- | --- | --- |
| Architecture modes | 16/32/64 via bitness | real/protected/long mode modules |
| Current metadata normalization | typed register/immediate kinds and absolute branch target at supplied IP | register/operand enums; signed ImmediateI32 normalized as bits; relative ImmediateI8 added to instruction end; alias names normalized |
| Broader metadata | instruction-info feature exposes control flow, register/memory access and RFLAGS read/write sets | decoder-focused operand/opcode API; does not expose the same iced instruction-info interface |
| Selected features | std, decoder, instr_info; no encoder/formatter | std; default serialization/format features disabled |
| Invalid input model | invalid Instruction, inspect is_invalid before reading metadata | Result with DecodeError; no instruction metadata on error |
| Maintenance evidence | crates.io update timestamp 2024-01-20 for pinned latest stable 1.21.0; repository accessible and unarchived when checked | crate update timestamp 2026-07-05; repository has changelog/canonical mirror; accessible and unarchived when checked |
| Integration cost | whitelist exact Code/operand forms, then map to existing IR; richer typed metadata reduces ad-hoc normalization | map mode-specific operands/aliases and signed immediates; extra arch traits needed for lengths |

Timestamps are package release/update evidence, not a judgment about current maintainer responsiveness. Upstream README performance claims were not measured here. Decoder tables and feature sets affect build/binary size; this evaluation did not measure comparable stripped release binaries, so no runtime-size or speed winner is claimed. The selected dependency graph above is reproducible. Yaxpeax's README discloses unchecked unsafe operations for performance and differential fuzzing; that is an audit consideration, not a reproduced defect. Both libraries run locally without services; neither supplies full instruction lifting or Windows compatibility.

## Smallest next implementation and gates

Trial an iced adapter behind an explicit test/evaluation gate, preserving the existing IR, control-flow policy and independent Flags helper. Require exact opcode/operand-size/register/prefix whitelisting; decoder validity alone never authorizes execution. Preserve PE bounds, all supported/rejected forms, known-state checks, forward-only targets, overlap rejection, instruction caps and exit domain. Require byte/IR parity on the existing corpus and rejection matrix, deterministic source, all existing Windows/Linux cases, and unchanged generated-runtime dependencies. Record exact third-party notices before distribution. Do not extend opcode coverage in the adapter trial.

The library/policy boundary and handling of prefixes, target recovery and decoder errors are the concrete Astra High design questions for that next trial. Routine verification returns to Sol medium afterward. No current evaluation blocker remains.

SUB-504 follow-through: the [gated adapter trial](DECODER-ADAPTER-TRIAL.md) now checks exact IR/source and rejection parity; production still uses its original byte decoder. The counts above describe the SUB-503 comparison; the combined isolated suite now has 18 test functions.
