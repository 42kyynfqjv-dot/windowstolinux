# Foundation and first native translation deliverable

The original first assignment asks for a Rust foundation, Linear tracking, working
PE32-to-IR-to-Rust-to-ELF logic, original-program comparison and a reviewable PR.
Those narrow acceptance conditions have evidence in draft PR1:

- Cargo workspace (one production package), modular loader/control/stack/emitter,
  locked decoder dependency and independent reuse evaluation/provenance.
- Required open-source policy/license/architecture/contribution/security/changelog
  files, CI and existing Linear milestones/issues.
- Real PE32 parsing, instruction recovery and typed operation enum; generated Rust
  compiled and executed as native ELF, no original byte decoding/Wine/AI runtime.
- Exact exit and output comparisons against original authored PEs on genuine
  Windows Server2025:70 baseline plus32 corpus instances, limited to the documented
  profile. Corpus variants are four families, not32 separate semantic discoveries.
- PR remains draft and unmerged as authorized. Human acceptance/merge is a separate
  decision; no technical dependency forces it to continue authorized engineering.

No concrete mandatory gap remains for the *narrow first vertical slice*. M0's
landscape review is scoped to the implemented decoder/behavior decisions; the
broader listed lifting frameworks still require evaluation before major recovery
subsystems. This does not mark the entire M0/M1 roadmap, XP7 mission or general
compiler complete. PE32+, x64, broad memory/IR/runtime support, relocations/TLS,
representative applications and historical Windows validation remain open. The
single-package workspace is a foundation, not the planned mature modular workspace.

The key evidence gap is that all executed images are hand-assembled. Next gate:
create an independently authored tiny C program with a pinned available Windows
compiler/linker, custom entry point and no proprietary redistributed components;
record source/build provenance, PE metadata, disassembly and original observations.
Run the current converter and record every unsupported instruction/startup/API
feature without weakening rejection. This is a substantive compatibility boundary
measurement, not another review-only milestone or a claim that it already converts.

Prefer a regular-file ASCII output/helper computation matching the existing
observation domain. Compare generated fixture instruction/ABI assumptions with
actual compiler output, then choose the smallest justified implementation slice
needed to convert that executable end to end. Characterization can run at medium;
new memory/control-flow/ABI design goes to Astra High with a concrete scoped issue.
No new paid resource or Windows licensing is required for an existing authorized
CI toolchain; report availability if it is absent. No merge/release or XP7 claim.
