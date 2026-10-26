# Roadmap

- M0 foundation and M1 narrow modern-Windows PE32-to-native-ELF slice are in draft review.
- M2 has bounded EAX arithmetic, four flags, forward conditions, direct calls/returns and one-word stack arguments;
  the strict iced adapter is integrated. General stack/data memory is still open.
- M3 now has bounded code plus read-only-data mapping; general executable structure, imports, relocations and indirect calls remain open.
- M4–M7 Windows APIs, advanced execution, instrumentation and desktop behavior remain open.
- M8–M10 x64, representative corpus, optimization and reproducible releases remain open.

Current production evidence:63 authored Windows Server2025/Linux cases. This is
not XP/7 validation or application compatibility; the99% objective is aspirational.
No milestone is complete merely because generated Rust compiles.

## Next native program gate

SUB-508 implements the reviewed [SUB507-DESIGN.md](SUB507-DESIGN.md) contract:
exact PUSH imm32, MOV EAX,[ESP+4] and flags-preserving LEA cleanup over one tagged
stack. Ten new authored programs exercise arguments, shared/nested helpers, joins
and flags. The independent design prototype remains test-only. See
[SUB508-IMPLEMENTATION.md](SUB508-IMPLEMENTATION.md) for implementation evidence
and conditional native-stack assumptions.

Medium SUB-508 review found no production defect. Added a production-path
regression for multiple caller words: only the nearest word is readable, and
both words must be cleaned before entry RET. Existing fixture arithmetic and
intermediate-result branches were inspected against the actual emitted paths.

SUB-509 implements the bounded two-section profile in [SUB509-MAPPING.md](SUB509-MAPPING.md).
The SUB-509 image retains helper exit12; data became observable in SUB-510.
SUB-510 now implements exact A1 immutable EAX loads with complete four-byte
VA/RVA/file provenance and preferred-base/flat-DS/no-fault assumptions; see
[SUB510-IMMUTABLE-LOAD.md](SUB510-IMMUTABLE-LOAD.md). Data can now affect bounded
program results. Medium review reproduced no defect and adds cross-image/context
isolation plus changed-data native evidence. Next SUB-511 designs the smallest
imported console-output contract on Astra High, followed by medium contract review.
Compare primary CRT/Win32 contracts and specify exact output, import/IAT policy,
calling convention, immutable buffers, clobbers and error/short-write behavior.
Production integration requires separate bounded gates. General memory, writes,
dynamic pointers and rebasing remain unsupported; Server2025 is not XP/7 evidence.

SUB-511 selects a conditional one-import legacy CRT `_write` design; see
[SUB511-OUTPUT-DESIGN.md](SUB511-OUTPUT-DESIGN.md). Original Windows and separate
native support probes are prerequisites, not translated output evidence. Medium
contract review precedes bounded SUB-512 production integration. Imports remain
unsupported in the converter.

SUB-512 now implements the bounded one-import output profile;
[SUB512-OUTPUT.md](SUB512-OUTPUT.md) supersedes the earlier design-only checkpoint.
Six actual translated output fixtures extend the63-case baseline. Next medium
review audits parser/argument/effect state and evidence before further expansion.

SUB-512 medium review adds shared-helper evidence and corrects the malformed-case
count (35 historical,40 now). Next prioritize independent corpus/differential
hardening within existing semantics before additional APIs or instructions.

SUB-513 adds32 deterministic independent corpus instances in four composition
families plus160 adversarial mutations; see corpus/README.md. Original70 native
comparisons remain separate. Further hardening should follow reproduced failures
and corpus diversity, before more APIs.

Foundation/first vertical-slice acceptance is reconciled in
[docs/FOUNDATION-M1-ACCEPTANCE.md](docs/FOUNDATION-M1-ACCEPTANCE.md). Next substantive
gate: compiler-produced authored C PE characterization and fail-closed gap inventory,
then a measured implementation slice toward converting that real compiler output.
