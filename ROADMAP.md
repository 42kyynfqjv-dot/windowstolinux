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

SUB-514 measured unmodified MSVC output: both custom-entry and ordinary CRT builds
run on Windows but conversion rejects. compiler/RESULTS.md identifies loader and
register/stack gaps. Next bounded linker-image intake contract precedes the observed
ABI/instruction slice; ordinary CRT remains a separate larger milestone.

SUB-515 is narrowed to design/test-only validation before production changes; see
[SUB515-LINKER-DESIGN.md](SUB515-LINKER-DESIGN.md). The proposed profile separates
intake from emission, excludes loader/debug metadata from immutable reads, and
requires typed relocation provenance. Medium contract review precedes production
intake; actual compiler translation additionally requires the measured ABI slice
and pointer-preserving stack state. At that design checkpoint Windows actual-base
evidence was absent; SUB-516 adds a separately instrumented launch observation.

SUB-516 implements gated structural intake; see [SUB516-INTAKE.md](SUB516-INTAKE.md).
Compiler-image emission remains blocked pending typed pointer/ABI integration.

SUB-517 defines image-owned pointer values, saved-ESI ownership and the exact
remaining compiler ABI gates in [SUB517-TYPED-ABI-DESIGN.md](SUB517-TYPED-ABI-DESIGN.md).
Its independent model is test-only. Next: medium contract review, then bounded
typed-core integration with the emission barrier retained until all listed
ABI/form and unchanged-compiler Windows/Linux gates pass. No compiler-produced
PE has yet been translated successfully; ordinary CRT support remains separate.

SUB-518 implements the bounded typed/compiler ABI path described in
[SUB518-IMPLEMENTATION.md](SUB518-IMPLEMENTATION.md). Its substantive acceptance gate
is unchanged MSVC PE -> Rust -> ELF execution matching the original Windows output.
Next medium review audits that evidence and production proof boundaries before any
additional compiler/CRT coverage.

SUB-519 measures four frozen C variations without production changes: three retain
baseline structure and pass cross-platform conversion/execution; one three-argument
helper rejects. See [compiler/variations/RESULTS.md](compiler/variations/RESULTS.md).
The next bounded semantic gate is third caller-owned argument ADD and six-word
cleanup, with Astra High contract/core work before medium review.

SUB-520 implements the two measured three-argument forms under
[SUB520-THIRD-ARGUMENT.md](SUB520-THIRD-ARGUMENT.md). The unchanged three-argument
compiler program must now pass the same hashed-PE conversion/execution gates.
Next is focused medium review of ownership, unknown cleanup flags, exact forms
and the final CI artifact provenance; no broader stack or CRT support is implied.

SUB-521 measures three frozen structurally varied C sources. All originals meet
Windows expectations; all conversions reject. See compiler/structures/RESULTS.md.
Shared calls expose the smallest next gate: exact two-word ADD ESP cleanup, retaining
unknown flags and owned Data constraints. Nested tail transfers and conditional
movement/register support remain separate larger prerequisites. No new translated
comparison is claimed from the three rejections.

SUB-522 implements exact two-word ADD ESP cleanup using the reviewed ownership
and unknown-flag transition. See SUB522-TWO-WORD-CLEANUP.md. The unchanged shared
compiler experiment must now translate, while nested and conditional experiments
retain rejection. Next is medium review of the narrow production/evidence change;
backward tail transfers, argument stores and multi-register semantics remain open.

SUB-523 specifies the exact ECX/EDX and signed conditional-selection contract in
SUB523-CONDITIONAL-DESIGN.md, with an independent test-only model. Production
conditional.c rejection remains until medium contract review and bounded typed
state/call-clobber integration gates. The fixed entry's failure path alone cannot
validate both CMOV outcomes; independent native boundary cases are required.

SUB-524 implements the reviewed conditional contract and makes the unchanged
conditional.c compiler artifact a required same-PE Windows/Linux acceptance gate.
See SUB524-CONDITIONAL-IMPLEMENTATION.md for exact forms and independent native
boundaries. Next is medium review of production effects and artifact evidence.
The remaining frozen nested program rejects stack-copy/argument-store/backward
tail-transfer forms; any such expansion needs a separate bounded architecture
design, not another unmeasured register/opcode increment.

SUB-525 specifies the fixed nested-program prerequisites in SUB525-NESTED-DESIGN.md.
Eight independent test-only functions exercise scalar stack copies, borrowed
argument writes and preserved tail-return context. Production remains rejecting;
next medium review must assess the routine-graph and ownership implementation gates.

SUB-526 implements the reviewed bounded nested compiler path; see
[SUB526-NESTED-IMPLEMENTATION.md](SUB526-NESTED-IMPLEMENTATION.md).
CI now requires eight unchanged compiler programs, including nested.c, alongside
102 authored comparisons and18 launch samples. Medium production review is next.

SUB-527 froze eight held-out compiler configurations before measurement; all eight
initially rejected. The recorded first results remain historical evidence in
[compiler/heldout/RESULTS.md](compiler/heldout/RESULTS.md). SUB-528/529 introduced
checked non-emitting inspection, and SUB-530 reviewed the local-frame contract.

SUB-531 implements two owned scalar local words and a private importless execution
path under [SUB531-LOCAL-IMPLEMENTATION.md](SUB531-LOCAL-IMPLEMENTATION.md). The frozen
structure.c PE must now independently convert on Windows and Linux to identical
Rust, then execute as Linux ELF with empty stdout/stderr and exit12, matching the
same hashed Windows artifact. Source, compiler flags and PE bytes are unchanged.
The other seven held-out programs retain explicit conversion rejection gates.

Inspection always reports `emission_allowed: false`; it is independent of the
complete graph/ABI/local proof required for conversion. Writable/global/byte memory,
loops, ordinary CRT and PE32+ remain unsupported. CI preserves eight earlier compiler
comparisons,102 authored comparisons and18 launch checks alongside the one new
structure-program comparison. Three historical Windows timeout causes remain
unresolved; persistent diagnostics and failure propagation remain enabled.

Next: medium production/provenance review of local-versus-argument byte-form dispatch,
protected ownership and uninitialized state, importless proof isolation and the
unchanged structure artifact. Subsequent capability work requires a separate bounded
gate driven by the remaining held-out failures. XP/7 and general apps remain unvalidated.

SUB-531 medium review adds the missing untaken-uninitialized production regression.
Next: bounded Astra High byte-local contract/model for unchanged held_buffer, whose
PUSH ECX storage, byte MOV/MOVZX, INC AL and POP ECX require explicit partial-byte
initialization, register/flag and ownership semantics. Keep production rejection
until separate reviewed implementation and same-PE exit132 acceptance gates.

SUB-532 proposes owned byte-local storage and partial-register/per-flag semantics
in [SUB532-BYTE-LOCAL-DESIGN.md](SUB532-BYTE-LOCAL-DESIGN.md). Eight independent model
functions and exact unchanged-buffer artifact checks are design evidence only.
Production still rejects held_buffer; medium contract review precedes implementation.
