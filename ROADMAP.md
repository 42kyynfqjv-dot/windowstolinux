# Roadmap

- M0 foundation and M1 narrow modern-Windows PE32-to-native-ELF slice are merged.
- M2 has bounded EAX arithmetic, four flags, forward conditions, direct calls/returns and one-word stack arguments;
  the strict iced adapter is integrated. General stack/data memory is still open.
- M3 now has bounded code plus read-only-data mapping; general executable structure, imports, relocations and indirect calls remain open.
- M4–M7 Windows APIs, advanced execution, instrumentation and desktop behavior remain open.
- M8–M10 x64, representative corpus, optimization and reproducible releases remain open.

Current production gates:12 unchanged compiler-program comparisons,102 authored
Windows Server2025/Linux comparisons and18 original-only launch checks. Four
held-out capabilities remain rejected. This is not XP/7 validation or general
application compatibility; the99% objective is aspirational.
No milestone is complete merely because generated Rust compiles.

## Current startup prerequisite

SUB-546's [accessor closure decision](research/crt/ACCESSOR-CLOSURE.md) is no-go:
the existing internal API description and separate probes do not establish the
external effect frame needed to compose the real call with owned-cell/sentinel
research components. Next: bounded runtime-specific resolved-target effect analysis
with complete control-flow/effect coverage or a precise unresolved dependency.
Astra High for that proof decision, then medium review. Ordinary CRT stays blocked;
no further isolated cell implementation is a substitute for closure.

## Historical implementation checkpoints

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
in [SUB532-BYTE-LOCAL-DESIGN.md](SUB532-BYTE-LOCAL-DESIGN.md). Nine independent model
functions and exact unchanged-buffer artifact checks are design evidence only.
Production still rejects held_buffer; medium contract review precedes implementation.

SUB-533 implements the reviewed byte-local contract. See
[SUB533-BYTE-IMPLEMENTATION.md](SUB533-BYTE-IMPLEMENTATION.md): the unchanged buffer
program now requires same-PE Windows/Linux empty output/exit132. Ten compiler
comparisons,102 authored pairs and18 launches are required; six held-out conversions
remain rejected. Next is medium production/provenance review of partial values,
per-flag knowledge, ownership and exact artifact evidence.

SUB-534 proposes a complete straight-line read/add/return proof for the unchanged
initialized array program, under [SUB534-IMAGE-READ-DESIGN.md](SUB534-IMAGE-READ-DESIGN.md).
Nine independent model tests and exact array/loop artifact checks add design evidence;
production still rejects both. A writable section becomes usable only after checked
full-word provenance, loader-write exclusion and a complete no-write/no-escape proof.
Next: medium contract review, then separately gated production implementation for
same-PE exit9. Loops, ordinary CRT, PE32+ and general memory remain separate work.

SUB-535 implements the reviewed private initialized-data read/add/return profile.
See [SUB535-IMAGE-READ-IMPLEMENTATION.md](SUB535-IMAGE-READ-IMPLEMENTATION.md).
CI now requires unchanged held_array same-PE Windows/Linux empty output/exit9:
eleven compiler programs total, five held-out rejections. Next medium production
and provenance review; loops/general memory/CRT remain separate capability gates.

SUB-536 designs the exact frozen summation loop under
[SUB536-FINITE-LOOP-DESIGN.md](SUB536-FINITE-LOOP-DESIGN.md): rank N-i, stable typed
bound, unsigned comparisons and explicit step/exit gates. Eight independent model
functions and unchanged-artifact traces are test-only evidence; production loop
rejection remains. Medium contract review precedes a separate implementation gate.

SUB-537 implements the reviewed exact finite loop, with structural ranking proof and
native structured-loop output; see [implementation contract](SUB537-FINITE-LOOP-IMPLEMENTATION.md).
CI requires unchanged loop same-PE exit10 agreement alongside eleven prior compiler
comparisons. Four held-out cases remain rejected. Next medium production/provenance
review; general cyclic control flow, CRT/runtime inputs and PE32+ remain separate gates.

SUB-538 maps ordinary x86 CRT startup in [the dependency decision](research/crt/README.md).
The remaining runtime/CRT/file/PE32+ cases stay rejected. Next gate is complete
startup/initializer effect closure for held_crt, followed by a reviewed native entry
contract; no guessed-main bypass or new graph templates.

SUB-548 completes the bounded [original-startup precondition audit](research/crt/COMPOSITION-DECISION.md).
The matched accessor leaf does not close original object lifetime or earlier external
effects. Ordinary CRT remains rejected; stop repeated isolated success probes.
Next: design an independently authored freestanding public-API runtime-input target
with explicit Windows/Linux input mapping, frozen source/flags and independent
oracles. This advances runtime-input validation without skipping the held-out CRT
program's startup. No production capability changes in this decision.

SUB-549 selects a separate [bounded environment-input contract](research/input/CONTRACT.md)
using GetEnvironmentVariableW after declining raw command-line reconstruction.
Seventeen frozen expected vectors compare an authored freestanding Windows program
with a separate native Rust prototype; these are not converter comparisons.
Production rejection remains mandatory. Next review and measured instruction/
unknown-state/owned-buffer prerequisites precede any implementation.

SUB-550 adds a [conditional unknown-input model](research/input/MODEL.md) for the
exact frozen artifact: complete return intervals, guarded initialized bytes and
16-bit digit refinement. Eight independent test functions and artifact binding
add model evidence, no production eligibility. Native bounded input acquisition
and private production ownership/path-state integration remain explicit gates.

SUB-551 implements [isolated bounded native acquisition](research/input/ACQUISITION.md)
using an explicit stable initial-environment/procfs domain. Eight component tests,
17 inherited Windows/component comparisons and five Linux host rejections remain
separate from translation evidence. Next medium review, then private production
state/ownership integration with actual unchanged input PE conversion gates.


SUB-552 adds [production runtime-input integration](research/input/INTEGRATION.md):
checked import/relocation admission, symbolic unknown lengths/UTF16 values, guarded
owned buffers and mechanically emitted native operations. CI now requires the
same unchanged input PE to match Windows in all 17 frozen runtime scenarios, with
identical Rust across hosts/converter environments. This is one new compiler
program, additional to the prior 12. Separate component/model counts are retained.
Next: substantive medium production/provenance review before merge, then evaluate
unknown-state composition diversity. Ordinary CRT, four older held-out programs,
general memory/loops and PE32+ remain outside this input capability.

SUB-553 freezes three structurally different runtime-input C programs before
measurement: reordered guards/join, squared digits, and a pointer/length helper.
All51 original Windows scenarios match independent frozen expectations, but all
three conversions reject. No support is widened. See
[measured barriers and next gate](research/input/diversity/RESULTS.md).
Next recommended Astra design: bounded register-parametric scalar IR and proof
for the unchanged reordered-guard program, preserving unknown-state/ownership
checks. Nonlinear IMUL and helper-pointer calls remain separate prerequisites.

SUB-554 defines [reusable bounded scalar semantics](research/input/scalar/DESIGN.md)
and an independent test-only model for register/width operands, modular predicate
refinement, snapshots, disjunctive joins and owned initialized reads. Eight model
tests exercise register permutations and guard order without production expansion.
Next: medium contract review, then bounded normalization/proof/emission integration
for unchanged guard_join. Nonlinear IMUL and pointer-helper calls remain separate.

SUB-555 [integrates parameterized scalar operations](research/input/scalar/IMPLEMENTATION.md)
for unchanged guard_join, requiring17new Windows/ELF input comparisons.
All51original diversity scenarios remain; squares/helper retain explicit rejection
pending nonlinear value and pointer-call ownership designs. Medium production review
precedes merge. No fixture-result or graph-stencil admission is introduced.

SUB-556: bounded nonlinear scalar design/model in
`research/input/scalar/NONLINEAR.md`; eight new test functions and same-artifact
seven-form inventory. Production squares/helper still reject. Next gate is medium
contract review before private expression/proof/emitter integration and actual
unchanged squares Windows/ELF evidence. See document for resource and proof limits.
