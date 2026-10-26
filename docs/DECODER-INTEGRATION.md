# SUB-505 production decoder decision

Decision: integrate the reviewed strict iced adapter into the converter. The
SUB-504 trial and medium review established bounded acceptance/IR/source parity,
independent expected IR for all supported forms, prefix/truncation rejection and
resource/target limits. The selected benefit is a maintained typed decoding API
for later explicitly reviewed extensions. This does not provide wider execution
semantics or establish a performance advantage.

The cost is two locked converter dependencies: iced-x86 1.21.0 with only `std` and
`decoder` enabled, and lazy_static 1.5.1. `instr_info` is unnecessary in production.
On this Linux workspace/stable Rust 1.99.1, unstripped default release converter
size changed from 494,168 to 717,080 bytes (+222,912). Cargo's observed release
build duration was 0.43s before and 2.93s after (the latter compiled both added
crates). These single local observations are not controlled cold-build or runtime
benchmarks. The dependency/size cost is acceptable for the converter; generated
application source is unchanged. Required exact notices are in the root
THIRD-PARTY-NOTICES.md and dependency checksums are in Cargo.lock.

## Production boundary

`src/control/decoder.rs` is the single production instruction adapter. The root
CLI calls it through `control::decode_instruction`; no feature flag or silent
fallback selects another decoder. The former handwritten byte decoder is retained
as `oracle_instruction` under `cfg(test)` only. The isolated comparison harness
explicitly calls that oracle for its baseline and the production `decode` path
for its candidate. Independent literal IR assertions call the same production
instruction entry point. There is no copied trial adapter that could drift.

The exact original first-byte/form/length/operand whitelist remains in force.
Legacy prefixes, equivalent alternate encodings, other registers, memory forms,
near/backward branches and other conditions remain unsupported. Invalid or
truncated input is rejected before operand metadata is read; targets must agree
with checked entry-relative arithmetic. No byte skipping or resynchronization
occurs. Instruction errors report the entry-relative offset and a reason such as
unsupported encoding, invalid/truncated instruction or backward branch. These
human-readable reasons are not a promised machine-stable error API. Shared graph
and semantic errors retain their existing diagnostics and rejection policy.

Both successors, instruction overlaps, slice bounds, unknown state, 1,024-operation
limits and exit range 0–255 remain enforced by the existing implementation. The
32-bit offset guard is unreachable from zero within this bounded forward graph;
a future unbounded/address-space design must revisit it explicitly.

The emitter and independent Flags implementation are unchanged. Generated Rust
contains no iced/yaxpeax dependency and compiles directly with rustc to native ELF.
The converter's dependency license obligations apply to converter distribution;
these libraries are not copied into the generated application. No Wine code or
runtime dependency is introduced.

## Verification and limits

Run root formatting, Clippy and tests with the locked dependency graph, then the
existing isolated evaluation commands in DECODER-ADAPTER-TRIAL.md. CI uses locked
root builds and runs the actual production converter for all 34 authored PEs.

Local pre/post CLI comparison with ecf21f6 produced byte-identical Rust for all 34
positive fixtures; both binaries reject exit 256. The full comparison harness
retains 181,248 mutation calls and 131,072 first-two-byte/offset comparisons, with
fresh decode/IR/source determinism and explicit malformed/policy boundary tests.
Root suite: 24 functions. Isolated suite: 19 functions, comprising 13 inherited
control tests, 3 original decoder comparisons and 3 adapter/oracle tests. Do not
count the inherited tests twice as unique coverage. The additional root test
checks offset and reason for unsupported, truncated and backward-branch errors.

Original Windows versus generated Linux checks remain 34 small authored cases on
Windows Server 2025. No XP/7 or application compatibility claim follows. Shared
graph/flags/emitter code is not independently verified by decoder parity. Mutation
counts include duplicates and are not exhaustive x86 testing. Dependency upgrades
must rerun all rejection/parity gates and review notices; automatic broadening of
the accepted subset is prohibited.

Next: Sol medium review of production/test path selection, locked features,
notices and exact final CI evidence. Then define a bounded M2 arithmetic extension
with independent flag truth tables and Windows/Linux fixtures; do not combine it
with memory, APIs or general PE loading. Production integration alone does not
complete the wider M2 milestone.

## Post-integration review

Source inspection confirms production decode selects iced while the retained
handwritten oracle is cfg(test) only; the harness compares those distinct paths.
Cargo's locked feature graph confirms only std/decoder plus lazy_static in the
converter. Root notices include both exact license texts. The emitter and flag
module have no integration diff; pre/post CLI source equality and final CI provide
the bounded emission evidence. No production regression was reproduced.

The roadmap now prioritizes bounded call/return structure (SUB-506) over another
immediate arithmetic opcode, with a separate Astra High soundness/design gate.
See ROADMAP.md; this review adds no execution support.
