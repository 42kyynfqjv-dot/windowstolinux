# SUB-504 gated iced adapter trial

Historical evaluation/trial record. Current production integration and test counts are documented in [DECODER-INTEGRATION.md](DECODER-INTEGRATION.md).

The trial preserves the existing instruction subset. It is compiled only by tests
in the isolated `tools/decoder-eval` workspace. The root CLI still selects the
handwritten decoder and has no new dependency or runtime switch. This is evidence
for a later integration decision, not approval to replace production decoding.

## Boundary and implementation

`adapter.rs` decodes 32-bit instructions using pinned iced-x86 1.21.0 with default
validation (`DecoderOptions::NONE`). It first whitelists the original first byte,
then checks exact `Code`, encoded length, operand kinds and EAX registers. This
byte check matters: iced can normalize ignored prefixes while returning the same
Code. Every legacy prefix is rejected, including segment overrides and REP. Exact
forms remain B8 id, 05 id, 3D id, 31 C0, C3, and 72/73/74/75/7C/7D cb. Alternate
encodings with equivalent arithmetic meaning are still outside policy.

Invalid/truncated decodes return an error before operand metadata is used. The
trial does not skip invalid bytes or resynchronize. Short branch displacement is
checked as signed rel8; negatives are rejected. The target is a checked addition
to the instruction end and must agree with iced's IP-relative result. IP is the
entry-relative byte offset, not a virtual address. Only offsets representable in
u32 are accepted by the trial; bounded forward graph traversal from zero cannot
reach that limit within the existing 1,024-instruction cap. A future general
loader/decoder adapter must revisit address-space policy rather than inherit this
assumption silently.

The existing control module was structurally factored into single-instruction
decoding, graph traversal and emission; its byte decoder logic is unchanged.
Production always calls its own decoder. The trial returns the same typed IR and
uses the same graph traversal, validator and emitter, avoiding a second semantic
implementation. Internal parent-module visibility supports the isolated harness;
there is no public IR ingestion interface. Both branch successors are traversed;
overlap, executable-slice bounds, known-state, resource and exit-domain checks
remain shared. Unreachable trailing bytes remain outside the decoding policy.

No library instruction-info semantics are used to calculate flags or execute
instructions. Original independently implemented flags remain authoritative.
Generated source contains only the existing Rust arithmetic/control-flow code;
it contains no iced, yaxpeax, original-byte decoder, or Wine dependency.

## Reproducible evidence

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
python3 scripts/check_fixture_manifest.py
python3 scripts/export_decoder_cases.py
cargo fmt --manifest-path tools/decoder-eval/Cargo.toml --check
cargo clippy --manifest-path tools/decoder-eval/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path tools/decoder-eval/Cargo.toml --locked -- --nocapture
```

- 34 authored streams have identical complete IR and byte-identical emitted Rust
  through the two decoder paths. Emission is repeated for determinism.
- 181,248 single-byte mutations of the corpus, plus every proper stream
  truncation, agree on decode acceptance, full IR when accepted, and emission or
  semantic rejection. Mutation counts include replacements equal to the original
  byte and repeated fixture bytes; they are not counts of unique programs.
- All 65,536 first-two-byte combinations with zero-filled remaining bytes are
  checked at offsets 0 and 17: 131,072 single-instruction acceptance/IR comparisons.
  This is exhaustive for that bounded matrix, not arbitrary 15-byte x86 input.
- Independently specified checks require rejection of every legacy prefix on each
  supported form, all proper truncations of those forms, alternate encodings,
  other registers, memory, near/backward branches and other conditions. Graph
  checks cover target overlap, out-of-bounds targets and an unsupported untaken
  path. Known-state and exit-256 rejection, zero/max-positive displacement and
  the exact 1,024/1,025-instruction boundary are exercised.
- The isolated suite has 18 test functions: 3 adapter tests, 3 prior decoder
  comparisons and 12 inherited production-control tests. The root suite has 23
  functions; inherited tests are not unique additional production coverage.

A local cross-revision check compiled the previously published converter at
273d179 and this refactor, then generated all fixtures through both: the 34 positive
sources were byte-identical and both rejected exit 256. Existing CI compiles and
executes production-generated source on Linux and runs the original authored PE
on Windows. Trial source equality connects the adapter to those same 34 outputs;
the trial itself is not a replacement CLI or a second PE loader. Windows evidence
is Windows Server 2025, not XP/7. No application compatibility, broad fuzz-safety,
throughput or independent verification of shared graph/emitter logic is claimed.

## Licenses and decision

Exact notices for every locked evaluation dependency, including build dependency
autocfg, are in [THIRD-PARTY-NOTICES.md](../tools/decoder-eval/THIRD-PARTY-NOTICES.md).
The iced notice is copied from the exact v1.21.0 tag; other notices are from the
checksum-pinned crate archives. MIT is selected for dual-license dependencies;
yaxpeax's 0BSD notices are retained. No dependency implementation is vendored or
ported. Original adapter/tests remain MIT OR Apache-2.0.

The measured trial passes its bounded parity gates. No production correctness
failure was reproduced in this pass. Next is a focused Sol medium review of the
whitelist, test independence, shared-code extraction and notices. After that,
make a separately scoped production-integration decision with the same rejection
matrix and final-commit Windows/Linux checks; do not widen execution semantics
while integrating. Broader M2 and M3–M10 work remains open.

## Medium review follow-through

The comparison counts were checked against the actual loop bounds: corpus byte
lengths total 708, hence 708 * 256 = 181,248 mutation calls; the instruction grid
is 256 * 256 * 2 = 131,072 calls. These are comparisons, including duplicates.
The review strengthens determinism by decoding afresh before comparing IR and
source, and adds literal expected IR for all eleven supported forms at offset 17.
Immediate bit patterns and each branch condition/polarity/absolute target are
asserted without calling the handwritten decoder for expected values.

Rejection equivalence means both decoders fail, or equal IR reaches the same
shared semantic rejection. Error strings are intentionally not compared; this
is not diagnostic-category parity. Shared graph/emitter behavior remains outside
independent decoder-oracle coverage. All six packaged dependency notice texts
were compared verbatim to pinned archives; iced retains its tagged upstream
notice. The production decoder and execution policy are untouched by this review.

Next integration decision: pin iced in the converter only after deciding whether
the maintenance benefit warrants its dependency/build cost. Preserve the exact
byte whitelist, fail closed on decoder/policy disagreement, retain the independent
handwritten oracle under tests, and require malformed/prefix/target/resource
regressions plus identical fixture IR/source and final Windows/Linux CI. No silent
fallback, resynchronization or new instruction acceptance. Use Astra High for the
production boundary/design change, then medium for verification and documentation.
