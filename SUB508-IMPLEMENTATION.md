# SUB-508 bounded stack arguments

Implements the reviewed [SUB507-DESIGN.md](SUB507-DESIGN.md) contract. New accepted
encodings are exactly `68 id`, `8B 44 24 04`, and `8D 64 24 04`: PUSH imm32,
MOV EAX,[ESP+4], and LEA ESP,[ESP+4]. They preserve all modeled flags. ADD ESP,
POP, PUSH imm8/register, RET imm16, other addresses/operand forms, prefixes and
writes to argument/return storage remain rejected. Primary Intel instruction and
Microsoft convention provenance is recorded in the design. No external source
implementation was imported; original code remains MIT OR Apache-2.0.

## Production behavior

`src/control/decoder.rs` checks exact bytes plus iced code, length, operand kinds,
registers, base/index/scale/displacement and SS metadata. Typed IR distinguishes
PushData, LoadArgument and DropData. The independent handwritten test oracle is
extended only for these forms; literal expected IR checks do not use that oracle.

`src/control/stack.rs` provides one ordered tagged stack to both validation and
emitted Rust. Data words carry the creating invocation's identity; return words
carry a fresh invocation identity, parent identity and opaque continuation. Only
caller-owned data immediately below the current return can be loaded. Cleanup
removes one current-owned top data word. RET cannot cross uncleaned data or a
foreign return; entry RET requires a lone entry tag and known EAX in 0..255, marks
the state terminal and rejects later transitions. Rejected stack transitions leave
state unchanged. Neither numeric ESP nor return-address data is exposed.

Limits remain 32 internal calls and 1,024 decoded/executed operations, with a new
128-word limit for data plus internal returns (entry tag excluded). Conservative
all-path call-depth and instruction-boundary policy remain. Stack/known-state
checks follow the deterministic executed path; valid bytes on an untaken path do
not imply that path's stack state would be supported. There is no abstract state
cache keyed only by instruction offset. Shared and nested helpers revisit their
instructions with the actual invocation and stack state.

Native equivalence is conditional on flat 32-bit stack addressing, aligned incoming
ESP, a valid entry return, accessible 512 bytes below it, no address wrap/faults
and no asynchronous interference. PE parsing does not prove these assumptions.
General ABI, compiler output, native stack faults, memory and APIs remain open.

The emitted application contains Rust stack support and statically decoded match
arms, with no iced/yaxpeax, Wine, AI or runtime instruction decoder dependency.
Validation and emission intentionally share the stack helper; agreement between
them is not an independent semantic oracle. The separate test-only design model,
literal state/IR expectations, concrete byte layout and Windows execution supply
additional evidence. Output source changes from SUB-507 because stack support is
now unified, while existing program observations must remain equal.

## Reproducible checks and cases

Run root `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`
and `cargo test --locked`. Then `python3 scripts/export_decoder_cases.py` and the
same Cargo checks with `--manifest-path tools/decoder-eval/Cargo.toml` (test with
`-- --nocapture` for measured comparison counts). Run
`python3 scripts/check_fixture_manifest.py`; CI contains the full Linux and Windows
execution commands, expected exits and empty stdout/stderr checks.

Local checks pass 34 root functions and 35 isolated functions. The latter comprise
23 inherited production control/stack functions, six decoder/adapter comparison
functions and six separate design-model functions; do not count inherited tests
as unique new coverage. The 52 streams contain 395 decoded records, with 350,208
single-byte mutation calls and 131,072 two-byte/offset comparisons. Mutation counts
include duplicates and shared graph/semantic code; they are not exhaustive x86
verification. Boundary tests cover every ModRM/SIB/displacement byte variation of
the two memory forms, legacy prefixes, truncations, wrong owners/returns, terminal
and failed-transition atomicity, missing/stale arguments, cleanup errors, joins,
128/129 words including CALL, 32/33 calls and 1,024/1,025 executed operations.

All 52 generated Linux ELFs locally pass expected exits and empty output; repeated
translations are byte-identical and standalone `rustc -D warnings` succeeds. The
42 earlier authored cases are retained. Ten new fixture expectations are:

| Fixture | Expected observation |
| --- | --- |
| stack_argument | argument7 +5, exit12 |
| stack_shared | first7 +5 checked equal12, second9 +5 exits14 |
| stack_nested | inner11 +5 checked equal16, restored outer7 +5 exits12 |
| stack_shared_join | shared helper's taken/fallthrough stack join, exit14 |
| stack_flags_zero | ZF preserved despite argument7 load, exit22 |
| stack_flags_carry | CF preserved, exit22 |
| stack_flags_overflow | SF=OF=1, JL untaken, exit11 |
| stack_flags_negative_overflow | SF=0/OF=1, JL taken, exit22 |
| stack_flags_negative | SF=1/OF=0, JL taken, exit22 |
| stack_flags_clear | SF=OF=0, JL untaken, exit11 |

Original Windows execution is a required CI gate, not inferred from Linux results.
The final commit/run and observed OS are recorded in PR/Linear after CI completes.
Modern Windows Server2025 observations do not establish XP/7 or application
compatibility. No 99% corpus measurement exists.

## Next review

Return to Sol medium for a focused review of exact-form policy, owner/return
invariants, terminal state, shared/nested/join paths, fixture intermediate-result
checks and test independence. Verify final-head CI and documentation consistency;
fix confirmed gaps within this slice before selecting another roadmap gate. No
remaining architecture blocker was identified inside the stated execution domain.

## Medium review

No production defect was reproduced in ownership, protected returns, terminal
state, nested/shared contexts or branch joins. Exact byte guards prevent prefixes
and alternate addressing forms before iced metadata is examined. The validator
and emitted match arms call the same checked transitions; shared helper code is
not an independent oracle. Fixture shared/nested intermediate-result checks and
all four SF/OF combinations were inspected. Valid-stack assumptions remain
conditional and do not follow from PE headers.

A new production-path test verifies two caller words expose only the nearest
argument and require two cleanups. Current suites:35 root functions;36 isolated
functions (24 inherited control/stack +6 comparisons +6 design-model functions).
The52 native fixtures and decoder comparison counts are unchanged. Next SUB-509
is bounded two-section code/read-only-data mapping, with Astra High for checked
address/range design and medium review afterward; it is a prerequisite for later
data access/output, not a new API or application-compatibility claim.
