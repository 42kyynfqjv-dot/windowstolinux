# SUB-555 bounded scalar integration

The production input IR now parameterizes constants, TEST, CMP and immediate
ADD/SUB by register and comparison width. Existing Copy/Load/MOVZX/LEA operations
already carry register operands. Exact admitted forms normalize into these shared
operations; proof and emission use those operands without fixture names, hashes,
result calculators or whole-graph stencils. The new decoder forms are precisely
the additional guard_join forms inventoried in DESIGN.md.

Proof preserves immutable affine expressions and captured comparison predicates,
full initialized local ranges and per-path symbol/owner state. Arithmetic wraps
modulo32. ADD/SUB conservatively invalidate abstract flags; any subsequent branch
before a supported comparison/test rejects. Native code computes the consumed
CF/ZF bits correctly, with overflow/borrow from the Rust arithmetic primitive.
Other flags have no admitted consumer. CMP AX uses a16bit mask and immediate;
MOVZX reads low16 and writes full32. Partial destination writes stay excluded.
LEA reads source values before the assignment even when destination aliases a
source. Typed API/name/local pointers never become scalars. Existing private PE,
import, relocation, stack, saved-ESI and return gates remain mandatory.

## Evidence gates and counts

88 root functions include two added production tests: literal expected decoded IR
and unsafe reordered-guard paths; six permutations of the scalar register mapping
with ABI input/return adapters. The latter exercises the real proof/emitter and,
on Linux, compiles each generated source and runs five independent expectations
(30 native executions total). This is IR reuse evidence, not permission for any
unlisted machine encoding. Existing86functions,18 authored input native executions
and83malformed-image rejections remain. The separate8Python design tests are unchanged.

The frozen diversity harness now requires guard_join acceptance on both hosts,
identical generated source for the same PE and across converter environments,
and all17Windows/ELF output/exit matches. It additionally checks105native boundaries
(all100two-digit decimal strings and5non-digit Unicode/control cases), plus9unsafe
CLI image mutations in separate files. Source/flags and original PE are untouched.
Only expected acceptance policy changes; the frozen51original expectations remain.

Actual scope: one newly translated compiler program (guard_join),17new runtime
comparisons. All51Windows scenarios across the three variants still run. Squares
and helper retain34original-only scenarios and explicit converter rejection.
There are no51new Windows/ELF pairs: squares still needs nonlinear IMUL proof and
additional forms; helper still needs entry/call graph and pointer ownership proof.
Those architectures were excluded by the reviewed contract and remain blocked.
Do not relax gates to manufacture the larger comparison count.

The prior13compiler programs,102authored comparisons,18launch checks, original
input17scenarios and four older held-out rejections remain required. Ordinary CRT,
general memory/loops, PE32+ and XP/7 claims are outside scope. The genuine procfs,
stable initial environment, ASCII-key/UTF8/resource and valid-stack/no-fault
assumptions in INTEGRATION.md still apply. Four historical timeout causes remain
unresolved. Modern Windows evidence is not older Windows validation.

Reproduce with cargo fmt --check, cargo clippy --all-targets --locked -- -D warnings,
cargo test --locked, tools/check_input_production.py, and the Windows/Linux
research/input/diversity/measure.py commands in diversity/RESULTS.md. Generated
sources require Rust2021 (the harness passes --edition=2021).

Next medium review must check normalized operands/widths against the listings,
source/destination alias evaluation, snapshot flags and unknown-state rejection,
full local byte ranges on both guard orders, actual unchanged-artifact hashes and
all17new comparisons. The remaining nonlinear/helper barriers require their own
bounded design decision before implementation.
