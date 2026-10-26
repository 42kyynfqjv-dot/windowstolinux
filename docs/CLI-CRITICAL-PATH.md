# From narrow experiments to a useful native CLI

Assessment at SUB-561 (2026-10-26). The user wants steady, correct progress; there
is no request to rush or discard validation. We have over-fragmented work into
design, implementation and review issues for small changes. Those checkpoints
have caught errors, but issue and PR counts do not measure compatibility. All
eight newly held-out artifacts rejecting exposes limits that earlier fitted
examples do not. Preserve the useful proofs and tests while reducing that overhead.

## What is reusable, and what remains specialized

| Source evidence | Reusable foundation | Present constraint |
|---|---|---|
| `src/control/decoder.rs`, `src/linker/input.rs` | iced-x86 decoding and explicit policy | separate byte-pattern adapters; register/form variations repeatedly need additions |
| `src/linker/input/proof.rs` | immutable expressions, path-sensitive initialized buffers and protected internal calls | three input symbols, one allocation/API/capacity, restricted predicates, no general cyclic CFG |
| `src/linker.rs` | checked ranges, metadata exclusion, typed relocation provenance | exact three-section/COFF/optional-header profile and one selected import API |
| `src/linker/translate.rs`, `src/control.rs` | decoded graphs, explicit state and regression evidence | separate validation/emission systems and mostly deterministic accepted paths |
| `src/inspection/loops.rs` | a valid rank proof for its admitted summation | exact28-byte masked stencil and fixed graph; not a reusable loop lifter |
| `src/inspection/reads.rs` | full initialized reads and no-write exclusions | separate five-operation body evaluator, not general mutable memory |

The input path fixes the W2L_INPUT name, capacity3 and an8-byte local allocation;
the effects are not yet independently composable with the other linker's output
path. Predicate reuse helps but does not remove these architecture boundaries.
The input emitter uses fixed Rust functions for decoded blocks. Older emitters
include a statically generated PC/operation dispatch or an IR evaluator. They
compile to native ELF and do not decode original PE bytes at runtime, but not all
paths are direct structured native lifting. Document that distinction explicitly.

Current16 compiler-built programs and51 runtime-input comparisons are regression
assets, not16 ordinary applications. Ordinary CRT startup, broad mutable memory,
general loops, file APIs and PE32+ remain incomplete. No compatibility percentage
can be inferred from these deliberate small samples.

## Next integrated milestone: runtime-input composition

Finish the current contract checkpoint and medium review. Then integrate the
predicate gate as part of a **cohesive operand/frame/owner-offset/capacity** milestone
against all eight frozen O1/O2 artifacts, rather than opening an issue for each
new first rejection. Keep dependent design, implementation and tests in one feature
branch/PR with reviewable commits and substantive review before merge.

First inventory every reachable instruction, frame transition, alias, import and
control edge in all eight unchanged PEs. Existing first failures are authoritative
but incomplete inventories. This pass must expose any additional dependency before
promising acceptance. Do not retune source or flags to fit the converter. Then:

1. Normalize observed operand families using decoded register/width/address/flag
   metadata into the existing or a common typed IR. Keep unsupported addressing,
   prefixes and effects explicit. Avoid filename/hash/whole-body stencil admission.
2. Unify the required stack frame and preserved-register rules, including measured
   EBP prologues and saved scalar ESI. Keep protected returns, unknown absolute ESP,
   balanced cleanup and per-invocation ownership. A register choice must not require
   an independent semantic engine.
3. Represent borrows as owner plus checked offset and initialized extent; permit
   only the measured read-only offset/capacity operations after proof. Larger
   capacity must extend API result classes, initialization and resource bounds
   together. A pointer becoming a scalar loses read authority.
4. Compose actual nested/shared calls, return predicates and measured conditional
   selection forms with correct volatile effects and disjunctive state. Unknown
   input stays unknown; unsupported effects still reject. Retain existing limits
   until an explicit bounded replacement is justified.

Objective: the eight unchanged artifacts process their112 frozen input cases on
Windows and Linux with matching stdout/stderr/exit, artifact hashes and identical
generated Rust. Add independently specified boundary/unsafe cases and a held-out
composition or compiler configuration to test reuse; report its result honestly.
If inventory or proof uncovers a larger prerequisite, record it and bound the
milestone openly. Do not reinterpret a rejection or a model pass as execution.
Even all eight passing would establish this composition capability, not useful
general CLI compatibility. The next user-facing target below remains separate.

## Useful CLI target and critical path

Recommend an independently authored **freestanding ASCII-uppercase stdin/stdout
filter** as the subsequent end-to-end target. Map ASCII a..z to A..Z and preserve
all other bytes, including NUL/high bytes and CR/LF. Use binary-exact redirected
I/O, explicit EOF, partial reads/writes, zero-progress and error behavior, with
small exit statuses. Freeze the source, output oracle and two documented compiler
configurations before evaluating conversion. This is a proposed target, not an
existing translated program or a reason to start broad I/O during SUB-561.

Expected public API surface is GetStdHandle/ReadFile/WriteFile/ExitProcess; the
actual compiled inventory must confirm it and expose any compiler runtime helpers.
A documented freestanding entry avoids claiming ordinary CRT startup equivalence.
Do not skip startup in the existing CRT artifacts. Initial supported handle kinds
must be explicit; regular files are a smaller gate than consoles, pipes or async
I/O. Do not conceal platform differences behind a passing ASCII example.

Concrete prerequisites visible today: multiple import effects in one program,
typed handles, mutable initialized byte/count buffers, aliases and external writes,
loop-carried state, dynamic output bytes, and common native emission. Current fixed
environment acquisition and immutable output do not supply these. The earlier
composition milestone prepares operand/frame/borrow reuse, but does not prove I/O.
Use a cohesive implementation PR for this utility after its inventory, not another
chain of one-function probes detached from actual conversion.

Semantic compilation is not the same as predicting the result or proving every
program terminates. A future reviewed execution contract may preserve unknown
runtime branches and use checked guest-memory accesses, while proving faithful
transitions and memory bounds. Streaming termination can depend on external EOF;
samples cannot prove it. Runtime checks must not invent original-program behavior,
silently zero unknowns, or convert unsupported cases into success. This is a design
direction requiring review, not permission to remove current admission gates.

Acceptance for the filter: unchanged compiler PE to Rust to ELF, same-hash Windows
baseline, independently expected byte output for all256 byte values, empty input,
embedded zeros, chunk boundaries/multiple chunks and larger files; partial/error
paths tested, with model injection distinguished from real OS observations. Show
input changes at runtime without regenerating Rust, both compiler configurations,
and no runtime PE decoder/AI/Wine execution. Keep prior regressions. There is no
defensible elapsed-time estimate before the actual dependency inventory.

## Mature components and overhead

* **Use more of iced-x86 already in production.** Its official
  [Rust README](https://github.com/icedland/iced/blob/master/src/rust/iced-x86/README.md)
  documents operands and register/memory/flag metadata and MIT licensing. Normalize
  those results instead of duplicating register encodings. Decoder acceptance is
  not execution or ownership proof; preserve explicit policy and negative tests.
* **Consider `object` for repetitive PE record reading, not eligibility.** The
  official [manifest](https://github.com/gimli-rs/object/blob/main/Cargo.toml)
  advertises PE support and MIT OR Apache-2.0. Compare against existing malformed
  range/alias tests, pin/audit the chosen release and transitive notices before
  adoption. Retain private semantic/relocation checks. No dependency is added here,
  and a parser migration should not block useful work without measured benefit.
* **Keep rustc/LLVM for code generation and optimization.** Do not build another
  optimizer while lifting/API semantics remain incomplete.
* **Remill is an evaluation/reference candidate, not a Rust drop-in.** Its
  [README](https://github.com/lifting-bits/remill/blob/master/README.md) describes
  machine instruction lifting to LLVM bitcode, with LLVM/Clang/XED dependencies.
  Replacing this architecture needs explicit backend/license/distribution review;
  no implementation is imported here. Wine remains a behavior research reference
  under the user's independent-Rust requirement.

Primary repository metadata above was inspected on2026-10-26. These are suitability
findings, not measured migrations. Reuse existing Windows/Linux CI and persistent
failure artifacts. Keep four historical timeout causes unresolved unless diagnosed.
Never hide them with retries or loosen budgets merely to pass.

Use Astra High for coupled semantics and implementation, then Sol medium for
substantive correctness/artifact review. Keep that review, tests and design rationale
inside the cohesive feature PR where practical; split only at a concrete risk or
review boundary. Standing merge-after-review applies. No release/deploy or new
XP/7, ordinary-CRT, PE32+ or general-application claim follows from this plan.
