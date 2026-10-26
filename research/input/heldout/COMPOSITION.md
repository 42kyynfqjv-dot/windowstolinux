# SUB-562 integrated runtime-input composition

This milestone extends the existing private input IR/proof/emitter in one PR.
It does not add per-artifact recognizers. `full-inventory.json` records complete
instruction/padding bytes for all eight frozen source/configuration artifacts
before implementation, using SUB-561 CI40414130330. Historical hashes bind that
inventory only; they are never admission authority. Frozen C, flags and inputs
are unchanged. Source contracts are the Intel SDM instruction semantics cited in
`../postcall/CONTRACT.md`, Microsoft x86 calling convention and
GetEnvironmentVariableW contracts already cited in `../CONTRACT.md`.
No external source implementation is imported.

## Shared execution and proof contract

* iced-x86 decodes instructions. The existing exact forms remain; a shared operand
  normalizer admits selected unprefixed 32-bit register/scalar, stack-relative,
  MOVZX WORD, LEA, immediate IMUL, CMP/TEST, CMOVE/CMOVBE and direct branch forms.
  EAX/ECX/EDX/ESI/EDI are scalar/capability registers; EBP additionally has a private
  frame-anchor role. EBX, ESP as a scalar, other widths/prefixes, indexed stack
  addresses, indirect transfers and general memory effects reject. Decoding a
  form alone never authorizes emission.
* Incoming register values remain unknown or distinct preserved-register tokens.
  They cannot be consumed as numeric zero. Generated zero placeholders are never
  observable on admitted paths. EBP=ESP records a stack coordinate, not an invented
  numerical guest ESP. Root EBP save/anchor/LEAVE and bounded PUSH ECX/SUB allocations
  are modeled explicitly. PUSH ECX allocation does not initialize local bytes.
* There is one root local object, at most 12 bytes, acquired once. A buffer value
  is that unique owner's offset, never a host pointer. It cannot outlive cleanup
  or be recreated after acquisition. Pointer arithmetic is only constant LEA
  within the live object; each later access separately checks its full width.
  Read-only borrows retain object authority through nested/shared call contexts.
  An offset pointer does not restrict authority to a fabricated smaller subobject.
* Stack words distinguish root/internal returns, local byte coordinates, preserved
  register origins, and scalar/capability values. Saved scalar/capability copies
  may also be passed as arguments: PUSH ESI has no intrinsic x86 save-versus-argument
  bit. Caller words remain unchanged across each callee. Original register/frame
  tokens and return metadata cannot be read as scalar arguments or consumed by
  argument cleanup. Return checks require exact caller stack and ESI/EDI/EBP values.
  Mixed local/argument cleanup rejects; local cleanup removes the entire root
  object. Numeric ESP-derived flags remain unknown.
* Internal calls propagate their actual decoded EAX/ECX/EDX effects, including a
  value left untouched by a callee. They do not impose an artificial ABI clobber.
  Tracked flags are conservatively invalidated on return. External acquisition
  still clobbers volatile scalar registers/flags under its reviewed contract.
  Preserved-register equality is checked separately at every internal/root RET.
* Complete decoded control flow has instruction-boundary and overlap checks.
  Backward-address edges are allowed only when the context-sensitive graph is
  acyclic; nested's shared error epilogue is such an edge. Recursion and cycles
  reject regardless of sampled branch outcomes. Limits remain 512 code bytes,
  128 decoded instructions, four internal call levels, 16 stack words, 4096 graph
  visits and 4096 symbolic-state visits. Native functions follow the proven graph;
  no runtime opcode interpreter or fallback is introduced.
* Expressions retain immutable snapshots over four unknown UTF-16 units and one
  unknown API-result length. Modular affine bounds use signed representative
  coefficients and width-specific projection; wrapping intervals lose precision.
  Exact single-symbol refinement and entailed constant/multisymbol comparisons
  are supported; unproved correlations reject. Immediate IMUL is modular affine
  scaling. Existing nonlinear DAG/resource limits remain. CMOV evaluates its
  scalar source even when untaken, then forks the proof on the tracked condition.
  Register CMP currently requires an affine constant right-hand value. Arithmetic
  that cannot establish the required tracked flags leaves them unknown.
* Acquisition capacity is proven constant 3 or 5 and fits the live local object.
  All success lengths 1..capacity-1, zero, insufficient capacity, and raw failure
  ranges are considered, independently of sampled inputs. Initialized bytes
  include the terminator only on successful nonempty paths. Each aligned WORD or
  DWORD checks the entire initialized range, including overlapping high units.
  Offset-eight terminator is known only in the four-unit success class. Reads
  through borrows use runtime owner-relative offsets; stack access roles and
  physical addresses must agree across every context. Unproved emitted reads or
  addresses reject. Native acquisition uses the same reviewed procfs reader and
  checked UTF-8-to-UTF-16 conversion; no input is baked into generated code.

## Evidence and reproducibility

The first checkpoint 2a92a1a / CI40416275741 accepted composed O2 only: 14 actual
Windows/ELF pairs, with seven explicit rejections. That was incomplete.

The integrated implementation's acceptance gate is now **all eight unchanged
artifacts /112 Windows-versus-ELF scenarios**. `measure.py` checks the PE and source
hashes, converter outcome and byte-identical generated Rust on both hosts, and
actual stdout/stderr/exit for every scenario. Converter environment perturbation
must not change output. Windows baseline remains Server 2025; no XP/7 claim.
Final-commit run and downloaded artifacts are recorded in the PR/Linear evidence.

Local tests comprise 99 root Rust functions (seven added since pre-SUB-562), plus
nine acquisition example functions (one added), with inherited suites counted
separately. New regressions cover exact operand normalization and forbidden forms,
constant/width/wrap predicates, native composition, frame/protected cleanup,
saved scalar argument copies, unknown initialization, overlapping DWORD content,
backward acyclic paths, cycles/recursion and resource limits. The earlier
production harness still requires 18 native executions and 83 rejected PEs.
`check_composition.py` adds independent decimal-task expected results across all
eight generated ELFs: 992 native runs, including the 112 frozen scenarios and
880 scenarios outside that frozen set. These are NOT extra Windows pairs.
All earlier compiler, 51 runtime-input variant, 102 authored and 18 launch checks
remain in CI. Model/prototype tests are not counted as translated programs.

Local reproduction against downloaded Windows artifacts:

```
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
python3 research/input/heldout/measure.py evidence --compare
python3 research/input/heldout/check_composition.py evidence
python3 research/input/postcall/check.py evidence --compare
```

## Limits and next review

One fixed ASCII environment key, one root buffer and acquisition, capacities3/5,
no general mutable memory/heap, no ordinary CRT startup, no general loops or x64.
The older input and other linker execution engines remain distinct. This removes
composition restrictions for this selected corpus, not general application
compatibility. Stable initial environment/procfs, valid nonfaulting stack and
preferred/load-base assumptions remain. Four historical Windows timeouts remain
unexplained, with diagnostics and failure propagation retained and no silent retry.

Medium substantive review must audit state/emitter correspondence, aliases and
saved-value argument interpretation, internal effects, CMOV/refinement, full-width
reads, all eight artifact hashes and actual 112 comparisons before merge.
Next useful CLI work remains the cohesive freestanding binary-exact ASCII-uppercase
stdin/stdout target from `docs/CLI-CRITICAL-PATH.md`; obtain its complete compiler/API
inventory and I/O/error contract before implementing broad I/O. Do not restart a
chain of first-error opcode patches.
