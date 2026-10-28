# Cohesive handler execution milestone — SUB-579 / same PR45

Current normal-call integration: [original FILE scope](FILE-SCOPE.md) connects
owned lock acquisition, active scope, explicit driver cut, original normal cleanup
and epilog. It preserves unresolved formatter exceptions and termination as
admission blockers; no whole-startup claim.

Previous event integration: [owned software exception event](RAISED-EVENT.md) derives the
event from the original imported call, reserves checked scratch, and keeps the
exception-captured context opaque. It composes original dispatch, cleanup and
restoration under the explicit closed-delivery domain; full startup remains
rejected. Component execution evidence is reported separately from PE admission.

Previous integrated boundary: [original dispatcher and owned FS composition](DISPATCH-COMPOSITION.md).
It adds instruction-derived handler/local-unwind effects under an explicit closed
callback and opaque incoming-chain boundary; full startup remains rejected.

Previous integrated boundary: [connected original initialization, checks and
restoration](CONNECTED.md). The initializer and supplied saved-context cuts are
closed within the declared component domain. Original dispatcher/FS/nested-unwind
and full-startup admission remain open; PR #45 stays draft.

Current fragment integration and evidence boundaries:
[Original frame, filter and finally composition](FRAME-COMPOSITION.md). It records
instruction-derived selection and complete cleanup effects, while retaining the
Main/handler/landing cuts and zero new whole-PE admissions. Earlier checkpoints
below describe the historical plan, not completion of those remaining gates.

Current entry-boundary decision: [ENTRY-CONTRACT.md](ENTRY-CONTRACT.md). An
original-entry observation establishes a nonempty borrowed ntdll-owned chain.
For application-contained exception handling, prove that identity is preserved
and neither dereferenced nor invoked, rather than cloning irrelevant loader
internals. Search/unwind crossing the root remains a separate unresolved shared
effect. This refines the initial-state requirement below without granting an
empty-chain premise or a no-exception assumption. No startup translation yet.

Execution of this plan reached the explicit architectural stop criterion:
[EXECUTION-BOUNDARY.md](EXECUTION-BOUNDARY.md) records the original helper dependency
graph, production decoder experiments and two independently frozen Windows
counterexamples to normal-return/clear-pending shortcuts. The required next work
is shared effectful activation/continuation integration, with actual handler
instructions preserved. This is not completed startup translation or permission
to merge the unfinished milestone.

Medium review of f53ad06 found the separate cookie/complement mapping correction
consistent with the pinned original instructions. Focused formatting/Clippy,
15 Rust component tests and 15 startup Python tests pass. Existing evidence is
170 root tests total, five original-Windows probe observations and zero newly
translated startup programs. Full CI status belongs to the exact head in Linear.

## Required result

Deliver one integrated path from mechanically lifted prolog/record operations to
controlled handler search, filter result, unwind and validated restoration. Keep
rejection on any unresolved path. A Boolean that clears pending, another isolated
state model, or a hand-written replacement for the measured handler is not this
milestone. Full rcedit admission is contingent on its complete startup composition.

## First: close the actual byte/effect inventory

Retrieve the full guard helper at 0x47b250, handler through every terminal edge,
filter/context-validation/local-unwind thunks and targets, and positive/destructor
path beyond the current excerpt. Derive destinations from bytes using iced-x86;
verify unique executable mappings and complete instruction boundaries. Record
indirect target sets, unknown calls and exceptional successors. Bounded excerpts
and symbol names cannot prove graph closure. Resource exhaustion is explicit
incomplete evidence, never permission to ignore the remainder.

Read the scope header and entries from initialized, provenance-bound module data.
The observed [-2,0,-52,0] binds the current artifact's layout only after the actual
guard helper establishes how each field is used. Cookie and complement locations
are independent; neither their spacing nor frame offsets select application code.

Establish incoming FS/chain/stack/module invariants from a separately labeled
original-entry observation or a documented loader contract. Preserve artifact
hashes and the ordinary baseline. Do not infer empty FS:[0], build a guessed main
entry, dump environment/credentials, or treat a debugger run as an ordinary baseline.
Use existing supported observation infrastructure. If it cannot capture the entry
state safely, record the exact missing field/transition and supported experiment.

## Shared execution mechanism

- Replace the single pending flag only with private, validated phase transitions:
  ordinary, search, unwind, restoration, terminal/unsupported. Caller-provided
  "handled" or raw handler addresses grant no authority.
- Build owned exception-record and x86 CONTEXT mappings from the originating
  guest event and register/flag/stack state. Track which fields are initialized
  and valid under ContextFlags. Preserve exception parameters, code, faulting
  instruction, continuability and nested-event state. Do not zero unknown fields.
- Lower actual x86 instructions to shared IR/native Rust. Preserve arithmetic,
  flags, partial registers, pointer provenance and all stack/saved-register effects.
  There is no runtime PE interpreter fallback. Record and cookie checks assert
  instruction effects; they do not replace those instructions.
- Permit handler memory operations only through validated phase-local capabilities
  and checked ownership/ranges. Original writes to exception code, frame locals,
  scope state and context invalidate aliases appropriately. Do not expose arbitrary
  process memory through an unrestricted dispatcher escape hatch.
- Treat mapped RX bytes and a syntactically valid CONTEXT as necessary conditions,
  not proof of a valid callback or safe continuation target. Prove target boundaries,
  live stack/frame ownership, preserved registers and context restoration.
- Integrate contracts for the measured SSE2 code filter, cookie/context checks,
  filter callbacks, local/global unwind, termination callbacks and any destructor
  path actually reachable. Separate language filter returns from raw dispatcher
  dispositions. A noncontinuable event cannot resume ordinary execution.
- Handle further exceptions during validation, filters, cleanup and restoration
  explicitly. Unsupported nested/async/debugger/external effects block admission;
  do not silently skip them or promise identical failure codes without evidence.

## Observable acceptance

1. Instruction-level differential snapshots for unchanged original prolog/guard/
   handler slices and independently authored layout/register variations: record
   bytes, cookie locations, exception-code mutation, selected successor, restored
   registers/flags/ESP/FS and ordered cleanup effects. Label this as slice evidence.
2. For every newly admitted whole PE, compile unchanged PE to deterministic Rust
   and Linux ELF and compare Windows stdout/stderr/exit and relevant observable
   state on the same artifact hash. Include normal return, continue-search,
   continuable resume, selected-handler unwind and direct termination cases.
   Component/slice snapshots cannot be counted as these translated pairs.
3. Independently specified negatives: wrong thread/module, stale frame, corrupt
   cookie/header/record, incomplete context, illegal target, uninitialized read,
   noncontinuable resume, cleanup fault, unproved indirect call and exhausted proof
   budget. Conversion must reject unsupported reachable behavior before publishing
   an executable claiming equivalence. A checked runtime fault needs a reviewed
   guest-event mapping; exit125 alone is not Windows exception equivalence.
4. Retain all prior regression/corpus checks, exact-head CI, original artifact
   provenance and timeout failures. Modern Windows does not establish XP/7 support.

## Stop criterion and useful no-go result

Do not stop merely because another component passes. Attempt the composed path.
If a reachable helper, incoming state or restoration rule cannot be closed, return
an exact minimal dependency graph: originating instruction/event, missing field
or external contract, observable consequence and why current evidence cannot prove
it. Supply a reproducible counterexample or one supported observation experiment.

A justified no-go must distinguish a local missing opcode from an architectural
requirement (for example context-sensitive nonlocal control flow or externally
owned loader frames). Recommend a concrete shared architecture change with bounded
acceptance. Do not append another arbitrary accessor/model issue. Keep the whole
milestone in this PR, preserve production rejection and request medium review only
after integrated execution evidence or a supported architectural no-go exists.
