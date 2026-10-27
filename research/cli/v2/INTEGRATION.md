# SUB-564 streaming integration checkpoint

Status: **partial implementation; production admission remains blocked**. This is
one cohesive branch/PR, not a completed CLI milestone. Source freeze `bc3ebd8`
preceded compiler evaluation. Additional closed-output-pipe expectation freeze
`2443466` preceded that experiment. Neither freeze changes v1.

## Established evidence and implemented components

V2's sole application change is immediate GetLastError after failed ReadFile:
ERROR_BROKEN_PIPE becomes exit 0, every other read failure remains exit 11. The
parent's v1 source/hash/exit-11 pipe history is retained unchanged. Both use the
original documented O1/O2 flags and custom entry, without CRT startup.

The first measured v2 run after the LF checkout fix, CI 40423734900, used Windows
Server 2025 build 26100, MSVC 19.51.36260 / linker 14.51.36260. Its artifacts:

| Build | Unmodified PE SHA-256 | Normalized reachable instruction nodes |
|---|---|---:|
| O1 | `96a3571001e52c6dd89928d40ce9e38ba5c64093f05a1e36d6fe1db95c390694` | 96 |
| O2 | `0a1d5fbb705fc79ea28b8acbfcea431165954fb21629989e219114e797bb8f7a` | 133 |

Hashes above describe that run, not a promise that relinking is byte reproducible
across timestamps. Every subsequent report binds its own exact original PE to
its graph and observations. Both hosts receive the *same* Windows-produced PE.
Imports are ReadFile, WriteFile, GetStdHandle and GetLastError in KERNEL32.dll.
Both have one cyclic strongly connected component containing nested loops;
this is not one loop or a termination proof. O1 uses an EBP frame; O2 uses ESP
relative locals and EBP as a handle. Both allocate 264 local bytes and save
nonvolatile registers. Register-held import targets and actual per-call stdcall
cleanup need typed binding before execution eligibility.

Implemented, compiled Rust components (used only by explicit examples so far):

- `src/stream/graph.rs`: register/byte-width/indexed-address normalization,
  checked intraprocedural successor closure, instruction overlap rejection,
  bounded iterative SCC analysis, and explicit unresolved call operands.
  Prefix and unsupported-form rejection remains strict. Memory-looking NOPs
  have no load effect. Unreachable bytes must be NOP/INT3 padding. Calls currently
  record their continuation, **not a resolved interprocedural effect graph**.
- `src/stream/memory.rs`: private arena/object identity, checked owner+offset
  access, byte initialization, overlapping byte/word reads, protected objects,
  stale/reused/foreign-arena rejection, complete ranges and disjoint count cells.
  4096 bytes / 32 live objects are storage limits, not a total-stream limit.
- `src/stream/effects.rs`: successful-prefix initialization, failure invalidation,
  count reset, checked source ranges, actual partial counts, file-versus-pipe EOF,
  and native Read/Write adapters. No read-to-end or write-all substitution. Input
  and output endpoints are supplied owned Rust objects; the module does not
  discover guest standard handles or turn numeric values into host pointers.

`stream_graph` emits deterministic **structural reports**, not Rust application
source. `stream_core` is an independently authored consumer of the components,
not mechanically lifted application logic. Its file/pipe/failure comparisons
must not be counted as PE-to-ELF translations. **Zero CLI PEs are admitted.**

## Counts and reproduction

The frozen v2 manifest has 14 input vectors: original 11 plus 65535/65536/65537-byte
inputs. Per compiler build: 14 file and 14 anonymous-pipe executions (56 original
Windows successes total), read-access and write-access failures. The extra closed
output pipe adds one failure per build. Its read endpoint is closed *before*
process launch, avoiding a reader timing race. No stdout bytes can be observed on
that failed destination; report exit/stderr instead of inventing captured output.

Ten scripted Windows API cases execute v2 with substituted functions: missing
handles, failed read/write, zero/excessive progress, excessive read count, immediate
and post-output broken-pipe EOF, and a non-broken error after output. They are
scripted component evidence, not ten additional unchanged-PE scenarios.

Linux component coverage is 28 file/pipe + 3 failure executions once per input
set, compared with both compiler baselines; **31 unique component executions**,
not 62 independently compiled programs. Internal short-I/O tests use five read/
write chunk-size pairs on 65537 bytes, plus retained-prefix failure and zero
progress. They do not claim actual OS partial writes occurred in every baseline.
There are 12 memory/effect/consumer test functions and 5 graph test functions;
these are separate from the inherited 99 root tests and 9 acquisition tests.

```
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
cargo test --locked --example stream_core --example stream_graph
cargo build --locked --example stream_core --example stream_graph
# Windows x86 MSVC developer shell:
python research/cli/v2/measure.py <evidence-dir>
python research/cli/v2/inventory.py <evidence-dir>
python research/cli/v2/check_components.py <evidence-dir> --windows
# Linux, after downloading that exact evidence directory:
python3 research/cli/v2/check_components.py <evidence-dir>
```

## Concrete architecture gap; next implementation in this same milestone

The current production input proof specializes live storage to an acquisition
buffer and uses acyclic call/control traversal. Its scalar expressions and
initialization facts do not provide a fixed point for this mutable stream frame.
The older sum-loop recognizer is a separate fixed graph. Neither can establish
all streaming iterations by deleting a cycle check or inspecting a successful
trace. The new safe component checks also do **not** establish x86 equivalence.

Continue with one reusable typed-frame/loop-state integration, then native
emission. The required invariant at each read iteration is:

1. Stack/frame coordinates are tied to one activation; saved original registers,
   return words and argument words are distinct from mutable local bytes. All
   stdcall argument cleanup restores the prior stack coordinate. EBP and ESP
   variants use normalized operands, not separate artifact recognizers.
2. ReadFile produces a fresh symbolic length `n` and result class. Only its
   successful prefix `[0,n)` is initialized. The count cell and buffer are
   disjoint, fully owned and live. Every repeated read invalidates facts derived
   from the previous acquisition epoch, including aliases and saved scalars.
3. Loop joins rename incoming scalar identities consistently. Range and
   relational constraints must prove `0 <= index < n <= capacity` before every
   transform read/write, and `0 <= sent <= n` plus `written <= n-sent` before
   progress. Meeting/widening facts must never manufacture initialization or
   equate values from different iterations. Unknown proofs reject.
4. Byte writes preserve unknown upper register bits. Width-correct arithmetic,
   CF/ZF/SF/OF, INC's preserved CF, API clobbers, handle comparisons and immediate
   last-error consumption must correspond to each emitted operation. ESP-dependent
   arithmetic flags remain unknown unless reset before use.
5. Imports/relocations bind function tokens at every direct or register-held call.
   Synchronous effects preserve only documented nonvolatile state. No arbitrary
   function pointers, hidden startup effects or generic memory accesses enter.
6. Emit normalized blocks as native Rust with iterative control flow and constant
   live storage. The outer input loop depends on external EOF/error; it cannot
   claim unconditional termination or silently impose a total-input cap. Inner
   progress is guarded and bounded. No runtime PE decoding or instruction
   interpreter, and no hard-coded uppercase algorithm in production emission.

A bounded relational fixed-point domain (with path facts at joins and explicit
acquisition epochs) is the proposed route. Runtime range checks may remain a
safety backstop, but an unexplained check failure cannot be relabeled successful
conversion. Static proof resource exhaustion must reject before emission. This
needs a focused architecture review; the existing components do not supply the
fixed point, frame lowering, import binding, standard-handle discovery or emitter.
Do not start another issue per missing opcode or merge this partial milestone as
completed CLI support. Keep PR25 draft through integration and substantive review.

Acceptance remains genuine unchanged v2 O1/O2 PE-to-Rust-to-ELF pairs, identical
Rust per PE across hosts, all file/pipe/failure observations, independent unsafe
index/epoch/alias/saved-slot/call/flag negatives and prior corpus. Additional
register/frame permutations must exercise reusable lowering. No sample-based
bounds or source/result templates. Until then ordinary CLI conversion rejects.

## Native effect domain and limits

Single-threaded, stable, already-owned synchronous regular-file/byte-pipe endpoints.
Devices, consoles, message pipes, asynchronous cancellation and concurrent handle
replacement need separate contracts. Backend errors are categorized only enough
for this component: broken input pipe 109 versus other errors. Full Win32 error
number equivalence is not implemented. Successful calls leave last-error unknown.
The supplied Rust executable uses Rust's ordinary SIGPIPE handling; embedding the
component into a process that changes signal policy is outside current evidence.
Closed-pipe failure is tested explicitly rather than assumed. No system security
settings are changed. Failed writes retain any output already delivered; no
rollback/flush equivalence for arbitrary buffered writers is claimed. The component runner now duplicates the existing standard descriptors through
safe AsFd/try_clone_to_owned and File; no buffered stdin/stdout locks, invented
raw descriptor ownership or /proc reopening. Duplicates share offsets and closing
them does not close the original standard descriptors. Duplicate failure remains
a component setup failure, not a proved guest GetStdHandle result. Only raw
file/pipe endpoints belong in eventual native admission.

The architecture-correct preferred/rebased-address and valid-stack assumptions
from existing work remain. No XP/7, ordinary CRT, x64, GUI or general-app claim.
No Wine source/runtime or AI runtime is introduced. Implementations and fixtures
are independently authored MIT OR Apache-2.0. iced-x86 remains compiler-only.
Primary contracts are linked in parent CONTRACT.md; GetLastError's immediate,
per-thread and unspecified-success rules were checked in Microsoft's documentation.

## Findings retained

CI 40423079028 stopped before compiling v2 because nested JSON fixtures were
checked out as CRLF. Added LF attributes; original frozen hashes were retained.
CI 40423734900 passed all five jobs after that fix; this is not a timeout retry.
Local review then reproduced cross-arena pointer aliasing when two Memory instances
both allocated object 1. Arena identity now forms part of every private pointer;
independent regression rejects cross-arena read/write/release. Invalid-handle read
failure also invalidates requested initialization conservatively.

Five earlier Windows fixture timeouts remain unexplained (see parent RESULTS.md).
No silent retries or enlarged timeouts. Green runs do not diagnose those failures.

A further deterministic defect was reproduced by the newly frozen closed-output-
pipe case: the first component runner used buffered Rust stdout, which returned
success before delivering bytes and hid the error at process exit (exit 0 instead
of 12). Replaced both standard stream locks with owned, unbuffered File duplicates.
The permanent end-to-end component regression checks exit 12 and empty stderr;
no flush-at-exit workaround or rewritten expected result. This illustrates why
component API semantics must be validated before using them in emitted programs.

### Continued production binding stage

The production linker intake now accepts the exact four-name stream import set
(independent of table order), validates the full ILT/IAT plus terminator, reserves
all descriptors/names/tables against overlap, and binds relocated absolute IAT
uses to function identities. Ordinals, duplicate names, unsupported names/DLLs,
table aliases, mismatched thunks and unconsumed relocations reject.

Function-token propagation uses a finite must-analysis over the normalized cyclic
graph. Joins retain a function identity only when all incoming states agree;
external calls invalidate volatile EAX/ECX/EDX tokens. The final converged states
must resolve every register-held call. O1 binds five calls and O2 six. This proof
covers function identity only, not arguments, stack shape, memory initialization,
termination or behavioral equivalence. Both originals still reject emission with
an explicit cyclic frame/epoch proof diagnostic.

Four independent binding test functions cover preserved versus volatile tokens,
conflicting and agreeing branch joins, relocation provenance, IAT writes and a
cyclic call path. The five graph tests are also exercised through the production
module; they are inherited tests, not five new independent cases. Root test count
is now108 (99 previous +5 inherited graph +4 new binding). Twelve malformed import
mutations across the two unchanged originals reject through production intake;
the two originals reach the proof barrier with output files preserved.

### Relational verifier decision

[Compiler-time solver evaluation](proof/DECISION.md) documents the concrete
correlations lost by per-value intervals, nine standalone proof-language checks,
and the proposed coherent frame/SSA/epoch/induction/emission route. The recommended
Z3 dependency is research-only pending architecture review; production emission
remains blocked. These solver outcomes are not whole-program proofs.

## Integrated production implementation (SUB-564, pending final CI/review)

The earlier partial checkpoints above are history. The production stream route now
binds the same checked graph to a finite frame/definedness analysis and local Z3
4.15.4 constrained-Horn-clause safety proof, then mechanically emits native Rust.
It does not emit the authored component consumer. O1/O2 use one normalized operand,
frame, effect, proof and emitter implementation; no artifact hash/graph recognition.

The private frame proof tracks stack coordinates, exact local allocations,
protected saved registers, argument snapshots/stdcall cleanup, complete local
word ranges, nonvolatile restoration, per-register width knowledge, count-word
initialization and CF/ZF knowledge. Unknown/opaque joins lose knowledge. Entry
registers and actual stack addresses are not invented observable constants.

The current relational profile supports one fixed owned read region and capacity,
one read-count cell that is written only by ReadFile, separate write-count cells,
and initialized-prefix byte accesses. All reads must use that same read-count
identity; scalar stores or WriteFile aliases to it reject. The fresh prefix and
read count share one capability value only after this structural unique-writer
check. Every acquisition replaces it, including failure/zero-length results;
allocation/cleanup invalidates it. Stale counts cannot retain initialization.

The proof retains every CFG edge, including a conditional branch whose target is
its fallthrough. Each instruction's safety property is checked against the entire
cyclic transition system. Numeric sort/capability bounds are checked on incoming
edges before becoming preconditions; a first invalid invariant reaches the error
relation. Safety checks are recorded before safe continuation is assumed. Every
query must be UNSAT. There is no sampled unrolling, per-artifact invariant or
fallback after SAT/UNKNOWN. This proves the admitted safety/definedness conditions,
not a complete formal proof of the decoder, encoding, solver or emitter.

Byte content and byte-arithmetic flags are over-approximated in the safety proof;
actual byte operations and branches remain exact in emitted Rust. Upper-bit
knowledge is conservatively forgotten after partial writes, though native code
preserves upper bits. Full reads require a subsequent full definition. Scalar
32-bit ADD/SUB/INC must prove no wrap in this stream profile; other translator
profiles retain their existing wrapping contracts. Pointer arithmetic is owned
frame-relative arithmetic, with actual-load-base/valid-stack/no-wrap assumptions.
Opaque handles/BOOL/error values permit only the reviewed observation predicates;
GetLastError comparison supports equality with109, not arbitrary error-number
emulation. Unproved flags or initialized ranges reject.

No static proof of total stream termination is claimed. Native basic blocks execute
faithful cyclic control flow with constant live storage and no hidden total-input
cap. EOF/errors remain external events. This is semantic compilation, not a runtime
instruction decoder, interpreter, solver, Wine wrapper or AI service. Runtime range
and initialization checks supplement admission proof; violations exit125 and are
not successful compatibility.

### Dependency, budgets and reproduction

Install the official version/hash-pinned wheel from `proof/requirements.txt` or
supply the matching official Z3 executable on PATH / `W2L_Z3`. The license and
platform wheel hashes are recorded in `proof/`. The compiler runs it locally with
no network. It requires the exact64-bit4.15.4 version, uses a fixed Spacer
configuration, a15-second query timeout,512MiB solver memory limit,20-million
resource-unit ceiling and25-second total process deadline. `W2L_Z3_RLIMIT` may
lower the ceiling for diagnostics/tests; it cannot raise it. Absence, version
mismatch, malformed output, exhaustion or any non-UNSAT property blocks emission.
There are no automatic proof retries. `W2L_STREAM_OBLIGATIONS` optionally records
SMT-LIB in a **new** file for reproduction; an existing path is never overwritten.
No solver or decoder dependency appears in generated Rust/ELF.

```
cargo build --locked
W2L_Z3=/path/to/z3 target/debug/w2l original.exe generated.rs
rustc --edition=2021 generated.rs -o native-cli
# Both original.exe and generated.rs must be the exact CI-recorded artifacts.
python3 research/cli/v2/check_translation.py downloaded-cli-v2-evidence
python3 research/cli/v2/check_safety.py downloaded-cli-v2-evidence
```

Generated native endpoints duplicate existing standard file descriptions without
buffering or reopening them. Domain: stable single-threaded regular-file or byte-
pipe standard endpoints, available descriptor-duplication resources, synchronous
calls, no external buffer mutation. Consoles/devices/message pipes/async I/O are
outside admission. Descriptor setup/resource failures produce explicit contract
failure; they are not proof of Windows handle-allocation equivalence. Read/write
permission failures and closed output pipe are tested as real I/O failures. Native
other-error values map to a non109 category; opaque error-use restrictions prevent
claiming complete Win32 error-number equivalence.

### Integrated evidence gates

CI must produce matching hashes and generated source for the same untouched O1/O2
PEs, with62 real Windows/ELF comparisons:28 file,28 pipe, six failures. Sixteen
additional native scripted executions compare eight valid API-result probes per
emitted program to the separately labelled Windows probes. The two scripted cases
that violate ReadFile/WriteFile's maximum-count contract remain negative component
contract evidence, not real OS translation pairs.

Production negative tests cover inclusive index guards, saved-register owners,
read region overflow, undefined count reads, stale-count identity after a fresh
read, coincident branch successors and unavailable/exhausted solver. Two separately
labelled mutated arithmetic fixtures check that decoded SUB immediates actually
change native output; they are not unchanged compiler baselines. No original PE,
source freeze, compiler flags or expected baseline results are edited to pass.

Five historical Windows fixture timeouts remain unexplained. New proof-performance
experiments that returned UNKNOWN were rejected, not silently retried in production.
PR25 remains draft until exact-head CI and substantive medium review complete.

CI40434680140 stopped in Windows solver provisioning before compiler measurement:
the verified official Windows wheel installs `data/bin/z3.exe` under Python's
prefix, not its Scripts directory. The CI locator now checks that exact package
layout. This is a diagnosed setup failure; it is unrelated to the five historical
Windows program timeouts. Checks and solver budgets were not relaxed.
