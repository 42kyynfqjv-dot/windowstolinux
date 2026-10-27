# Stateful composition integration (SUB-570)

The four frozen fold/tabs O1/O2 artifacts join the two previously accepted escape
artifacts. Source, compiler configuration and expected bytes retain the SUB-569
freeze hashes. The full instruction inventory and original rejections remain in
[RESULTS.md](RESULTS.md). No graph/result template or sampled input selects emitted
behavior: the shared decoder, frame analysis, Horn proof and emitter process the
actual instructions. This is the same bounded freestanding Win32 streaming profile.

## Instruction contract

Independent implementation follows Intel SDM Volume 2, MOVZX, CMOVcc and AND:
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html

- Unprefixed MOVZX register32, low register8 (AL/CL/DL/BL) reads a known scalar byte,
  discards unknown upper bits and establishes a full zero-extended scalar. Both
  tracked flags remain unchanged. High-byte, word, memory, prefix and ESP-destination
  forms remain rejected. Opaque pointers/handles/functions/errors cannot become
  scalars through truncation. Unknown low bits are never silently initialized.
- Unprefixed register32 CMOVA selects its source exactly when CF=0 and ZF=0;
  otherwise it preserves its destination. Flags are unchanged. Both scalar values
  must be known even for an untaken selection; unknown CF/ZF, typed pointers,
  memory/word forms and ESP destination reject. Existing CMOVE remains supported.
- AND with a contiguous low-bit mask is encoded as integer modulo mask+1. For a
  nonnegative u32 this is exactly the same bit operation; other masks retain the
  bit-sum encoding. When finite input values are known, guarded exact constant
  results precede that general expression as a fallback. This removes nonlinear
  search from small loop-control states without assuming unproved input values.
  Runtime instructions and flags are unchanged.

## Weighted invariants and trust boundary

The existing binary-state hint for CRLF remains separately proved without hint
assumptions, followed by a mandatory safety phase. Weighted finite-state loops use
**assertion-before-assumption induction** in one full-CFG safety system instead.
This deliberately replaces redundant global invariant discovery for weighted
loops; it does not promote a heuristic to an assumption without a proof obligation.

Discovery identifies an indexed input byte loop, a disjoint indexed output byte
region and one modified finite register with the complete set 0..3 or 0..7. It
proposes an outer bound `output <= weight * input_index`, and for an inner expansion
backedge, `output + weight - column <= weight * (input_index + 1)`. Candidates are
structural aids, not a recognition-based permission to execute. They can be false;
that must reject. Graphs outside discovery still require the ordinary proof.

Each candidate is part of the domain at its cutpoint. The entry domain and every
incoming transition check the destination domain **before** adding it to the safe
continuation. Each check has an error edge using the predecessor domain and actual
transition/branch effects, without the checked destination bound in its premises.
All error queries must be UNSAT. Consequently any first failure of a candidate,
initialization, range, numeric/finite fact or flag requirement remains observable;
the failed path cannot disappear at the next cutpoint. There are no unchecked
cutpoint seeds, omitted predecessor edges, candidate-based instruction substitutes,
or retries after UNKNOWN. Tests strengthen both the uses and checks of the weight
from four to three and require SAT at the first expansion-entry edge.

The unchanged tab program has outer `used <= 4*i`; inside its do/while expansion,
`used + 4-column <= 4*(i+1)`. Column resets and all joins/read/write/EOF paths remain
in the graph. These bounds help prove complete accesses to the 256-byte output
region. The initialized prefix remains an independent fact: capacity never grants
permission to read a gap or bytes from a new input epoch. Owned ranges, protected
scalar/saved slots, partial I/O and error paths retain their existing obligations.
No total-stream termination proof or arbitrary-memory permission is claimed.

Solver budgets are unchanged: pinned local Z3 4.15.4, 25-second process budget,
15-second queries, 20-million resource limit, 512 MiB, 8 MB combined constraints,
1024 queries. Every SAT, UNKNOWN, timeout, error or missing result rejects emission
and preserves the destination. Z3 and iced-x86 are compiler dependencies only.

## Evidence and reproduction

CI builds the unchanged sources with the frozen MSVC O1/O2 configurations, runs
Windows baselines before conversion, then sends those exact hashed PEs and emitted
Rust to Linux. `measure.py` and `check_native.py` now require all six conversions.

- Four newly accepted artifacts require **124 actual Windows/ELF pairs**: 28 file/
  pipe inputs plus three OS failure cases per build. The prior escape62 are retained:
  **186 actual pairs** total, same PE hashes and byte-identical generated Rust.
- 72 original Windows substituted-backend records remain distinct from OS results.
  Every emitted build runs 24 frozen backend cases: **144 native scripted runs**.
- Six emitted builds each run 37,450 short-input/partition/EOF cases and 48 long
  cases (maximum expansion, resets, binary input and variable chunks/short writes):
  **224,988 Linux-only backend executions**, with whole-sequence independent oracles.
- Three new root test functions cover exact/rejected encodings, knownness and typed
  provenance, unsigned flag requirements, and **166 native emitter assertions**
  across unsigned boundary comparisons and low-byte/register permutations. These
  are not additional Windows comparisons. Root total:126 test functions.
- `check_safety.py` requires 16 separate malformed/unsafe PE copies to reject,
  plus two false-weight certificate SAT results and two exhausted-solver rejections.
  Exhaustion is rejection, not a diagnosed counterexample; raw diagnostics persist.
- All prior CLI/CRLF/input/compiler/authored checks remain mandatory.

On Linux, after obtaining the Windows artifact:

```sh
python research/cli/stateful/check_native.py stateful-evidence
python research/cli/stateful/check_safety.py stateful-evidence
python research/cli/stateful/check_partitions.py stateful-evidence
```

Use the repository's pinned Z3 and Rust setup. CI evidence and exact commit links
are recorded in the PR. Local checks against downloaded older Windows baselines
are development evidence; cross-host conversion identity requires final-commit CI.
Windows Server 2025 does not establish XP/7 support. Stable synchronous regular
files/byte pipes, valid stack and no concurrent mutation remain assumptions.
Ordinary CRT, general applications, PE32+, devices and asynchronous I/O remain
unsupported. Seven original-Windows timeout occurrences remain unresolved (including the new case below).

Development CI at909daa1 (run40452176178) failed on Windows tabs O1 at the inner
backedge invariant query (resource exhaustion); the same graph had passed locally.
The failure remains recorded, not retried as acceptance. Subsequent proof encoding
uses exact guarded finite AND results and removes a redundant overflow alternative
for AND, whose result is always within u32. Solver budgets stay unchanged; both
hosts must pass the new final commit.

### Additional original-Windows launch failure

Run40452702063 at6f7126c independently failed the older authored corpus at case12
on Windows Server2025, image win25-vs2026/20261021.278.1. The retained executable
SHA256 is05467e738deb03223e2878330d9071435ba6134940b18c5af5aa36653af71a3f;
artifact12711026676 (`corpus-launch-evidence`) contains the exact program, outputs
and case-12/launch.json. Expected and actual stdout were433132 (`C12`), stderr
empty. Spawn took0.01233s; process.poll() was still None after15s; kill completed
with exit1. This resembles the earlier full-output/process-still-running symptoms
but identifies neither a common cause nor a resolved runner defect. The18 launch
probes had passed immediately beforehand. No retry/timeout increase/suppression
was added; this workflow failed. A later passing run does not explain the cause.
The failure is independent of the converter's stateful graph changes, but remains
part of the project's unresolved original-Windows validation reliability gap.
