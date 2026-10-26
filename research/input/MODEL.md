# SUB-550: guarded unknown-input proof

This is a test-only, conditional proof for the exact frozen input program. It
constructs no production certificate, emits no program and does not activate an
API shim. Original CRT and the new input PE remain conversion rejected.

## Result and initialization partition

The API contract from CONTRACT.md gives the following complete disjoint return
classes at capacity three, under normal API completion. No concrete input is used
to construct this partition.

| EAX/ECX return | Guaranteed initialized local bytes | Path/result |
| --- | --- | --- |
| 0 | none used (conservative even if empty writes a terminator) | exit200 |
| 1 | [0,4): one WCHAR and terminator | digit branch; exit0..9 or202 |
| 2 | [0,6): two WCHARs and terminator | digit branches; exit0..99 or202 |
| 4..65 | none | exit201 |
| 66..2^32-1 | none | exit203 |

Return3 is impossible: a length-three value requires capacity four; length-two
success returns2. The overapproximation includes huge required lengths that may
exceed OS environment limits; none reaches a read. Zero includes missing/empty/API
failure and deliberately does not distinguish last-error state. Faults/exceptions
that do not return normally are outside this model, never silently successful.

`State.le` splits inclusive intervals at actual unsigned branch bounds. TEST/JNE
separates zero, CMP/JBE65 separates resource overflow, CMP/JBE2 separates short
success. The remaining states are singleton lengths1 and2, not singleton character
values. The model retains unknown characters as symbols. `read_join` requires a
full read in every incoming state; a success path cannot confer initialization
on a failure/overflow or shorter-success path.

## Machine relation and arithmetic

`check_model.py` binds the complete129-byte entry body, both exact HIGHLOW fields,
IAT and one named Kernel32 import, immutable UTF-16 name, preferred base and entry
to the unchanged PE hash from the independent Windows experiment. It checks the
same bytes on Linux. This is an exact trusted compiler-profile audit, not a general
hostile-PE loader or proof of startup eligibility. Other PE metadata and all
production intake obligations remain for the future certificate.

The compiler reserves eight local bytes; the output subregion owns six. API
stdcall pops three arguments (12 bytes); its return address is separate. The
first DWORD at local0 is safe for n=1 (character+NUL) or n=2 (two characters).
PUSH ESI shifts ESP by four; `[ESP+6]` is local+2 and spans second WCHAR+NUL,
only on n=2. Local padding [6,8) remains unknown and is never readable by the
proof. Protected return/saved words are not output memory. Cleanup restores ESI
and removes the eight local bytes on every normal terminal path. This stack
relation assumes a valid stack and normal ABI-compliant imported return; the
small Python model does not implement a complete stack machine or ABI verifier.

Each character guard computes low16(c-48), then CMP AX,9 and JA. For every
16-bit c, `(c-48) mod 65536 <= 9` iff `48 <= c <= 57`: adding48 to the accepted
interval0..9 cannot wrap. Thus valid characters refine to decimal digits without
assuming their values. LEA does not alter flags; the following CMP produces CF/ZF
used by unsigned branches. EAX/ECX/EDX and flags after the import are otherwise
unknown until assigned/refined. No stale pre-call flag is used. SF/OF/PF/AF are
not modeled because these paths do not read them; admitting such a consumer would
require separate semantics.

MOVZX discards the upper half of the DWORD. The digit branch rejects before any
numeric interpretation of an invalid low half. For two valid digits the measured
LEAs compute `c1 + 2*(5*(c0-48)-24) = 10*(c0-48)+(c1-48)`, range0..99. No accepted
arithmetic overflows. All application branches and returns in the exact body are
covered by this manual machine-to-model relation. The checker does not derive
the relation automatically or validate arbitrary changed graphs.

## Independent evidence and limits

Eight test functions cover complete result partition, terminator/full-word bounds,
unknown failure/overflow, owner and join rejection, mutated guard/offsets,
interval boundaries, independent arithmetic examples and all65,536 one-word
values against a direct decimal interval oracle. The exhaustive word check is
separate from the algebraic proof; it is not exhaustive Windows behavior or an
enumeration of input pairs. The17 original/prototype pairs remain inherited
contract evidence, not17 translated programs or new model test functions.

The model's State objects are ordinary test data. A caller can construct one;
they must never be accepted as production provenance. Object identity tests reject
foreign owners, but lifecycle/generation, immutable-name/stack-alias disjointness,
import side effects and PE metadata closure are premises, not newly implemented
checks. In particular, no API execution may grant a real buffer capability from
caller-provided initialized-byte counts. Model mutations exercise unsafe reads;
changed but memory-safe graphs may have different results and are rejected by the
exact byte-profile gate rather than blessed by the parameterized test model.

## Concrete implementation gates

After medium review, a bounded Astra implementation design must connect the model
to the production owned-image and tagged-stack system before emission:

1. Create a private effect certificate only from checked import/relocation/name,
   full live six-byte buffer provenance and disjoint protected regions. No public
   State/Boolean/model report can authorize execution. Full metadata rejection
   persists; certificate failure must have no permissive fallback.
2. Add runtime symbolic scalar/length state and path-refined initialized bytes,
   exact observed16/32-bit forms and unsigned flags. Validate every branch of the
   fixed acyclic body, all full-width reads, saved ESI and normal stdcall cleanup.
   Unknown data remains runtime data, never folded from a baseline environment.
3. Define a bounded native acquisition boundary. Current prototype `std::env::var`
   copies an unbounded host string before checking64 units. Production must choose
   and review a safe ownership/lifetime strategy with capped decoding and explicit
   allocation bounds, case-alias detection, stable environment and invalid-byte/
   surrogate/NUL rejection. No unsafe borrowed host pointer without lifetime proof.
   This is an unresolved architecture prerequisite, not a solved feature here.
4. Preserve observable zero/error projection without claiming general LastError
   emulation. Further API consumers or environment mutations invalidate this
   narrow effect contract. Keep exceptional/faulting paths outside the admitted
   domain and explicit; do not silently force success.
5. Require unchanged PE -> deterministic Rust -> ELF for all17 frozen runtime
   inputs, same ELF changing exit with values7/42, conversion independent of its
   environment, and independent guard/owner/metadata negative regressions.
   Standalone prototypes and this conditional model cannot satisfy that gate.

No source/flags were changed to fit the converter. Existing12 compiler pairs,
102 authored pairs,18 launches and four held-out rejections stay required. Windows
Server2025 evidence is not XP/7 compatibility. Four historical timeout causes
remain unexplained; the earlier JSON encoding defect is separately documented.

Run `python3 -m unittest discover -s research/input -p test_model.py -v`.
Run `python3 research/input/check_model.py EVIDENCE` on the measured Windows
artifact directory, then `--compare` against the same directory on Linux. The
report includes PE/code/model-source hashes and always denies emission.
