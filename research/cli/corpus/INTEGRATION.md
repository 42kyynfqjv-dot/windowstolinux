# Shared streaming scalar and ownership integration

The six sources, flags and expectations frozen in d4abc13 are untouched. Full
O1/O2 disassembly inventory found a shared error-selection expression, byte
transforms, reverse counters, scalar LEA, local word spills, a memory PUSH, and
compiler alignment NOPs. Production changes operate on normalized operands and
shared graph/frame/logic/emission paths; no PE hash, program name, result or graph
template controls admission.

## Arithmetic and error observations

Primary instruction contract: Intel Software Developer Manuals, instruction
reference for NEG/SBB/AND/DEC/LEA/MOV/PUSH and EFLAGS:
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
Windows error contract: https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
The existing runtime distinguishes ERROR_BROKEN_PIPE109 from other errors;
it does not reproduce every numeric Windows error on Linux.

Opaque errors carry an affine value `(a * error + b) mod 2^32`, where a is1 or-1.
Moves and constant ADD/SUB/NEG preserve that provenance. Raw results cannot escape
through stores, addresses, partial reads or process returns. SUB/ADD flags stay
unobservable. NEG's zero/carry flags become observable only if the unique zero is
error109: `a*109+b == 0 mod2^32`. This algebra supports either sign, different
constant sequences and register choices; it does not recognize an instruction
sequence. NEG produces CF iff its input is nonzero. Self-SBB cancels its operands
and materializes the already-approved carry as0 orUINT_MAX. This result is scalar;
an immediate AND can mask it. Wrong roots/unknown carry reject. Ordinary CMP109
continues to expose only the reviewed equality predicate.

The native emitter performs actual32-bit wrapping arithmetic; the safety solver
models opaque affine arithmetic, NEG and SBB modulo2^32. AND-immediate is encoded
as a sum of selected binary digits. Scalar ADD/SUB/INC retain their existing
no-wrap admission limits. DEC requires a provably positive scalar, subtracts1 and
preserves CF. Only CF/ZF are consumed by admitted branches; SF/OF/AF/PF observation
is outside this graph policy. Byte contents/flags remain conservatively abstracted
for safety while emission performs exact byte arithmetic and preserves upper bits.
SBB requires defined, observable carry even for byte destinations.

## Frames, aliases and loops

Fixed aligned owned local words now participate in state, rather than only API
count cells. A word spill can retain a standard-handle type; mixed/absent typed
values at joins lose initialized authority. API count writes produce scalar cells.
Every word lies wholly in an owned local allocation and is disjoint from the full
read buffer. Byte access remains confined to the current initialized prefix;
word/byte aliases and protected slots cannot bypass this proof. Memory PUSH reads
its source before decrementing ESP. Unknown or unaligned word addresses reject.

Scalar LEA computes low defined bits without inventing unknown upper bits. Full
address uses still require defined32-bit owned pointers. The frame worklist checks
all structural edges; Horn obligations check reverse-counter and compaction index
relations across actual cyclic control flow. Every fresh ReadFile replaces prefix
state; the unique read-count writer and disjoint count/word rules are preserved.
The two additional exact compiler alignment NOP encodings have no memory effects;
arbitrary instruction prefixes still reject.

No new solver budget, solver retry, runtime decoder, total-stream limit or total
termination claim is introduced. SAT/UNKNOWN/exhaustion remain emission failures.

## Evidence gates and accounting

- Six unchanged PE→Rust→ELF programs:174 real Windows/Linux file/pipe/failure
  comparisons, with the same PE hashes and byte-identical Rust across hosts.
-48 scripted error results (eight per emitted program), including0,108,109,110,
  INT_MAX,INT_MIN,UINT_MAX;24 forced partial-I/O executions. These are separate
  backend tests of emitted code, not additional original-Windows process pairs.
- Ten separate unsafe PE copies: six wrong error-class roots, two counter-direction
  mutations and two inclusive compaction-read guards. Originals remain unchanged.
-120 root functions (five new functions); the six graph example functions are
  inherited in root and must not be counted again as unique tests. One emitter
  function executes22 independent result/carry checks from11 literal NEG/SBB/DEC
  boundary vectors, including INT_MIN, UINT_MAX and borrow-in wrap. These isolated
  native emission checks are not additional original Windows comparisons. Prior CLI,
  broken-pipe adapter checks,14 safety rejections and previous corpus remain required.

Local accepted executions use a labelled copy of saved Windows evidence with local
emission hashes. They do not establish cross-host source equality; CI must do that
on the final published commit. Historical RESULTS files describe the earlier
measurement/rejection checkpoint. Windows Server2025 evidence is not XP/7 proof;
ordinary CRT/general memory/device/async/application compatibility remains outside
scope. Five historical Windows process timeout causes remain unexplained.
