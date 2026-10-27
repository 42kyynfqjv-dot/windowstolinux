# Cross-compiler scalar and loop integration (SUB-572)

SUB-571's frozen LLVM 20.1.8 configuration and seven source/oracle hashes remain
unchanged. Its historical result was six rejections and 186 Windows observations.
This integration targets all six fold/tabs/escape O1/O2 outputs in one shared
streaming path. No source, compiler option, PE instruction or import is rewritten.
The original measurement is retained in RESULTS.md and INVENTORY.json.

## Instruction and state contract

Primary architectural contract: Intel SDM Volume 2, MOV/MOVZX, SETcc, CMOVcc,
NOT, ADD/SUB/INC/DEC, AND/TEST and NOP entries:
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html .
Implementation is independent Rust, using the existing locked iced-x86 decoder.

Normalized registers carry a base register, width and bit offset. AL/CL/DL/BL
and AH/CH/DH/BH overlap their 32-bit parent correctly. A byte write preserves
other runtime bits. The frame proof tracks a 32-bit definedness mask, intersects
it at joins and transports it through scalar word spills and reloads. Unknown
bits do not become known zeros. Overwriting a byte of an opaque handle/pointer
forgets the other bits' scalar authority; reading those original bits as scalar
still rejects. Numeric proof representatives for unobservable opaque bits carry
no execution authority. The emitter preserves the actual runtime bits.

Exact unprefixed byte SETNE and register32 CMOVAE are added to the existing
conditional forms. SETNE and MOVZX preserve flags; NOT preserves flags. Byte
AND/TEST and comparisons have exact CF/ZF effects. The emitter always performs
the decoded arithmetic, including byte carry/wrap and high-byte preservation.
Only CF/ZF conditions are admitted. Memory MOVZX requires a complete initialized
owned byte, with the same address/provenance checks as ordinary byte loads.
A byte read from a fixed scalar word uses that word's corresponding knowledge
mask. General partial stores into tracked scalar words remain rejected by the
separate byte-region proof. Word-register forms and unrelated prefixes remain
unsupported. Alignment NOPs admit operand-size repetitions and a CS override
only on decoded 0F1F /0; these have no memory effect. The decoder retains the
architectural instruction-length and boundary checks.

## Modular arithmetic and inductive bounds

Scalar ADD/SUB and INC/DEC now encode exact unsigned 32-bit wrap. Bounded linear
cases avoid expensive general modulo when one wrap suffices; LEA with one base
and signed displacement uses the same exact cases. Full address ranges and
initialization must still prove independently. LLVM's column counter can cross
2^32: there is no assumption about total input length. NOT followed by TEST of
the low two bits is modeled exactly, while native code keeps the full counter.

Candidate discovery inventories the actual graph, including rotated and JNE
counted loops, memory MOVZX, multiple ReadFile sites and partial-write loops.
It proposes bounds on expansion rate, input index and initialized output frontier.
The tab inner-loop candidate uses the modular column residue. Every candidate
is checked at entry and every incoming edge before being used as a continuation
assumption. False candidates reject; they cannot seed reachable states, replace
graph behavior or grant emission. Candidate discovery is bounded to 64 hints.
It remains incomplete: other valid programs can reject when discovery or the
solver cannot establish their invariants.

Fresh ReadFile epochs replace the input prefix, while independent output storage
retains only its proved initialized prefix. Read counts, returned write counts,
zero progress, EOF, pending state and failure branches retain the existing API
contract. This proves memory/observation safety for the admitted synchronous
subset, not termination of an arbitrarily supplied stream.

Z3 remains a local compiler dependency with the unchanged 4.15.4 version lock,
20-million resource/query, 15-second/query, 25-second/process and 512-MiB limits.
Every query must be UNSAT; SAT, UNKNOWN, errors and exhaustion reject. Generated
ELFs contain no Z3, decoder, Wine or AI dependency.

## Reproduction and evidence gates

Run `measure.py OUTPUT --require-translation` in the pinned Windows environment,
then `check_native.py OUTPUT --require-translation` on Linux. The shared native
checker requires identical PE hashes and generated Rust, 186 exact stdout/stderr/
exit comparisons (28 file/pipe plus three real failure cases per artifact), and
144 separately labeled scripted backend runs. Real OS executions do not claim
to force every partial-write schedule.

`stateful/check_partitions.py OUTPUT` exercises 224,988 additional Linux-only
partition/EOF executions across the six emitted programs using independent
whole-sequence byte oracles. `check_safety.py OUTPUT` requires 18 mutated-PE
rejections, two SAT results for false modular expansion invariants, and two
solver-exhaustion rejections. Original hashes and output sentinels are preserved.
Some malformed PEs reject through proof exhaustion; those are conservative
rejections, not claimed counterexamples. The false-invariant tests require SAT.

The root suite has 129 unique test functions, three added here. The new native
emission test runs 97 independent byte-alias, carry, flag-preservation, scalar
spill-related and near-2^32 loop vectors. Example targets repeat inherited tests;
those are not additional unique functions. Prior MSVC, authored and runtime-input
comparisons remain required in full CI. Final commit/run and artifact results
are recorded in the PR and Linear after CI, not inferred from local acceptance.

## Limits and review

The six programs use an explicit custom entry, bounded valid stack, stable
synchronous file/pipe handles and the reviewed four-function kernel32 contract.
They do not establish ordinary CRT startup, general memory/API support, PE32+,
application compatibility or Windows XP/7 behavior. Windows baselines use the
recorded modern hosted runner. Seven historical original-Windows launch timeout
occurrences remain unexplained; failure diagnostics and thresholds are preserved.

Review must check the mask-to-numeric proof boundary, all incoming invariant
obligations, modular counter wrap, scalar-word byte aliases and cross-host hash
provenance. A useful next validation gate is a bounded held-out streaming corpus
with different state/control composition across both pinned compilers, evaluated
without support changes, before another capability expansion.
