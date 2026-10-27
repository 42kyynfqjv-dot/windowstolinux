# Stateful CRLF integration

The unchanged frozen O1/O2 programs are compiled mechanically through the shared
stream graph, frame proof, Horn constraints and native emitter. Application
branches, pending-CR state, byte copies, final flush and error exits come from
instructions. No filename/hash/input schedule selects behavior. The original
measurement remains in RESULTS.md; this document records the later implementation.

## Proof and execution contract

- Exact unprefixed register32 CMOVE uses known ZF, selects one scalar value and
  preserves flags. Both source and destination must have full scalar knowledge;
  opaque pointers/handles/functions, ESP destination, memory and other widths
  remain outside this form. Intel SDM Volume2 CMOVcc is the instruction contract:
  https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
- Frame ownership and protected slots remain mandatory. Fixed scalar words and
  the complete ReadFile region partition live allocations into disjoint byte
  regions. These are machine-frame ranges, not inferred C array declarations.
  The CRLF output range includes three bytes of linker/compiler frame padding;
  the proved loop relation bounds actual output to input length plus one (129).
- Each region carries a lower bound on its contiguous initialized prefix. An
  output store may overwrite or append exactly at that frontier; a gap cannot
  create initialization. Reads and WriteFile require complete initialized ranges.
  Byte accesses cannot alias tracked words, protected saves or absent allocations.
  Free/reallocate invalidates the relevant proof facts. Output initialization
  persists across a read; only input initialization is replaced by a fresh read.
- Input byte stores remain restricted to its current initialized prefix. The
  guest count word aliases the proof prefix only after a structural unique-writer
  check. Otherwise independent state tracks guest n and initialized input. CRLF's
  n=0 EOF store cannot retain/create permission for stale bytes.
- Finite sets (up to eight values, then unknown) preserve small scalar control
  facts across joins, words and calls. Arithmetic is u32 wrapping in this auxiliary
  domain; existing no-wrap/safety obligations still apply where required. Every
  incoming transition validates its numeric/finite domain before it is assumed.
- A bounded graph heuristic proposes a capacity hint for indexed input/output
  loops with one changing binary state: output_index + state <= input_index + 1.
  Discovery is not proof. The first Horn system proves each hint on the entire
  graph **without assuming any hint**. A reset starts the final system, which uses
  the established hint and checks all safety/known-state/domain obligations.
  Only all-UNSAT output from both systems admits emission. SAT, UNKNOWN, missing
  results, solver errors and exhaustion reject; there is no strategy retry.
  The first system retains the existing first-violation safety transitions: hints
  concern safe prefixes. The final system checks every possible first violation.
- Same pinned Z3/version/license; one process, 25-second total, 15-second query,
  20-million resource limit per query, 512MiB, 8MB combined text and 1024 combined
  queries. No solver or PE decoder is emitted into the native runtime.

The native memory and I/O adapter retains exact instruction operations, actual
read/write counts, binary bytes, pipe EOF109, error exits and partial writes.
The source transform removes only CR immediately followed by LF, preserving lone
CR/LF and all other bytes. Pending CR survives reads and flushes once on successful
EOF; non-EOF read failure does not promise to flush pending/unwritten bytes.
Regular files and synchronous byte pipes, stable single-thread endpoints and valid
stack remain assumptions. No total stream termination claim is made.

## Evidence gates

- Both unchanged compiler-produced PEs: 78 actual Windows/ELF stdout/stderr/exit
  pairs, same PE hashes and byte-identical generated Rust across hosts.
- 24 frozen separately scripted schedules/failures per emitted build (48 runs),
  compared with the original separately authored Windows backend probe.
- 18,725 short input/partition combinations per build, each under file and pipe
  EOF: 74,900 native generated-program runs. The independent oracle removes CR
  positions immediately followed by LF from the complete input. These are Linux
  backend executions, not extra Windows observations or exhaustive arbitrary input.
- Unsafe separate PE mutations: output gap, missing initializer, input underrun,
  inclusive bound, count/output alias, unknown source/count and protected restore.
  Solver unavailable/exhausted checks preserve the destination. A deliberately
  false capacity hint must return SAT in the independent first system.
- Prior uppercase, ROT13/reverse-XOR/compaction, runtime-input and authored suites
  remain required. Independent emitter vectors cover CMOVE result and both CF/ZF
  preservation alongside previous arithmetic boundaries.

Local development matched the recorded Windows baseline and all scripted/partition
cases. Fresh final-commit CI is required for cross-host source/hash confirmation.
Six historical original-Windows timeouts remain unexplained; deadlines, failure
propagation and persistent diagnostics are unchanged. Windows Server2025 evidence
is not XP/7 validation. Ordinary CRT, general applications, arbitrary memory,
consoles/devices/async I/O and PE32+ remain outside the demonstrated subset.

Reproduce: run measure.py in the documented x86 MSVC environment, then run
check_native.py, check_integration.py and check_safety.py on that exact artifact
with the pinned local Z3 and Rust toolchain. Original source/flags/expected files
retain their frozen hashes. Review is required before merging this milestone.
