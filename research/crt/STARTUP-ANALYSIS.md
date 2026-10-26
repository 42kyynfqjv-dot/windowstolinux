# SUB-539 bounded startup analysis

Test-only tools; no production entry replacement or emission permission. The root
iced dependency remains pinned; examples/crt_graph.rs is a separate executable and
is not linked into the converter or generated ELF. It walks ordinary direct control
flow from PE entry, both conditional successors and call continuations, checks code
mapping and overlapping instruction targets, and caps visited instructions at10000.
Indirect edges and traps are explicit. Continuing after a call is an overapproximation
of possible return, not a claim the call returns. RET matching, exception dispatch,
indirect callbacks and import semantics remain unresolved; complete_effect_proof is
always false. This trusted-artifact research parser is not an adversarial PE intake.

On unchanged held_crt from CI40313382722, entry1300 reaches632 normal-flow instruction
addresses with19 indirect sites and2 trap/unresolved sites. These are exploration
counts, not executed instructions, function counts or coverage of exception edges.
The analysis is reproducible on each CI artifact and compared between Windows/Linux.

Independent static table examination in that image (hex RVAs, exclusive ends):
- C initializer range20c4..20d0 contains null, VA401030, VA4010e0.
- C++ initializer range20b8..20c0 contains null, VA4010f0.
- Accessor17a0 returns VA4030f4; accessor17b0 returns VA4030f0. Both slots contain zero
  in the original file. This identifies initial storage, not a no-write proof.
- Calls via _initterm_e/_initterm dispatch these ranges; ordinary direct exploration
  does not automatically follow callback tables. Their target bodies and every prior
  write/import effect need separate analysis before startup can be declared closed.

The first C initializer at1030 includes stdio/app/runtime policy calls, floating-point
state and conditional error paths. Therefore 'no authored global constructors' does
not imply empty initialization. Cookie initialization and FS exception registration
remain obligations. No startup region is certified removable.

## Separate authored probes and observer

exit_probe.c uses documented atexit, exit, _exit, setvbuf and fwrite contracts. Four
runs test normal/quick termination for reverse callback markers BA and a buffered X.
Expected results were specified before Windows execution; setup/error statuses are
checked. The programs are probes, never translated application comparisons.

observer.c creates only its own exact held_crt child with DEBUG_ONLY_THIS_PROCESS,
records CREATE_PROCESS image base and LOAD_DLL paths, closes event file/thread handles,
and enforces a15second deadline. It changes no process memory, privilege or system
configuration. probe.py records source/observer/probe/child hashes, on-disk module
hashes and file versions, preserves the unchanged child hash, and compares debug-run
output to the independently captured ordinary CRT baseline. Versions are recorded
from resolved modules, not inferred from API-set import names. Unresolved paths/errors
remain in the JSON. File hashes are not in-memory verification and debug scheduling
is not ordinary-run timing. External DLL initialization and unobserved branches remain
unknown. No DLL bytes are copied into the repository.

Reproduce on the existing MSVC x86 CI environment with research/crt/probe.py after
compiler/heldout/measure.py; retain crt-probes.json, build logs and crt-debug.txt.
No new credentials or security changes. Probe children receive only Windows system/path/temp variables from an explicit
allowlist; values are not dumped. This is not a general environment equivalence proof.

Primary contracts: Microsoft CRT exit/atexit/setvbuf documentation and Windows
CREATE_PROCESS_DEBUG_INFO, LOAD_DLL_DEBUG_INFO, WaitForDebugEvent, ContinueDebugEvent,
GetFinalPathNameByHandle documentation. Prior SUB-538 primary-contract review applies.
Original implementation MIT OR Apache-2.0, no Wine/Microsoft source port.

Next prerequisite: bound and validate initializer dispatch/table ownership and imported
initialization effects, including possible mutation of callback slots and failure exits.
This requires Astra High design after medium review; successful probes alone cannot
close the effect proof. Keep ordinary CRT/runtime/file/PE32+ rejected, preserve12
compiler/102 authored comparisons and18 launch checks. Three historic timeouts remain
unexplained. Server2025 evidence is not XP/7/application compatibility.

Independent authored graph checks cover RET, a self-cycle, indirect call, outside-code
target, trap and overlapping instruction target. Even a trivial RET and a finite
graph remain explicitly incomplete effect proofs. Six checks are research-only;
they are not new native program comparisons or root Rust test functions.
