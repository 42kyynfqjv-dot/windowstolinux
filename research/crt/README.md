# SUB-538: ordinary x86 CRT entry decision

Decision: retain rejection of the three ordinary x86 programs. Select held_crt as
the first ordinary-program target, but neither a startup replacement nor mechanical
startup translation currently has a complete effect proof. Do not jump to main.
This report establishes dependencies and the next proof gate, not CRT support.

## Reproducible evidence

Snapshot inventory-40313382722.json comes from CI40313382722, commit
3e1f6c2ce70120671ca5b4af07e730f10e1f01b6, artifact12645986081. It records exact
unmodified PE/source hashes, frozen source commit, flags, compiler versions, entry
edges and original observations. Source LF bytes were verified against the frozen
commit. Compiler19.51.36260.0/linker14.51.36260.0 used /O2 /W4 /c /MD, normal console
linking, no /ENTRY override or /GS- for these three programs. The runner is Windows
Server2025 build26100. These are available toolchain versions, not a permanent pin.
DLL import names are contracts, not proof of loaded DLL versions: actual runtime
module paths/versions/hashes and actual image load base were not captured.

Reproduce with `python3 research/crt/inventory.py ARTIFACT_DIRECTORY`. The utility
verifies source/PE hashes and directly checks entry CALL/JMP bytes and mapped target
ranges. Directory/cookie data comes from PE bytes. Import names and indirect-transfer
addresses come from dumpbin reports; this is not an adversarial production parser or
complete reachable graph. Whole-disassembly counts include potentially dead paths.
Reports always set complete_reachable_graph=false and emission_allowed=false.
CI regenerates reports from fresh unchanged compiler outputs on both hosts.

| Program | Entry RVA | Entry call / jump RVA | Imports | Original observation |
|---|---:|---|---:|---|
| held_crt | 1300 | 1610 / 1110 | 37 across7 DLLs | stdout CRT, empty stderr, exit0 |
| held_args | 1310 | 1620 / 1120 | 37 across7 DLLs | stdout Args, empty stderr, exit68 |
| held_file | 13b0 | 16c0 / 11c0 | 40 across7 DLLs | stdout Data, empty stderr, exit0, held.txt=Data |

All addresses above are hexadecimal. All have relocation/import/IAT/debug/load-config
directories; TLS directory is absent. Load-config size64 includes security-cookie VA
403040. Absence of PE TLS does not remove imported DLL initialization or conditional
CRT TLS callback logic. Inventory lists43/43/49 indirect call/jump occurrences,
including IAT thunks; these are not counts of executed calls or resolved dependencies.

## Actual startup obligations in held_crt

Entry1300 calls1610 before jumping1110. The first routine reads cookie403040,
compares the default BB40E64E, gathers system-time/thread/process/performance-counter
values through IAT calls, then writes cookie and complement403080. Identifying this
as cookie initialization is supported by bytes/data flow and Microsoft's contract;
there is no symbol/PDB proof for every internal routine name.

At1110 the startup body builds an EBP frame and FS:[0] exception chain, reads the
cookie and mutates globals. It calls _initterm_e via thunk1cc4 with ranges20c4..20d0,
and _initterm via1cbe with20b8..20c0. The table contents and all possible callback
side effects still require independent closure analysis. Around11e7..1232, conditional
callback checks include indirect CALL ESI at1210 and TLS-exit registration. Those
paths cannot be erased from an observed successful trace. At1235..124c, initial
environment and argc/argv accessor calls supply arguments to direct target1000.
That target's body calls __acrt_iob_func(1) and fwrite for the authored CRT string;
source correspondence supports identification, but is not permission to bypass entry.
Post-call paths include exit/_exit, cleanup and exception filtering.

Dependencies include KERNEL32 entropy/CPU/exception/module services; VCRUNTIME
exception context and _except_handler4_common; UCRT runtime initialization, argv,
environment, onexit tables, termination; stdio mode/stream access/fwrite; locale,
math and heap policy. Startup also contains CPUID/SIMD, global mutation, stack/SEH
and indirect flows outside current execution support. held_args additionally makes
argc and argv bytes observable; held_file requires mutable buffers, FILE ownership,
open/read/write/close errors and filesystem effects. PE32+ requires a separate x64
ABI and address model and is not advanced by this x86 decision.

## Native-entry alternatives and chosen gate

Mechanical startup translation preserves the original entry and exposes each
instruction/import effect to validation. It needs a sound reachable graph, typed
mutable globals/stack, SEH/TLS/callback policy and independent native contracts for
imports. It is the conservative default, but far beyond one opcode addition.
A native startup support contract might replace a proven region only after its
observable state, initialization ordering, error and exit behavior are established.
Current evidence cannot justify such replacement. Similar code bytes, source main,
empty TLS directory or one successful run are insufficient authority.

The smallest defensible candidate domain is this unchanged held_crt image, one
thread, normal loader, successful redirected regular-file stdout, documented locale/
encoding and no asynchronous mutation. It still needs proved initialization/cleanup;
these conditions do not excuse skipping callbacks, cookie or buffering. Incidental
addresses, cookie entropy values and CPU dispatch choices may be abstracted only
if no admitted behavior observes them and consistency/security checks are preserved.
Exact stdout bytes, return value, errors, flush and destructor/onexit ordering are
observable. FILE objects remain opaque typed handles, never guessed layouts.

Next bounded gate (Astra High after medium review): startup control-flow and
initializer closure for held_crt. Use iced decoding from the actual entry, checked
instruction boundaries and relocation/IAT bindings. Enumerate both conditional
successors and call continuations, classify external calls without assuming return,
resolve initializer/callback tables or report explicit unresolved edges. Include
exception/nonlocal exits; normal graph reachability alone is not full proof. Produce
a per-effect ownership/state contract for cookie, startup globals, argc/argv/env,
stdio and termination. Stop with rejection if closure cannot be shown. No production
startup support before this gate and subsequent contract review.

Acceptance for that gate: independently checked byte/target/table expectations;
negative changed callback, overlapping table, unresolved indirect call, altered init
order and failure-exit cases; runtime module version/hash and original load-base
observation where possible without changing binaries or security settings. Authored
separate probes must cover init failure, callback order, exit versus _exit flush,
argument quoting/encoding and file short/error results. Probe successes are not
translations. An eventual implementation must consume identical original PE hashes
on both hosts and compare stdout/stderr/exit (plus files where applicable), preserve
all12 compiler/102 authored comparisons and18 original launch diagnostics.

## Primary contracts and provenance

Reviewed Microsoft documentation on2026-10-26:
- https://learn.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol
  Default console entry mainCRTStartup invokes main; the linker recommends default
  entry to initialize the CRT and static constructors.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/crt-initialization
  Ordered initializer groups and toolchain-specific startup internals.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/security-init-cookie
  Initialization precedes protected functions; bypassing it compromises checks.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs
  Argument/environment construction contract. These images import newer accessor
  functions; this page alone does not specify all their behavior.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/exit-exit-exit
  exit processes TLS destruction/onexit and flush; _exit/_Exit omit those effects.
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
  Directory/address/load-configuration structure; earlier project PE review applies.

Original report/tool/source remain MIT OR Apache-2.0. No Microsoft/Wine implementation
source imported or ported, no clean-room claim. Toolchain-linked startup bytes have
their own redistribution terms: this report commits hashes/factual metadata only,
not executable images or copied runtime implementation. Existing CI artifacts retain
their prior provenance; any future runtime-source reuse/distribution needs separate
license review. DLL internals/version-dependent behavior remain unresolved research.
Windows evidence is not XP/7/general-app compatibility. Actual load base and three
historical timeout causes remain unknown; no silent retries. Production unchanged.

## Medium review: evidence boundaries and safe next probes

The snapshot inventory reproduces byte-for-byte from artifact12645986081. Entry
edges/cookie location are byte checks; import names are dumpbin references; callback
and exception paths are static observations. Original process output is dynamic
success evidence only. No callback reachability, actual cookie entropy, runtime DLL
version or startup failure behavior has been observed by this inventory. The script
is deliberately limited to trusted authored reports, not a production hostile-input
parser. Its import counts do not independently validate PE import-table integrity.

SUB-539 should freeze these separate probes and expected outcomes before execution:

1. A small independently authored C probe registers two atexit callbacks that append
   distinct bytes to a private file; normal exit must record reverse registration
   order. A separate invocation uses _exit and must leave the marker file empty.
   Do not use buffered stdout to infer callback order. Check all file/registration
   return values and fail the probe on setup failure.
2. A separate stdio probe sets full buffering explicitly, writes one byte without
   newline to redirected regular-file stdout, then calls exit or _exit in distinct
   invocations. Success expects the byte only for exit. Require successful setvbuf/
   fwrite and empty stderr; distinguish test setup errors from semantic mismatches.
3. Test-only initializer-table traces independently specify null entries, ordered
   callbacks, failing C initializer and unresolved/overlapping callback ranges.
   A model trace is not Windows startup evidence. A future original Windows probe
   must document its supported compiler hook; do not depend on undocumented section
   ordering and then call that ordering portable or production-supported.

Use fixed source, compiler flags and source/PE hashes; empty private working folders,
no inherited secrets, no shell commands from program input, no destructive file
paths. Bound each launch to15seconds and preserve diagnostics on failure, no silent
retry. These are new authored probes, not edits to held_crt. Argument quoting/encoding
and file short/error probes belong to later runtime-input/file contracts, not an
unbounded prerequisite for the first held_crt success domain.

For runtime provenance, use a separately built/hashed authored observer with existing
Windows debug APIs on only the exact hashed child PE. Record CREATE_PROCESS_DEBUG_EVENT
image base and LOAD_DLL_DEBUG_EVENT paths plus on-disk version/hash where resolvable;
close event file handles, continue events correctly and terminate only the owned
child on timeout. No injection, code patching, privilege adjustment, system debugger
configuration or attaching to unrelated processes. Do not copy or execute DLLs at
new paths. API-set import names may resolve to different host modules. Missing paths,
access or races remain explicit gaps. A module-file hash does not verify all in-memory
bytes. Debug observation changes scheduling and is a separate observed run; keep the
ordinary baseline/hash/output comparison independently. Compare both observations,
never silently substitute one for the other or infer all loaded modules are used.

Astra High is appropriate for SUB-539's bounded control-flow/initializer effect
analysis. Medium review found no production defect; production remains unchanged.

SUB-543 adds an isolated Rust local sentinel effect; see
[SENTINEL-IMPLEMENTATION.md](SENTINEL-IMPLEMENTATION.md) for binding, known-state,
flags, stack obligations and independent CPU comparisons. It does not close CRT
startup or enable ordinary CRT translation. Earlier __p__commode alias/state effects
and later process exit registration remain unresolved.
