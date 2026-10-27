# SUB-577 production heap integration

The same normalized graph, frame analysis, constrained-Horn-clause proof and native
basic-block emitter now handle the frozen grow/shrink programs. There is no
program-name, hash, source-pattern or expected-output dispatch in the compiler.
Sources/configurations/expected vectors frozen at f188f69 are unchanged.

## Admission and layout contract

- One owned, available default process heap; stable opaque handle identity. This
  models the documented default-heap domain, not arbitrary handles/private heaps,
  startup failure, SEH, concurrency, callbacks or other allocator users.
- Exact named KERNEL32 imports, checked ILT/IAT/name ranges, distinct metadata,
  relocation-bound function loads and proven indirect-call tokens. The allowlist
  now includes GetProcessHeap, HeapAlloc, HeapReAlloc and HeapFree alongside the
  existing four stream functions. Larger tables are not execution authority.
- At most eight acyclic allocation/resize call sites. Every site also proves its
  `used` bit false before the call. Requests prove 1..4096 bytes; flags are exact
  0/HEAP_ZERO_MEMORY (free: 0). More general allocations remain rejected.
- Registers and aligned local words carry heap-handle or allocation-site-plus-offset
  provenance. Saved registers/protected return storage retain their previous rules.
  A zero predicate can refine aliases of the *same base result*, including spills,
  on the zero successor only. Calls/flag writes invalidate that predicate.
- Heap bytes can be read/stored and borrowed by WriteFile after complete range,
  live-owner and initialized-prefix proofs. Heap word access and ReadFile into heap
  storage remain outside this slice. Out-of-order initialization with holes needs
  a richer domain and is conservatively rejected.
- Allocation success/failure is symbolic. Failure returns zero without creating
  storage. Reallocation failure preserves the old live object, prefix and bytes;
  success invalidates its proof identity, preserves the common prefix and defines
  only a zero-requested new tail. Free requires the exact live allocation base.
  Old aliases reject even when native allocation happens to reuse the address.
- Proof coordinates use distinct aligned canonical bases. Emitted registers keep
  actual numeric guest addresses from the shared Space. Canonical coordinates are
  sound only for the admitted placement-independent observations: base null tests,
  same-default-heap identity, proved owner-relative accesses, and the low three
  alignment bits. Other pointer bits/order/printed addresses/move observations
  are not scalar knowledge. Partial writes preserve real upper bits in native
  code while the proof withholds unknown-bit authority.

Immediate logical SHL/SHR counts use x86 five-bit masking, preserve flags at count
zero, and make CF unavailable when the nonzero count reaches/exceeds operand width.
Only CF/ZF are observable in this graph policy. OR, partial lanes and zero-extension
retain their independent width/flag checks. No new signed/overflow-flag support is
implied. Instruction contracts: Intel SDM Volume 2, OR and SAL/SAR/SHL/SHR entries
([official manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)).

## Proof and runtime boundary

Every incoming edge proves its successor domain before assuming it. Every memory
access and API borrow proves live owner/full bounds/definedness. Every allocation
outcome is considered, not merely the observed Windows successes. Unknown/timeout,
resource exhaustion or a counterexample rejects without replacing the output file.
The existing pinned Z3 remains compiler-only. No interpreter, Wine or AI runtime is
introduced. Native code executes the actual lifted instructions and runtime branches.

The existing checked-memory core backs both frame and heap. Its process identity,
generations and definedness still guard runtime accesses. Native execution assumes
available bounded resources: allocation infrastructure failure is explicit contract
exit125, not invented Windows NULL/SEH equivalence. The trusted scripted backend
can inject allocation failure to exercise generated cleanup code; these tests are
not Windows OOM measurements. Valid HeapFree is modeled as successful; invalid frees
reject. LastError knowledge is preserved on failed allocation/resize and invalidated
on unspecified successful effects. Existing restricted I/O/error observations apply.
Invalid standard-handle values reach the API's failure result, not an assumed
successful read/write; memory/provenance obligations still apply on those paths.

## Evidence and reproduction

Windows `measure.py OUT` builds both unchanged PEs, records 32 independently expected
successes and four real redirected-file I/O failures, then converts each PE. Linux
`check_native.py OUT` verifies PE hashes, byte-identical Windows/Linux generated Rust,
compiles it and compares 32 successes plus four failures. Its separate 32 handwritten
component matches are **not** counted again as translated evidence.

`check_translation.py OUT` exercises the actual emitted programs with 240 scripted
allocation/resize-failure, short-read, one-byte-write, zero-progress and write-error
cases, plus 508 additional native inputs outside the frozen 16-case set. These have
no additional Windows observation claim. Thirteen production rejection checks include
unknown initialization, invalid sizes/flags, stale resize aliases, layout observation
and solver exhaustion; each report retains the actual diagnostic, so a structural
rejection is not described as a proved memory counterexample. Mutated unsafe PEs are
never executed. The original PE files remain untouched.

Six new unique root test functions cover types/knowledge/predicates and checked-handle refinement, exact import
bounds and normalized shifts; 15 literal native shift/OR vectors extend an existing
emitter test. Ten heap-component tests and earlier evidence remain inherited.
Per-run artifact reports and exact-head CI determine measured outcomes; local runs
against saved Windows baselines do not establish fresh cross-host generation.

ISCC/rcedit and ordinary CRT/startup/module/API composition remain rejected. Modern
Windows Server 2025 evidence is not XP/7 or general-application compatibility.
Historical original-Windows timeout causes remain unresolved.

## Preserved integration CI regression

The first integration head 2754d7f passed the fresh heap Windows build/conversion
and local replay of its exact artifact, but PR run40563615088 rejected an existing
CLI v2 conversion: Z3 exhausted its unchanged resource budget at a 133-property
proof. The new invalid-handle failure alternative enlarged the solver search. This
was a converter proof-budget regression, not an original-Windows launch timeout.

The correction propagates finite handle outcomes along actual checked equality
branches. Each refined fact is still a successor-domain proof obligation, including
invalid outcomes on the failure join; no valid-handle fact is assumed and no solver
limit is increased. A separate root regression checks both branches and predicate
invalidation. Both unchanged O1/O2 failure-run artifacts and both heap programs
then proved locally. Exact-head CI must recheck the entire earlier corpus.
