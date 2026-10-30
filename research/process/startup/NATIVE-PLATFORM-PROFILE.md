# Declared native synchronization profile and original load call

The component now accepts an explicit `w2l-native-sync-20348-v1` environment.
This is a bounded native replacement profile, not a claim that a Linux process
has the complete Windows 10.0.20348 loader state. The versioned mapping comes from
[the retained x86 Windows API-set observations](API-SET-BOUNDARY.md):
`api-ms-win-core-synch-l1-2-0[.dll]` resolves to the load provider `kernelbase.dll`.
Only ASCII case variation and the optional `.dll` suffix are admitted. Unknown
profiles, contract versions, ordinary DLL names, path/search overrides, nonzero
reserved arguments and flags other than `LOAD_LIBRARY_SEARCH_SYSTEM32` (0x800)
reject. There is no fallback to a Linux shared library or a supplied success bit.

## Minimum predicates, without conflating separate calls

| Predicate | Observable requirement or internal restriction | Current status |
| --- | --- | --- |
| Original CALL, actual UTF16 name/flags, protected stdcall return | Original program inputs/control flow; owned pointers and exact byte certificates are internal proof machinery | Checked in original loader graph, generic effect checker and native adapter |
| API-set mapping and source-module identity | Windows-observable name/handle relationship; version selection is an explicit platform premise | Revision 1 admits only the observed synchronization mapping; all other profiles/maps reject |
| Replacement provider ready before guest entry | Native platform initialization; not execution of Windows DllMain | Real owned construction transaction prepares root and implemented descriptor before component entry; returned failure issues no profile |
| One owned reference for successful acquisition, live identity and cache write | Observable module/reference semantics; serial/capability representation is internal | Actual acquisition, original XCHG cache publication, replay/stale checks |
| Resource behavior of this acquisition | Native bookkeeping must not introduce a fabricated Windows load failure | Fixed 256 reference slots including roots; fixed name/check buffers and allocation-free delta checks; exhaustion rejects component execution, never returns guest null/error1114 |
| InitializeCriticalSectionEx resource/failure semantics | A **later API call**, not an effect of LoadLibraryExW | Not a prerequisite for this acquisition slice; remains a prerequisite before executing that operation in a translated complete path |
| GetProcAddress and function-cache publication | The next original API operation | Not yet bound by the native platform adapter; stops at CALL0x402ae0/IAT0x415070 |
| Arbitrary DLL attach/detach/TLS/reentrancy and their failures | Observable effects for ordinary executable DLLs | Not in this profile. Ordinary failure1114 observations do not certify arbitrary rollback or native initialization |
| Complete process initialization, incoming chain, delivery, exit and resource bounds | Whole-program equivalence and admission | Still open; default converter admission remains rejected |

The earlier provider document incorrectly grouped future synchronization failure
semantics with the immediate load-call prerequisites. This table separates them.
It does not remove the future API gate or infer Windows success from unused native
capacity. The declared native environment supplies resident replacement behavior;
it does not prove that every Windows process has the same initial state. Selection
of this profile is explicit in the component API, not automatic based on PE name,
hash, observed outputs or the runtime host version. Production admission remains
blocked until a complete program has a justified environment and resource proof.

## Resource and lifetime policy

Native bootstrap may allocate owned provider names, maps and export storage.
It runs before guest entry. Its returned failures produce no guest result and
retain the prior cleanup/identity rules. Infallible Rust host-OOM outside fallible
reserves is still a host-execution limitation; this change does not claim a global
recoverable-memory model. In particular, the general compiler/runtime's other
collections have not become allocation-free.

Once prepared, reference acquisition/release, its fixed snapshot, checked UTF16
name validation, and reference-delta verification need no new allocation.
The table uses monotonic serial keys independent of reusable physical slots.
The 256-reference budget is an internal admission bound, not a claimed Windows
loader limit. A future complete conversion must prove its bound or reject before
emission. The component's explicit error on exhaustion is evidence of rejection,
not a semantics-preserving guest error return. Bootstrap exhaustion likewise does
not become Windows error1114. Success marks LastError unknown rather than inventing
zero or promising retention of an unspecified value.

The profile revalidates runtime/initialization ownership, root, source and export
lifetime on use. It checks that this version's implemented target belongs to the
same load provider, rather than generalizing to forwarded exports. The separately
observed HeapAlloc/ntdll case is not admitted. Native root persistence after final
acquired-reference release is intentional for this resident system-provider
profile; it is not ordinary-DLL final-release unloading.

## Connected execution and independent checks

With the explicit profile, the unchanged authored PE entry4017a4 executes the
previous cookie/CPU/EH4/startup path, original LoadLibraryExW at402b00, its helper
return, and resolver module-cache XCHG at402acf. The acquired module is written to
41cd0c: the original table at415d74 contains module index1. Execution stops at
GetProcAddress402ae0, before issuing an export result or initializing a lock.
The default path without a profile still rejects at402b00. Neither path is a
whole unchanged-binary entry-to-exit result; incoming activation/thread state and
other component premises remain explicit.

Independent tests cover unsupported profiles/mappings/flags/UTF16, failed bootstrap,
duplicate provider identity, cross-runtime/thread use, stale and reused handles,
exact reference capacity, sparse reuse with fresh serials, replay and allocator
denial. Eight transport scenarios run with the global allocator refusing all new
allocations; the success scenario must acquire exactly one reference and complete
RET12, and failures must retain reference count and prior error knowledge. Original
entry cases cover the native mapping, stale provider, readonly name/storage,
reference exhaustion and changed original load-helper code. Default and previously
changed-code cases remain required.

The initial connected assertion used module cache slot0; unchanged PE inspection
showed index1. That test failure is retained locally in
`platform-predicates/replay/cookie-record.stdout`; the corrected assertion checks
41cd0c. No source bytes, expected guest behavior or failure threshold were changed.
This is a test-expectation correction, unrelated to historical Windows timeouts.

## Next bounded integration

Bind named GetProcAddress to the already implemented descriptor using actual
module reference and export-target authority; execute original function-cache
publication and return. Independently test unknown symbols, stale source/target,
wrong module, duplicate/refcount changes, changed code and failure ordering.
Then validate the original constructor's pointer/index/ABI and retain the still
open synchronization resource/failure domain before invoking it. No new loader
probe is required merely to justify native reference bookkeeping. Fresh original
Windows evidence is required for any wider claim about initialization failures,
unloading, resource failure or OS-version semantics.

See [evidence/native-platform-profile.json](evidence/native-platform-profile.json)
for hashes, test results and CI provenance. Full startup/rcedit and historical
Windows process-exit timeout causes remain unresolved. PR45 remains draft.
