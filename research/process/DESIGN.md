# Shared PE32 process contract — SUB-575

Decision: introduce a guest address space and explicit process/effect boundary as
one reusable substrate. Existing profile proofs remain valid for their admitted
programs; they do not confer ordinary CRT or utility eligibility. This pass is
architecture and test-only validation. No production parser, lifter or emitter is
changed. The model is independently authored under MIT OR Apache-2.0.

## Evidence and scope

| Family and exact artifact | Established | Unresolved execution dependencies |
| --- | --- | --- |
| ISCC7.1.0, SHA256 f87212f64f08e0b57b53829c7441719cda73dffbfcfdcf851031b74ee0f9f2f8 | Six original Windows observations;11 sections; imports kernel32/user32/oleaut32/msvcrt/advapi32; actual retained inventories for ISCmplr/ISPP and compression modules | Delphi initialization, managed strings/heap, dynamic module resolution, exceptions, filesystem/console; source rebuild requires unavailable licensed Delphi; runtime redistribution rights separate |
| rcedit source e95698dd8d79b1da648ef70771a709d1bab0ba51; measured PE21efa80badc137bbcfde7d8478dd78b38b67e0081a5b9b1c46331f04d3e6a428 | Eleven original Windows cases;9 sections; VERSION/KERNEL32/USER32 imports; entryRVA688e thunk reaches wmainCRTStartup/security_init_cookie; wmain sets FS:[0] | Static C++ CRT/global constructors, locale/Unicode arguments, heap, exception/SEH, resource mapping/update, dynamic calls and lifetime |
| WinMerge bug52350 lead | Reported Wine10.13 Shell/COM deletion failure; Microsoft deferred-operation contract read | Current failure not reproduced; exact app asset/architecture/license dependencies unpinned; COM apartments, vtables, callbacks, cancellation, GUI; not a whole-app startup failure |

ISCC and rcedit both have a TLS template with an empty static callback list in
these artifacts. This does not remove TLS state requirements or prove dynamic
initialization effects. Static imports/disassembly are not complete reachability
or observed execution. See ../utilities/RESULTS.md, ../utilities/rcedit/RESULTS.md
and ../utilities/WINE-FAILURE-PRIORITY.md for provenance and retained evidence.
No third-party native utility execution is demonstrated. Do not treat missing
Delphi build capability as permission to replace its startup with guessed behavior.

## Reuse and necessary changes

src/stream/graph.rs normalizes operands and cyclic graphs through iced-x86.
Reuse exact instruction semantics and target-boundary checks, extending only after
independent conformance. src/linker/stream/frame.rs proves a bounded relative frame
with saved-register/argument tags; it cannot represent arbitrary process addresses,
heap objects or module TLS. src/stream/memory.rs provides checked4096-byte storage
and32 object slots, explicitly without guest-address admission authority. Its arena
identity is useful for proof tokens but cannot replace x86 numeric pointer identity.
The stream solver verifies inductive input/output ranges; its failure/unknown
remains rejection. The emitter compiles admitted operations and runtime branches.
Unify the new substrate under those operations rather than a new per-utility graph
recognizer. No interpreter or dynamic binary-execution fallback is selected.

## Address, allocation and alias rules

Guest registers carry exact32-bit bitvectors. Effective-address arithmetic wraps
as x86 specifies; a subsequent full access range must be checked without host
integer overflow. Width, segment-base addition and access permissions are explicit.
FS/GS bases are process/thread state, not ignored prefixes. Until supported, segment
accesses reject. Guest addresses never become unchecked host pointers.

A region records guest interval, owner(module/stack/heap/thread), mapping generation,
permissions, backing bytes and byte-definedness. Reserve, commit and protection are
separate concepts in the eventual implementation. PE raw bytes and specified loader
zero-fill are defined; uninitialized stack and nonzeroing heap allocations are not
silently zero. Overlap/alias policy must reflect a shared backing object, not two
independent copies. No writable/executable pages, self-modification or opaque host
alias is admitted by the first slice. Checked guest-memory faults initially remain
explicit out-of-domain errors, not fabricated Windows exceptions/equivalent exits.

Object capabilities are compiler proof facts, not guest pointer encodings. A stale
proof token becomes unusable on free/reallocation/unload. A saved numeric address
can alias a new object at the same address, as machine execution permits; hidden
generation rejection would change behavior. The defined supported domain excludes
use-after-free programs unless their actual numeric alias semantics are explicitly
modeled and tested. Pointer-to-integer arithmetic cannot be discarded: either retain
bitvector identity plus a checked access, or reject the proof, never substitute zero.
Address-dependent output requires a stated address-layout contract; portable output
comparison does not establish arbitrary Windows allocator-address equivalence.

Heap objects include heap identity, requested/available size and alignment. Realloc
success preserves min(old,new) bytes and definedness, invalidates old capabilities,
and initializes only new tail bytes when the chosen API flag requires it. NULL
failure retains the original allocation; HeapReAlloc does not set LastError.
In-place-only and exception-generating flags are separate outcomes, not ignored.
Zero-size, serialization, concurrency, resource exhaustion and allocator metadata
must have explicit contracts before an actual Heap API is admitted. Model limits
(16 regions,64KiB) are test budgets, not claimed Windows limits or production ABI.

## Process, modules and startup

Process state owns module instances, heaps, handles, thread records and an effect
log. Each thread owns stack, last-error state, TLS slots and exception chain. Loader
metadata parsing grants no execution permission. A module moves mapped -> bound ->
initializing -> ready/running only after every declared predecessor effect succeeds.
Binding includes verified relocations, import resolution, target provenance and
module instance identity. Initialization order must come from actual loader/runtime
contracts; an empty callback table does not authorize jumping to main.

The prototype's caller-supplied ordered callback list tests an order gate only. It
does not discover the correct Windows order or prove callback bodies. Cyclic DLL
loads, reentrant callbacks, loader lock, thread notifications and unloading are
explicitly unresolved. A failed initializer does not imply rollback of earlier
writes, registrations or I/O. Exception propagation and teardown require separate
validated effects; until then such paths prevent admission. Match original process
exit/flush behavior, including nonzero results, rather than host Rust defaults.

## Composable API effects

An effect contract states ABI/stack cleanup, register/flag clobbers, full read/write
ranges, ownership transfer, escaping aliases, handle identity, callbacks, thread
state changes, failure writes, LastError/errno, exceptions and blocking behavior.
Each outcome has its own postcondition. Do not assume every failure is transactional.
Before an external call validate complete borrowed ranges; after it invalidate all
possibly modified facts and re-establish only promised bytes/counts. A read epoch
tracks freshness separately from physical definedness: stale physical bytes may
remain readable machine data but cannot satisfy a proof about the new read result.
The prototype conservatively invalidates the borrowed tail and therefore rejects
some defined programs; it is a proof experiment, not exact general memory semantics.

At joins, byte-definedness and guaranteed ranges intersect; values/flags retain
only equal or soundly joined facts; generations and module states must be compatible.
Loops need inductive safety facts or checked runtime accesses, not sampled execution.
Do not require all user-visible results or loop termination to be statically known.
Timeout/resource policy is a separately stated execution domain, never invented
successful termination. Unknown external effects cannot compose.

Shell/COM illustrates why shared memory is necessary: QueryInterface/AddRef/Release,
interface/vtable identity, apartment rules, borrowed IShellItem and progress sink
lifetimes, callback reentrancy and HRESULTs cross procedure boundaries. DeleteItem
queues work; PerformOperations executes it, and S_OK can accompany cancellation.
GetAnyOperationsAborted matters. These operations are not implemented here. Do not
replace them with immediate unlink or infer failure closure from one success probe.

## Executable prototype and independent expectations

model.py tests integer ranges, alias-preserving backing, byte-definedness,
permission checks, generation-scoped proof capabilities, selected moving-realloc
outcomes, outcome-specific external writes and an ordered module phase gate.
Nine test functions use literal byte arrays and explicit invalid transitions. They
exercise address reuse, preserved partial initialization, shrinking/growing/failing
reallocation, stale and wrong-owner tokens, fresh read tails, full-range crossing,
integer wrap, permissions, budget limits, callback order/failure and entry gating.
They do not call production code, run Wine, or establish Windows conformance.

Run: python3 -m unittest discover -s research/process -v

## Bounded implementation acceptance path

Next implement a shared checked guest-memory core and integration with existing
normalized load/store/LEA operations for single-threaded PE32 programs using stack,
initialized image data and explicit heap effect adapters. Select exact API forms
only after Windows probes establish flags/alignment/zero-size/error behavior. This
is one cohesive memory/ABI milestone, not complete rcedit/ISCC/COM support.

Required gates: deterministic same-PE Rust emission; two unrelated compiler-built
programs with runtime-selected allocation sizes and aliasing; original Windows vs
native bytes/exit comparisons; independent register/offset permutations and mutated
PE negatives; failed realloc preserves data; success copies partial-defined bytes;
wrong heap/stale proof/overflow/cross-region/readonly/uninitialized/return corruption
rejections; error and resource-limit outcomes; all existing corpus preserved. Use
ordinary entry only when its startup closure is demonstrated; otherwise label a
custom-entry conformance program explicitly and retain third-party rejection.

Reserve a whole unrelated project/dependency family before those results inform
implementation. WinMerge may become a development failure case only after pinned
reproduction; CrystalDiskMark remains an unverified storage lead. No disk workload
is authorized here. Modern Windows evidence is not XP/7 validation.

## Primary contracts and remaining reproduction gap

- https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heaprealloc
- https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
- https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-best-practices
- https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-deleteitem
- https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-performoperations

Wine is absent; docker info fails connecting to the daemon with operation not
permitted. No security setting was changed, no image/binary was run, no failure
reproduction is claimed. An isolated official Wine environment and pinned licensed
WinMerge asset are prerequisites for that track, not blockers to this contract.
The Linear shared-notes tool returned tool-not-found; repository/evidence were used.
Eight historical original-Windows timeouts remain unexplained.
