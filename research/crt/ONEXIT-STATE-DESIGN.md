# SUB-542: bounded onexit ownership and failure contract

Decision: the unchanged caller's local sentinel initialization is a candidate for
an independently implemented owned-image effect. Its later registration crosses an
unclosed external boundary. Neither this design nor the probes justify replacing
CRT startup, jumping to main, accepting ordinary CRT programs, or assuming that
previous imports preserved the initial image bytes. Production remains unchanged.

## Exact artifact finding

`onexit_inventory.py` binds the complete literal bytes of helpers 0x13e0 (161 bytes,
including the trailing trap), 0x15c0 (76), 0x1c60 (12) and 0x17c0 (10), all relevant
HIGHLOW operands, the callback table entry, caller instruction windows and three
IAT thunks. Input is an unchanged owned compiler artifact whose SHA256 matches its
measurement manifest and whose conversion remains rejected. This is an exact
research-profile checker, not a hostile-input loader or complete reachability proof.

The 0x1c60 target is **not an import**. It clears EAX, compares image word 0x3098
with zero, then SETNE AL. The checked snapshot has mode=1, flag byte 0x30a9=0 and
24 zero bytes in the two table regions. These are file-time facts, not proof of
values after loader callbacks or preceding CRT imports.

Caller 0x104f explicitly PUSHes **1**, then writes through the previously returned
`__p__commode` pointer before CALL 0x13e0 at 0x1053. Thus the actual observed caller
uses policy 1, not policy 0. Assuming the flag is known zero on entry, this chooses
six FFFFFFFF stores regardless of whether the known mode word is zero or nonzero.
The query still executes and reads the mode; the no-fault/full-word initialization
obligation must not be erased. A prior unknown write through `__p__commode` is one
reason the actual incoming state is not yet certified.

At 0x1067 the caller PUSHes callback VA 0x4018d0 and CALLs 0x15c0. When the first
word is FFFFFFFF, registration calls `_crt_atexit`; otherwise it calls
`_register_onexit_function` with the first table. The bound thunks are:

| Thunk RVA | IAT RVA | Import |
|---|---|---|
| 0x1d0c | 0x2088 | api-ms-win-crt-runtime-l1-1-0.dll!_initialize_onexit_table |
| 0x1d12 | 0x208c | api-ms-win-crt-runtime-l1-1-0.dll!_register_onexit_function |
| 0x1d18 | 0x2090 | api-ms-win-crt-runtime-l1-1-0.dll!_crt_atexit |

The observed callback target is bound as an address only. Its body, later execution
and every external effect are not proved by that address binding.

## Ownership and lifecycle

The proposed local effect owns a single image generation: flag byte [0x30a9,0x30aa),
read-only input word [0x3098,0x309c), and two disjoint writable ranges
[0x30ac,0x30b8) and [0x30b8,0x30c4). Require complete file/virtual backing, exact
permissions, initialized reads, all address relocations and no overlap with code,
headers, metadata, cookie, return/saved state, TLS or option words [0x30d0,0x30e0).
Unknown contents may be overwritten by the six sentinel stores, but unknown or
invalid backing/ownership is never authority to write. All ranges must be validated
before returning a local effect. No generic image write authority follows.

Numeric equality is not pointer provenance: image owner and lifetime must agree.
The research model rejects mismatched owner IDs, wrong address/size and protected
aliases; those IDs are abstract test premises, not a production capability. The
future Rust implementation must bind a single immutable owned snapshot, as SUB-541
does, and issue no transferable arbitrary pointer token.

Three separate resources must not be conflated: image sentinel words, an opaque
CRT table with its associated allocation, and the process-wide exit registration
queue. Microsoft calls the table layout opaque and version-dependent; the six
sentinel stores are compiler instructions, not a portable definition of CRT table
members. The prototype therefore tracks lifecycle separately from raw words.
After a modeled successful initialization, a table is opaque-ready. After execution
it is consumed and must be reinitialized before registration/execution. The helper's
already-initialized byte does not repair a consumed table. Process queue callbacks
are stored separately from local-table callbacks in the model.

Callback ownership must establish valid code, calling convention, no arguments,
lifetime through execution, and a complete effect summary before executing it.
Registration alone cannot certify the callback body, ordering under reentrancy,
DLL unload dependencies, exceptions or termination behavior. Concurrent mutation,
recursive registration and arbitrary allocator/heap aliases are outside this gate.

## Paths and failure state

| Entry/path | Local result and retained state |
|---|---|
| Known nonzero flag | Return AL=1 before policy validation; no table read/write. Upper EAX remains its incoming value/unknown bits. |
| Zero flag, policy outside {0,1} | Reach fast-fail helper with code 5 and INT 29h. Model returns a distinct fastfail-request and marks that path terminal; later operations cannot resume it. No OS termination implementation. |
| Zero flag, initialized known mode, mode=0 or policy=1 | Write all six sentinel words, then flag=1; query cleared upper EAX, so final EAX=1. |
| Zero flag, mode nonzero, policy=0 | Call first table initialization, then second only if first returns zero. Unknown foreign effects block and invalidate tracked state. |
| Explicitly framed first import failure | Preserve its supplied write effects; second table untouched under that **explicit frame premise**; flag not set. XOR AL,AL preserves imported EAX upper bits. |
| Explicitly framed second import failure | Retain first table's initialized state and second import's supplied failure writes; flag not set. No rollback assumption. |
| Both explicitly framed imports succeed | Both resulting tables tracked opaque-ready, then flag=1/EAX=1. This is a hypothetical model contract, not an established import implementation. |

`Foreign(framed=True, ...)` in `onexit_model.py` is a synthetic test premise
specifying both side effects and unaffected storage. A numeric return, a module
hash, or a successful probe does **not** construct such a premise. Real imports
have no implemented frame proof. Default foreign effects invalidate flag/mode,
local tables and process queue, set a sticky blocked state, and prevent subsequent
known local operations from restoring a startup certificate. Failure may mutate
storage; unresolved nonreturn/exception effects block rather than become success.

The registration wrapper returns EAX=0 exactly when the import returned zero and
the original callback bits are nonzero; otherwise EAX=FFFFFFFF. CMOVE/NEG/SBB/NEG/
LEA implements this conversion. A null pointer is tested only as scalar arithmetic,
never passed to a real CRT registration API. Defined final CF/PF/ZF/SF/OF masks are
0x01 on wrapper success and 0x44 on failure, independent of returned EAX's sign.
The model/CPU probe excludes AF; a later instruction-level implementation must
account for AF if observed. Failed registration does not imply unchanged allocation
or process queue. Callbacks/lifecycle become unknown where effects are unspecified.

## Registers, stack, flags and isolation

Normal RET advances ESP by four from helper entry and leaves its caller-owned
argument for caller cleanup. 0x13e0 preserves EBP/ESI on every normal path; early
return never saves ESI, while other paths push/pop it. Local paths do not clobber
ECX/EDX. Imported paths require conservative volatile-register handling. 0x15c0
preserves EBP/ESI, cleans the one or two argument words it pushes, and leaves the
incoming callback argument untouched. It returns ECX=1 on success/0 on failure;
EDX is unknown after an external call. Return tags and saved words must remain
protected; a valid disjoint, fault-free stack is an explicit domain assumption.

The prototype models EAX known bits and control/state outcomes, not every flag or
transient stack instruction. It cannot stand in for production x86 semantics.
The query's XOR/SETNE produces full EAX 0/1. MOV AL,1 on an early return does not.
XOR AL,AL on initialization failure preserves upper EAX; imported 0xfffffff9
therefore becomes 0xffffff00, not full zero. CMP/TEST/partial XOR flags and the
caller ADD ESP cleanup require explicit instruction semantics in any implementation.
The scalar probe validates only the registration result-conversion instructions.
No numeric incoming ESP or flags are fabricated in the design.

## Independent evidence and provenance

Thirteen model test functions use literal bytes/values and explicit hypothetical
foreign frames; they include first/second failures, no rollback, blocked composition,
partial EAX, initialization policy, ownership/bounds, consumed lifetime, separate
process queue and invalid callbacks. They do not count as native program comparisons.

The authored C probe uses SDK types without inspecting opaque table members. Its
`tables` mode initializes two separate tables, registers A/B on the first and C on
the second, executes them and reinitializes the consumed first table before reuse.
Expected output is `BA|C|C`. Separate `process` (public atexit) and `crt` (internal
_crt_atexit) modes expect `YX` on normal exit. Agreement is comparative evidence,
not proof these APIs have identical failure/alias/exception behavior. No forced
allocation exhaustion, invalid pointers or security changes are used. Failure and
nonreturn cases remain model-only; no real allocator-failure coverage is claimed.
Six x86 scalar CPU cases independently check wrapper conversion, including zero,
signed-boundary and nonzero failure values. All modes are separate authored
executables/processes, not execution of original CRT helpers or translated programs.

`check_onexit.py` records actual stdout/stderr, exit, source/probe/unchanged-PE hashes,
compiler flags and module paths/base addresses from **each lifecycle probe process**.
Module file hashes/versions describe on-disk files, not proof of loaded bytes or
complete DLL effects. Scalar text newlines are normalized only in a separate
comparison field; raw output is retained. Windows/Linux inventory reports must
match on the same PE. These probes leave original artifacts unchanged and keep
complete_startup_proof/emission_allowed false. Existing 79 root Rust functions,
11 option-state research functions, eight initializer model functions, five option
CPU cases, 12 compiler comparisons, 102 authored comparisons and 18 launch diagnostics
remain distinct. Four held-out rejections, XP/7 limitations, preferred versus actual
load-base distinction and three unexplained historical timeout causes remain.

Primary Microsoft documentation read 2026-10-26:

- https://learn.microsoft.com/en-us/cpp/c-runtime-library/execute-onexit-table-initialize-onexit-table-register-onexit-function : zero success, negative failure, opaque table, initialization before use, consumed state after execution. Explicitly says these are internal infrastructure and should not be called directly by application code; our calls are isolated research probes.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atexit : public success/error convention, LIFO, heap allocation, DLL lifetime caveats.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/onexit-onexit-m : pointer/null public convention, distinct from internal wrapper's integer result.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/internal-crt-globals-and-functions : identifies _crt_atexit as an unstable internal interface; no full effect contract inferred.

No Microsoft/Wine implementation source was imported. This specification and the
probes/models are independently authored under the project's MIT OR Apache-2.0 policy.

## Smallest implementation gate after medium review

Implement only the exact **local policy-1 sentinel effect**, bound to this helper
and caller, in a research Rust component. Require a known initialization byte,
initialized mode word, both complete owned regions and all pointer/call provenance;
model early AL-only return separately, preserve protected returns/saves and reject
unknown state/unsupported forms. Compare an independent authored CPU sentinel/AL
probe, including nonzero incoming EAX upper bits and arbitrary overwritten words.
Reject policy 0 imported initialization unless its full external effect contract is
separately implemented. Never fall back from an unresolved imported path to the
sentinel path. Keep all outputs non-emitting. This closes the local effect under
explicit ownership assumptions while exposing _crt_atexit registration as a hard
boundary. It does not resolve the earlier __p__commode alias or any whole-startup
entry contract. A separate external registration/heap/lifetime design is needed
before actual ordinary CRT translation can advance.

Medium review also rejects fractional state/foreign/scalar values: range membership alone is insufficient to represent x86 bits. The independent regression checks rejection before local writes.
