# Connected startup UCRT getter and native FLS acquisition

Later checkpoint: [UCRT allocation and initializer prefix](UCRT-ALLOCATION.md)
continues beyond this getter boundary. The evidence below remains the historical
getter/FLS-read result, not full initialization.


## Original execution and supported contract

This connects the existing shared registered PTD getter to original startup.
`NormalCallEpoch` is passed through initializer401945, the original table loop
and callback40a407. There is no guessed thread head or borrowed fixture slot.
The original CALL40a428 executes getter40a332, whose unchanged prolog414268 links
its actual stack record (handler414ad6) into the same canonical thread registry.
Existing ownership, overlap, protected continuation, cookie, lifetime and stack
bounds checks remain. Helper/getter/epilog executable bytes are checked against
the original mapped image; the actual named imports are checked at their effects.

The original GetLastError call, branch, FLS thunk408061 and conditional null test
execute. The explicit native service implements the static kernel32!FlsGetValue
import under the live provider/process/current-fiber contract. Its module and
implementation owner remain checked. It does **not** publish a new dynamic
GetProcAddress export descriptor or turn a name match into callable authority.
The FlsGetValue2 branch remains rejected, not substituted with the fallback API.

Primary contracts reviewed2026-10-30:

* [Microsoft FlsAlloc](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc)
  documents an index initialized to zero, process-scoped indices and fiber-local
  storage. [Primary documentation source](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/fibersapi/nf-fibersapi-flsalloc.md).
* [Microsoft FlsGetValue](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue)
  retrieves the calling fiber's value for an allocated index.
  [Primary documentation source](https://github.com/MicrosoftDocs/sdk-api/blob/docs/sdk-api-src/content/fibersapi/nf-fibersapi-flsgetvalue.md).

The native read validates the actual native allocation identity and current
stationary fiber. Only an absent value for that native allocation can materialize
its documented initial zero and fresh value lease. Supplied/uncertain/retired
allocations cannot issue this fact. Existing values are never rebound/reset;
known scalar bits retain no pointer authority, and unknown values reject without
being replaced by zero. Reused indices cannot revive old slot/allocation tokens.
Cross-fiber state rejects in this stationary-fiber subset; no switching or general
multi-fiber execution is claimed. Fixed resource/serial exhaustion rejects before
publication rather than fabricating a Windows error result. The checked stdcall4
adapter validates protected/active call, saved registers, stack permissions and
argument knowledge before effects, and rejects replay.

Successful read makes LastError knowledge unknown. It does not promise a zero
or preserved error. Original GetLastError/SetLastError instructions retain their
save/restore role; the supported boundary currently stops before restoration.
No Windows failure or resource-exhaustion equivalence is inferred from these
native conformance inputs or newer-host mapping observations.

## Observable connected checkpoint

For the same unchanged authored PE
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`,
entry under the explicit native extension allocates second process index1 with
callback40a100, stores1 at41c170 and reads that actual allocation's null value.
The original registered UCRT record stays byte-backed, linked and live when the
original null test reaches CALL40a3a3 ->40a1ee. That lazy body is explicitly
unbound here: no allocation, PTD pointer, callback7 completion, epilog, restored
continuation or full startup result is manufactured. Prior cache sentinel/RO,
released resolver lock, first FLS index/value, process heap and earlier startup
writes remain.

Default admission still rejects402b00. The versioned second-fiber mapping remains
limited to its declared observed KernelBase revision/Windows20348; no XP/7 claim.
Five recorded Windows wrapper comparisons remain component evidence, with zero
new Windows/ELF or whole-PE pairs. Full rcedit is not admitted. Historical Windows
timeout causes remain unresolved.

## Independent checks and next coherent connection

Sixteen native read cases check zero only after actual native allocation,
repeat lookup identity, opaque bits without pointer creation, preserved unknown
failure state, supplied/retired/uncertain indices, foreign runtime/thread/fiber,
serial exhaustion, stale value identity, invalid ABI/registers/unknown argument,
closed initialization and replay. Strict positive cases require actual successful
return; negative cases check rejection before slot/serial/LastError changes.
Four independent original-PE mutations alter the getter, prolog, epilog and FLS
thunk. They require exact changed-code rejection and distinguish zero versus one
already-linked record and absence of a new FLS value. Connected positive assertions
require the actual native allocation/value identity, byte-backed record/head and
absence of a heap PTD. Older pending/delivery/ownership tests remain independent.

The current lazy-body source is a separate UCRT contract: it publishesffffffff,
executes calloc(1,0x364), publishes the allocation or handles failure, invokes
initializer40a067 and preserves saved LastError. The initializer writes through
at least offset350 and invokes409efb/40a00d locale/reference helpers. This868-byte
object is not the40-byte VCRUNTIME dispatcher PTD. Actual409efb additionally
registers an EH4 scope, acquires the indexed lock, follows pointer-bearing fields,
executes LOCK INC through offset48 and runs its original cleanup release;
40a00d registers another scope and calls40a296 under its indexed lock. These
effects are required evidence, not harmless accessors. Current shared locked IR
accepts only register-source OR/AND; the actual LOCK INC and related cleanup
LOCK XADD are rejected by `extended` in `src/crt_stream_ir.rs`. A coherent next
contract must cover counter wrapping/flags, writable canonical targets, indexed
lock authority, reference lifetime and cleanup together, rather than admitting
that opcode alone. Next inventory and connect
those original producer/initializer/cleanup operations using canonical allocation
identity and an explicit UCRT view. Missing locale/reference effects must remain
rejected. Sol can attempt the bounded connection; escalate only an actual alias,
record-lifetime or continuation ambiguity. Do not supply successful callbacks.

[Source/artifact/test evidence](evidence/startup-ptd-acquisition.json) records local
verification and exact provenance. Final-head CI and substantive review are still
required. PR45 remains draft and no formal approval is submitted.

## Verification and retained CI failure

Final local replay completed: both artifact-dependent tests and five recorded
wrapper comparisons passed;287 CRT tests passed with those two tests ignored in
the ordinary run,76 Python tests ran with one existing skip, and Clippy/formatting
passed. Repeated generated Rust SHA256 is
`9380a72c6b32793bf115cb848e24c178dd395cef0f6d7b2a425f86ce0147907b`.

The preceding99d6775 PR [run41107853543](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41107853543)
failed [job124242290134](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41107853543/job/124242290134):
original Windows corpus case19 timed out in process.wait after15 seconds.
The corpus launch [artifact13002965454](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41107853543/artifacts/13002965454)
was uploaded. The other eight jobs passed. This is not a translated execution
result, nor an established infrastructure cause. This case's retained stdout was
not separately inspected here, so no output-present inference is made. No retry
or timeout relaxation was used; later CI cannot erase the original failure.
