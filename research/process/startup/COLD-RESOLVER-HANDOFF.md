# Cold resolver: measured ownership and publication gate

The cached path remains implemented. The original cold resolver and load helper
now execute as checked native components with explicit loader API effects.
Whole-image cold resolution and dynamic FLS invocation remain rejected. This is
not a native DLL loader or new application compatibility claim.

## Implemented ownership and publication boundary

Module values now carry runtime identity and module generation. Acquisitions have
separate single-use reference receipts; exported functions carry module lifetime,
export identity, exact case-sensitive symbol and guest address. Releasing one
reference keeps borrowed module/export values live while another owned reference
exists. Final release invalidates them. Reload at the same handle creates a new
generation. Unclosed release failure poisons lifetime knowledge. Scalar addresses,
foreign-runtime tokens, stale receipts and stale exports cannot create authority.
GetProcAddress may return data or forwarded exports in Windows; this component
only accepts separately justified named function results. It does not establish
forwarder dependencies or the actual Windows module identity.

Shared IR/emission now supports the observed memory/register 32-bit XCHG form.
Execution requires a live, explicitly bound module-cache word and startup-exclusive
runtime state. It checks the complete initialized range, alignment, exact storage
capability and module-versus-function role, reads before writing, returns the old
value, and leaves flags unchanged. Partial, foreign, stale, unbound and unknown
cells reject before publication. This serialized component has no callback between
its read and write. It does not prove concurrent guest publication equivalent or
that an actual original process is exclusively initializing.

The 160-byte resolver and 75-byte load helper are decoded mechanically. Original
branches, calls, error tests, exchanges and returns execute with checked storage.
Load/export/release callbacks are still explicit effect cuts. Their argument
bounds/types and returned lifetime authority are checked, and successful load and
release must show the matching one-reference change. A numerical success result
alone fails. Earlier effects are preserved on later rejection. The error-87 branch now calls the original 67-byte UTF-16 prefix comparator
and follows its actual retry decision. Counts above260 reject in this bounded
component; no loader initializer effect is inferred.

Seventeen scripted native scenarios cover fresh success, failed load, error 87,
retained-reference publication, failure after acquisition, absent export, scalar
export forgery, unload during lookup, wrong symbol, unknown LastError, false load
success, false release success and failure reported after acquisition. The retained
reference case supplies a serialized callback publication, not evidence of actual
thread races. Independent registry/exchange tests use a different module and
symbol, covering unload/reload, replay, foreign runtime, aliasing, partial access,
truncated/unknown storage, expired initialization, flags and failed-release poison.
All 302 bytes of the three bound bodies are individually mutation-tested.
Eleven independent comparator cases cover zero/one/multiple-word counts,
unsigned UTF-16 units, early mismatch/NUL, high surrogate units, truncated and
unknown storage and the count cap. The comparator compares code units; it does
not normalize, case-fold or replace malformed UTF-16. Loader name validation
remains a separate contract. Retry success, failure, second-call failure ordering
and matching api-ms- suppression are tested through the original load helper.

The checker records cold-resolver generated-source SHA256 and compares it across
hosts. These are component executions with scripted API results. There are zero
new original-Windows loader observations or whole-PE comparison pairs.


## New reproducible evidence

The artifact checker binds the entire160-byte original resolver402a53..402af3,
75-byte load helper402af3..402b3e, and module API import identities. A Rust test
independently decodes their calls and memory exchanges. All four memory XCHG instructions now lift under the restricted runtime
publication contract above:

| Address | Original effect |
| --- | --- |
| 402ab7 | publish failed module lookup (-1), receive old module-cache value |
| 402ac4 | publish failed function lookup (-1), receive old function-cache value |
| 402acf | publish loaded module, receive old cache value |
| 402aef | publish resolved function, receive old function-cache value |

The resolver calls FreeLibrary41506c and GetProcAddress415070. The load helper
calls LoadLibraryExW415074 with flags800, then GetLastError415044 on failure.
Error87 enters original prefix comparison4078e0 before a possible flags0 retry.
That comparison and loader effects must be closed, not guessed from sample names.
The module-name table415c80 references api-ms-win-core-fibers-l1-1-1,
api-ms-win-core-synch-l1-2-0 and kernel32. The actual dynamic function request is
FlsGetValue; the static fallback remains TlsGetValue. This is not UCRT slot state.

A successful module publication racing with an already populated cache has a
FreeLibrary path. Numeric HMODULE equality alone does not prove ownership of the
same acquired reference. Nor does a function-address scalar prove that its module
remains loaded. The new CrtValue module/function capabilities are distinct from Module memory
storage. Actual loader effects, API-set/forwarder identity and concurrent
publication remain obligations beyond these reference and storage checks.

## Reviewed defect fixed before this integration

An explicit backend callback could mutate captured ESP to a scalar/foreign stack,
or retire the Context object, after its initial validation. The original tested
normal-disposition path then returned despite stale capture state. A pre-fix
native regression failed. The dispatcher now rechecks the captured context after
PTD/backend return and before continuing its branches. All three cases reject
while retaining prior writes. The retirement case also reconstructs a new object
at the same guest address, preserving the distinction between address and lifetime.
This is protection around the component's explicit API-effect cut; it is not
proof of original Windows delivery or arbitrary DLL callback effects.

## Next connected implementation scope

Sol review now connects the original prefix comparator4078e0 through protected
CALL/RET and the actual flags800/error87/flags0 retry sequence. Word TEST/CMP
normalize into shared width-aware operations, with checked initialized reads.
The module-prefix immediate refines only after exact live input bytes validate.
Keep the supplied loader effects explicit.

Next bind the checked function result through the original indirect-call guard
and lookup wrapper into the distinct dispatcher PTD backend. This requires actual
module/API-set/forwarder lifetime evidence and a live FLS index/fiber owner; a
function token alone is not an API-effect certificate. Unknown exports and loader
initialization/detach/TLS callbacks stay rejected. Actual loading and concurrent
module publication require a separately justified contract, not broader defaults.
Unwind/termination and original Windows delivery remain separate unresolved gates.

Primary contracts read for this implementation are Microsoft Learn
[LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw),
[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress),
[FreeLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary),
and [FlsGetValue](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue),
plus the x86 instruction contract for implicitly locked memory XCHG. The documented executable-load reference increment, final-release unload and
DllMain detach, exact export-name spelling, function-or-variable result, and
flags800 search behavior informed this boundary. The links do not close all
loader behavior. Memory XCHG uses the observed word/flag semantics; concurrent
atomic equivalence is outside the component domain.

Sol can resume substantive review and the bounded original comparator/lookup
connection. Escalate only a concrete loader/forwarder or concurrency uncertainty. Unwind/termination, original
startup, rcedit, ordinary CRT and historical Windows timeouts remain unresolved.
