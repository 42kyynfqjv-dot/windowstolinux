# Remaining native startup/formatter boundaries

## Latest executable checkpoint: native-profile lock construction

The explicit native profile executes the original guard, indirect synchronization
call, constructor RET and lock-count publication. The mapped lock remains live
with count1 when original FLS acquisition `0x4024d6 -> 0x402963` rejects. Default
admission remains blocked at `0x402b00`. Native fixed storage and checked ABI are
implemented; arbitrary Windows resource-failure correspondence is still unproved.
This is component execution, not whole-PE support. See
[contract, review defect and next scope](PROFILE-SYNC-CALL.md).

The entries below retain earlier checkpoints and remaining independent paths;
older exact stopping addresses are historical, superseded by this checkpoint.

This inventory describes the experimental live component path. It grants no
whole-image admission. Addresses are bindings of the retained authored PE, not
application identifiers used to choose behavior.

| Boundary | Current execution | Requirement before removal |
| --- | --- | --- |
| Main report and epilog | Original instructions, live storage, original guard helper, protected CALL/RET and normal-return receipt | Retain original entry/callee contracts and malformed-state rejection |
| printf wrapper, iob and options accessors | Original decoded bodies and actual native CALL/RET; typed FILE/options results bound to owned objects | Keep code/ABI/lifetime checks; do not infer FILE or options initialization from an address |
| stdio-common formatter body | Full-body callback remains for returning cases. Original entry and full locale constructor execute in the rejection experiment | Prove initialized live locale/FILE state, execute driver/parser/integer/output and ordered destruction with correct failure behavior |
| Locale state | Constructor's unknown branch word at0x41ce7c rejects after original object writes. Lifecycle tokens now bind runtime identity as well as thread/generation; they do not initialize locale data | Establish this word and the objects/lifetimes behind0x41c230/0x41c234 from startup/effect evidence; cover alternative/lazy paths or reject them. Image initial bytes and successful samples do not establish post-startup state |
| stdout and options | FILE-array storage is live but the connected printf stdout fields/lock are unconstructed. The separate original initializer now uses a result-aware lock transition: only API success grants ownership, and constructed lock bytes are opaque. Basic options words are explicit initialized component inputs | Prove stream/lock/descriptor/encoding/buffer initialization and mutation assumptions before native formatter access |
| Inherited startup records | Original parser feeds the original standard-handle body on the same typed owner; seven native cases cover valid/empty input and bounds/lifetime/provenance failures | GetStartupInfoW output and already-provisioned descriptor capacity remain explicit effects. Bind the real allocator/block-lock/inheritance lifetime before claiming startup; reserved-data protocol is derived from original instructions |
| Standard-handle low-I/O initialization | Original 176-byte body executes in 25 native component cases with explicit API outcomes and pre-owned records. Artifact bytes/imports are bound; inherited handles, detached sentinels and type flags follow original instructions | Bind preceding block allocation/inherited startup data, actual API acquisition and handle lifetime/alias contracts, then connect resulting records to FILE startup. No initialized record or full startup authority follows from these tests |
| Integer C++ record and cleanup | Separate instruction/metadata inventory and partial helper proofs; no complete dispatch equivalence | Preserve the original C++ record/handler semantics or prove a complete contained domain. An EH4 token cannot stand in for this record |
| Output backend and exit | Separate writer/FILE/error/flush components exist; this connected path makes no physical stdout claim | Bind native formatter output to those effects; test short writes, errors, buffered flush/close and termination order |
| Original outer invocation and startup | Some outer-frame scalar state remains explicit entry input | Execute the original caller/initialization effects and module/thread entry; do not supply expected report arguments as execution |
| Windows exception delivery and unwind | Captured/delivery objects, incoming-chain containment and some API effects remain bounded component premises | Close actual acquisition and RtlUnwind/collided effects for each admitted domain; reject incomplete paths before program emission |

The returning printf tests still provide a native formatter result and validate
actual options/FILE/format/varargs routing. They do not format text. A separate
experiment executes original formatter entry and constructor instructions until
an unknown locale-state read; it cannot produce a successful return. Neither
experiment is a new Windows/ELF stdout comparison. Actual-load-base and historical
Windows process-exit timeout limitations remain unchanged.

The artifact-bound `locale_state_evidence` in `formatter_binding.py` and the
cross-host wrapper report now preserve a concrete mutation hazard. The branch
word is four virtual zero-fill bytes; the two pointer cells have file-backed
initial address integers. A conditional CALL at `40b2f8` reaches `407126`, which
exchanges scalar one into the branch word. A separate conditional path ending at
`40b372` writes through an object into the multibyte-info cell. This is **static
effect evidence**, not proof that either path executes during startup or an
exhaustive writer/alias inventory. Neither immutable globals nor nonzero state
may be assumed from these findings.

The next implementation must discharge these specific producer obligations:

1. Bind loader/module data and relocation-derived pointer cells to actual live
   locale objects and complete initialized ranges. Prove relevant startup and
   external-call effects, plus exclusion or handling of later mutation.
2. Bind FILE construction and its exact lock/descriptor state to the original
   initialization instructions. The lifecycle proof still exposes allocation,
   lock construction and low-I/O effects. The checked lock-result adapter consumes an external outcome and does not prove the OS invocation or low-I/O startup; creating storage or ending an
   initialization token does not discharge them.
3. Compose the driver/parser/integer/output and ordered cleanup on that same
   owner, including PTD errno/doserrno and temporary locale-state release on
   failure. Preserve the distinct C++ record and invalid-parameter/termination
   paths. Unsupported domains must reject before program emission.

The retained Windows observer records stream/write/lock/return boundaries, not
the complete locale object graph. It cannot certify those missing producer or
lifetime facts. Independent state/mutation/failure cases and original-instruction
execution are required; supplying zero globals or a "C locale" marker is not a
valid substitute. A bounded Astra High pass is warranted for this connected
producer/effect composition; routine regression and evidence checks remain on Sol.

Next cohesive scope: establish the live locale/FILE domain and connect the full
original formatter driver, parser, integer path, output and cleanup on the shared
owner. Keep raw instruction effects, pointer identity, initialization and failure
order visible in conformance tests. Use the existing helper certificates where
they apply, and reject remaining API/exception effects rather than supply default
results. This is a concrete semantic integration scope suitable for a bounded
Astra High pass after independent Sol review; routine verification stays on Sol.

Current concrete allocator integration: `40bf2a` calls the `40be7a` block
constructor. Its 64 descriptor records have stride 56 and critical sections at
record offset 0, while FILE locks use offset 32. Checked typed allocation issuance and distinct record-lock ownership now execute
with original constructor/destructor instructions, followed by the inherited and
standard-handle bodies in native component tests. No existing Buffer alias is
relabelled. The original manager's allocation loop and normal cleanup funclet now
execute on an owned component frame: lock 7 precedes scope activation, blocks and
capacity publish in original order, and scope -2 precedes cleanup release. Distinct
module-global leases preserve partial effects on acquisition/release failures.
The actual EH4 prolog/registration/epilog now execute under an exact live
initialization token, and the inherited producer invokes this registered manager.
Ordinary normal-call admission still rejects initialization. The bridge rejects
request >=8192 before effects; the original invalid-request/errno branch remains
unbound. Enter/Leave helper instructions now execute through a complete indexed-helper
certificate and exact constructed module-object binding; API synchronization and
exception effects remain declared component outcomes. Exception-driven cleanup
invocation remains to connect.
calloc/new-handler/errno (`407cf0`), free failure/errno (`407d50`), and continuation
after failed critical-section initialization remain unresolved. Explicit inputs
include global-lock initialization, frame/request, allocator availability and API
outcomes. The actual heap producer/calloc/new-mode getter now execute in component tests,
and a descriptor-constructor path uses actual calloc. The registered manager now calls that actual allocator, and the original errno
router selects canonical PTD/fallback storage. Its PTD lookup remains an explicit
callable effect. The separate connected errno/PTD component now executes the different
414268/414254 normal continuation protocol and original FlsGetValue path with
explicit fiber/slot input identity. This corrects the earlier TLS label: the actual
import is FLS, and the dynamic alternative names FlsGetValue2. Neither the live
manager registry nor lazy acquisition is closed by that component. Next: bind this
distinct record to the live registry, original FLS acquisition, recursive
initializing-sentinel failure behavior, and encoded new-handler/guard-slot/callback effects; then free failure
and locale/FILE production. See
[ALLOCATOR-EFFECTS.md](ALLOCATOR-EFFECTS.md) for exact instruction/API dependencies
and independent acceptance requirements. Sol can proceed; escalate only a
concrete missing exception-effect contract. Full startup/formatter/rcedit remains
unsupported until unchanged-binary entry-to-exit evidence passes.

See [PTD-FLS.md](PTD-FLS.md) for the independently checked stack layout,
slot/fiber lifetime and unknown-state tests, and explicit remaining API cuts.

The lazy getter now executes its first setter/failed-return path; successful
sentinel installation rejects at unbound calloc, preserving effects. Canonical
errno is invalidated on FLS mutation/slot retirement. Actual handler414ad6 uses
three-word record/state and metadata41b42c (19930522); the registry only implements
EH4 validation despite reserving a Cxx enum. A shared C++ state/unwind adapter and
recursive allocation/initializer contracts are the next concrete integration gate.

PTD C++ refinement: the actual three-word record and metadata now bind to the
owned normal frame, and original handler prefix/guard instructions execute.
The common dispatcher is still unbound. Both unwind entries lead to a
PTD-dependent termination callback/abort path, not a returning cleanup. The
adapter grants no disposition, cleanup receipt or registry admission; see
[CXX-PTD-RECORD.md](CXX-PTD-RECORD.md). Original dispatcher selection, PTD+12 callback
ownership, recursive PTD acquisition and termination effects are the concrete
next contracts before lazy-initialization exception composition.

The next Sol connection executes common C++ wrapper403002, thunk403e78 and
original dispatcher entry403d76 on that same handler stack. All eight arguments
forward in original order. The boundary is now actual context-validator402877,
which may read CONTEXT+0xc4 and FS:[0x18] thread stack bounds or fast-fail. It
cannot be replaced by a guessed successful validation. CLD is justified only by
the existing explicit forward cdecl ABI domain; unknown thread flags remain
outside it. Short-stack rejection preserves earlier metadata writes.

Context-validation connection: the existing original-helper proof is now reused
with a runtime/thread/frame-bound capture, live Context/Stack roots, typed saved
ESP and live selector. Bounds and lifetime are checked without manufacturing a
TEB or admitting unknown ESP. The protected call returns, original POP ECX consumes
the context argument, and execution rejects at actual PTD lookup4028c3. Actual
Windows capture acquisition and INT29 failure semantics remain outside admission;
remaining C++ dispatcher/termination callbacks have not been declared successful.

Dispatcher PTD correction/connection: original4028c3/4028d1 now execute against an
explicit protected lookup callback and require a live40-byte ThreadData root.
The original PTD+0x20 comparison executes, rejecting unknown data. Actual lookup
402bb4 resolves a dynamic backend or kernel32!TlsGetValue (not UCRT FlsGetValue).
Resolver/index/thread acquisition, lazy setter/allocate/free and termination
remain unbound; see CXX-DISPATCH-PTD.md. No successful cleanup is inferred.

Cached backend/dispatcher connection: original402bb4 now executes a checked -1
cache route through the original402a53 fast path to TlsGetValue/RET4. Cold cache,
dynamic pointers and unknown/truncated cache state reject. The requested dynamic
symbol is FlsGetValue, so its ownership contract remains distinct from TLS.
Original dispatcher branches/common epilog now return disposition1 for two
supplied non-unwind component cases. Unwind/search/dynamic-handler calls reject;
normal callback return grants no guest resumption. Backend API state remains an
explicit callable cut. Next: cold resolver/module lifetime and the separately
owned dynamic FLS backend, followed by dispatcher unwind/termination effects.

Cold resolver gate is now pinned in COLD-RESOLVER-HANDOFF.md: module/function
acquisition lifetime and four memory-XCHG publication sites are absent from the
current value/IR domain. Cold loading remains rejected. A reproduced stale-capture
hole after backend return was fixed by post-call context validation; mutation and
retirement now reject before dispatcher continuation, preserving earlier effects.
Next bounded Astra scope is shared module/function authority plus original cold
resolver/publication integration, not an unqualified scalar function-pointer call.


Cold resolver ownership connection: the complete original resolver/load helper
now execute with typed module/reference/export lifetimes and checked, serialized
word publication. Thirteen native scripted outcomes plus independent lifetime,
replay, alias, flags and corruption checks exercise this boundary. Actual loader
callbacks, API-set/forwarder dependencies and concurrency remain unproved; the
error-87 prefix helper now executes original instructions; dynamic FLS invocation still rejects. See
[COLD-RESOLVER-HANDOFF.md](COLD-RESOLVER-HANDOFF.md) for the exact contract and next
Sol-sized comparator/lookup connection. This does not supply original Windows
loader evidence or full startup admission.


Retry-helper review: original4078e0 now executes through the cold load helper,
including bounded UTF-16 prefix reads and the original nonmatching-prefix retry.
Seventeen scripted loader outcomes and eleven independent comparator cases pass;
loader initialization/detach and dynamic FLS still require explicit contracts.
The original failing hello run at5c3c2b5 remains preserved and unexplained.


Dynamic lookup connection: a separate component now executes original lookup,
resolver/retry, return-only indirect guard and checked FLS access. The live guard
word, module/export lifetime, target cache, single-use guard receipt and exact
fiber/slot generation must all match. Nineteen native cases retain earlier effects
on later guard/slot failure and preserve unknown PTD bytes. Actual loader/FLS
producers remain explicit. Next wire this variant into the dispatcher PTD getter;
the existing getter still uses the legacy lookup cut. See the current cold
resolver handoff for this precise composition boundary.


Dispatcher PTD connection: the shared getter emitter now selects either legacy
lookup or the checked dynamic wrapper at generation time. Eighteen connected
native cases retain the original LastError routing, protected returns, 40-byte
root check and rejection of unbound lazy/termination effects. Captured fiber/slot
inputs and loader effects remain explicit. The C++ common handler still selects
the legacy getter; connecting that protected caller is the next bounded step.


Caller authority split: the dynamic getter now accepts explicit Cached or
Initializing access. Cached has no lease and cannot enter cold resolution or API
effects, including during active initialization. Its post-initialization success
retains module/fiber/slot/PTD lifetime checks. Eleven new phase cases preserve
cache, reference, slot and phase state across rejection. The common handler still
uses legacy binding; next select the dynamic getter with Cached authority there.


Common-handler cached connection: the new bound variant now calls the dynamic
getter with fixed Cached access and no loader callback parameter. Twenty native
cases execute original prefix/common/dispatcher/epilog and retain capture,
fiber/slot/module ownership, replay, unknown data and changed-code rejection.
Successful normal cases return ContinueSearch1; they do not resume the guest.
Unwind helper4041a4, required-PTD termination4077ff, original Windows delivery and
incoming-chain effects remain explicit rejection boundaries. See the cold
resolver handoff for the connected instruction path and next effects to close.


Original unwind-state connection:4043e9/404406 now read/write the same checked
live C++ record through protected calls and exact metadata/map authority. Twelve
native cases cover owned transitions, invalid next state, alias/owner/unknown
state failures and the signed-byte/full-word boundary. The state write precedes
its action; it creates no cleanup receipt. The enclosing EH4 unwind body and
terminate/abort path remain rejected. See [DEPENDENCIES.md](DEPENDENCIES.md) for
the current connected paths and next cohesive frame/counter/action gate.


Registered unwind connection: wrapper4041a4/body4041bc now executes its actual
EH4 frame, PTD counter and state traversal. The action bridge/notification writes
also execute; termination remains rejected with earlier effects preserved.
The earlier provider and completed-event normal registry are explicit component
inputs. Pending-exception entry, terminate/abort and exceptional funclets are the
next connected gates. See [CXX-UNWIND.md](CXX-UNWIND.md) for24 native scenarios,
original-byte checks and zero new Windows/whole-PE pairs.


Cached unwind PTD connection: the new entry executes the original required
getter, dynamic cached lookup/guard and owned FLS access without a provider or
loader callback. Fourteen additional native cases retain failure and lifetime
rejection. Module/export and fiber/slot producers remain supplied. The next
registry gate now has a scoped child-only grant: the original cached unwind body
can execute during a pending component exception, while ordinary normal calls and
parent retirement still reject. Actual common-dispatcher call selection, delivery
acquisition and nested/collided effects remain external gates. Fourteen ownership
and four connected native cases add no Windows observations or whole-PE pairs.
See [CXX-UNWIND.md](CXX-UNWIND.md).

Original dispatcher unwind connection: common403002 → dispatcher403d76 now
executes call403de2 → wrapper4041a4 using the same delivery child grant, owned
record/context and cached PTD. Eight native cases and byte mutations preserve
rejection at all other search/indirect targets. The prefix entry, captured objects
and loader/FLS producers remain supplied; termination and actual Windows delivery
remain unbound. Positive delivery checks explicitly require callback success.

Original prefix delivery connection: prefix414ad6 computes its guard operand and
metadata register before entering the same common/dispatcher/unwind path under
child authority. Fourteen native cases preserve parent suspension, negative
ownership/guard/context checks and actual result1. The remaining cut is handler
invocation/delivery acquisition, not common-entry EAX. Terminate/abort and incoming
chain effects remain unresolved; no whole-PE pairs are added.

Same-event C++ invocation: a private binding now ties supplied unwind record/
context/owner to the pending RaiseException event and invokes the actual prefix.
A lease-bound receipt revalidates capture lifetime at consumption. Thirty native
cases cover mismatches, post-return retirement, replay, active nested delivery,
flags, full bounds and aliases. Actual Windows record/flag production and C++
registration selection remain supplied; no Windows/whole-PE comparisons are added.

Thread-chain boundary: the original C++ prolog and EH4 registry currently publish
to different head representations. A native two-prolog experiment demonstrates
that two live local candidates do not establish selection. See [THREAD-CHAIN.md](THREAD-CHAIN.md)
for the exact shared-head/source/search-cursor refactor and delivery obligations.
No selector or capture acquisition is enabled by that experiment.

## Shared-head checkpoint

Registered original C++ prolog/epilog effects now share `ThreadRegistry::head`
with EH4 and retain typed lifetime and child-lease checks (24 native cases).
Legacy supplied-FS components remain visibly separate. Ordered selection is
still unbound: result receipts need the actual executing registration/handler
identity before they can authorize cursor advancement. See [THREAD-CHAIN.md](THREAD-CHAIN.md).
Actual capture acquisition, incoming-chain containment and collided delivery are
not replaced by these components; full startup/rcedit remains unsupported.

## Current ordered lazy-PTD checkpoint

Later work supersedes the cached-only and separate-head checkpoints above. The
ordered EH4 → C++ search now binds the original lazy PTD getter to its live
pending-event child lease. Original setter/free thunks and checked publication
run before the dispatcher consumes the PTD. Original free failure executes the
proved error mapper and original errno router/store; failure conservatively
revokes allocation access without claiming release or unchanged storage.

Explicit cuts still include module/FLS creation, API availability/outcomes,
allocation body effects in the pending adapter, and UCRT PTD lookup for errno.
The original calloc and UCRT getter have separate components but need compatible
live-heap and nested-delivery authority here. Required-getter termination,
new-handler/recursive errno, lazy-path unwind and real OS delivery are unclosed.
There are no additional whole-PE pairs. See
[the current connected scope](CAPTURE-ACQUISITION.md#original-free-failure-and-pending-event-lazy-acquisition)
and [evidence](evidence/free-pending-ptd.json).

Live-heap review: the pending allocator thunk now executes original calloc and
mode getter. Only the HeapAlloc availability and new-handler outcomes remain
backend inputs there. Startup token and descriptor permissions stay separate.
The pending errno call still rejects until the actual UCRT getter's registration
and epilog are bound to the canonical child-delivery chain; its local-only FS
view is insufficient. UCRT/C++ slots must stay distinct. See
[the concrete registry gate](CAPTURE-ACQUISITION.md#exact-remaining-errno-producer-integration).

The registered UCRT integration supersedes the local-FS rejection above for an
already bound live UCRT slot. Both pending calloc errno and original HeapFree
failure errno now execute the original getter against the canonical delivery
registry. Initial UCRT state is still supplied; null-slot/dynamic acquisition,
required-PTD termination, new-handler/recursive allocation and exceptional unwind
remain explicit cuts. Allocation failure now reaches original sentinel cleanup
and then required termination `0x4077ff`. See
[the current producer and next gate](CAPTURE-ACQUISITION.md#registered-ucrt-errno-acquisition).

Required-PTD failure now executes abort4077ff's first CALL and the complete
original query caller40cbcf. Its locked callee40cafd remains the explicit runtime
rejection in this component; standalone tests label supplied query outcomes.
The next cut is EH4/lock3/cookie-decoded signal query plus finally unlock, followed
by signal dispatch/fast-fail/report/exit. No normal return or shutdown is implied.

The locked helper40cafd is now executed through normal registered return. Its
component input includes initial live lock3 and module signal/cookie state;
exception delivery remains a separate gate. The connected pending path rejects
at abort's407804 continuation pending actual signal22 dispatch, encoded callback
authority, reporting/fast-fail and exit. No terminate/abort success is claimed.

Abort407804 decisions and exit wrapper407004 now execute original instructions.
Unbound boundaries are signal22 dispatch40cc14, feature23 query41501c and shared
exit406e69 after actual3/2/0 pushes. No callback/API outcome or process exit is
fabricated. Initial flags and full delivery/startup effects remain supplied.

Shared exit `0x406e69` now executes its original inline FS installation in the
connected pending path. Its next actual rejection is `0x401d51`: GetModuleHandleW
and module-header inspection need checked image authority. The separately supplied
return-mode front rejects at manager `0x406cfa`. Original epilog component tests
establish unlink/return ownership but do not connect that body or model termination.
Handler `0x414af3`, manager cleanup, managed exit, physical exit and signal dispatch
remain unresolved; no successful callback or full-startup claim replaces them.

The original managed-image query is executable with an explicit checked image
view and modeled GetModuleHandleW(NULL) outcome. The startup main-module role,
image mapping producer and loader effects remain an input cut; the default
pending path rejects it. Native/managed query branches now reach their actual
unbound manager406cfa/managed-termination406f55 calls with supplied image authority.

The default exit front now uses canonical process-image authority created by
bootstrap, with no temporary module-reference owner. Bootstrap still takes the
mapped input image under initialization: integrating the original PE mapping with
existing CRT region ownership remains an entry-emission gate. Missing bootstrap,
manager/managed termination and original delivery effects still reject.

PE initial storage now has a bounded raw-file producer (`bootstrap_pe32`), separate
header/section permissions and transactional publication. This removes the supplied
flat image bytes from that component path. It does not close loader side effects,
actual delivery, or startup emission. In particular, the runtime FILE anchor must
become a checked view into mapped `.data` instead of a prior overlapping mapping;
cookie/record initialization must use the same section capabilities. The original
manager406cfa/managed-termination406f55 and physical-exit effects remain unresolved.

The FILE-anchor mapping gap above is now closed by `new_initializing_pe32`:
original FILE storage shares the canonical data-section capability, with no extra
mapping or default lock construction. Remaining supplied initialization includes
cookie/record producers and their external effects. Move those producers to
section-backed views before connecting the original manager and termination;
FILE role binding alone does not certify complete formatting or startup.

Cookie initialization is now original instruction execution for the already
established-cookie branch. Cookie/complement and normal record initialization use
canonical image bytes. The default-cookie producer remains entropy helper401b24:
GetSystemTimeAsFileTime, GetCurrentThreadId, GetCurrentProcessId,
QueryPerformanceCounter, local initialization and guest stack address effects.
This is an actual unresolved call, not a success callback. Startup40161f and later
initializer/manager/termination effects remain separate mandatory gates.

### Default-cookie helper acquisition boundary

Original401b24 now executes its own zeroing, four imported calls, XORs and return;
connected401b71 performs repair and canonical stores. Complete output pairs are
checked before mutation, and acquisition failure preserves earlier writes. The
runtime process/thread numeric ID provenance and individual FILETIME/QPC values
are still explicit inputs. Their ownership check does not manufacture OS
acquisition or uniqueness. No new Windows/whole-PE pairs. The next producer gate
is live identity/time/counter acquisition, then original40161f composition; older
loader, delivery and exit gaps remain.

### Native cookie producer available for the declared Linux domain

Actual PID/TID and UTC/monotonic clock acquisition now replace supplied values
in a separate checked native backend. The older scripted backend remains explicit
component input. Native binding revalidates runtime, initialization and host
thread identity on every API call. This does not supply Windows loader effects,
guest process creation or a general cross-process QPC contract. Actual startup
caller40161f and remaining manager/locale/FILE composition are the next gate.

### Entry-to-first-query path connected

The entry shim and initializer401945 now execute their actual instructions and
calls through startup's installed EH4 record. CPU-prefix writes are retained.
First unbound call: IsProcessorFeaturePresent(10) at401ebe (IAT41501c), followed
by currently unimplemented CPUID/XGETBV feature discovery if that call could
return. No success callback supplies that result. Original incoming-chain/root
activation, later initialization and full exit remain unresolved contracts.

CPU classifier update: original401ea5..4021be now executes through its RET with
bounded checked CPU/OS observations. Its host feature bits do not grant general
SIMD or whole-program admission. The next call40195a→4024ca is still rejected;
4029b4 lock construction and402963 FLS publication must supply their actual
ownership/effects. Earlier no-contract401ebe rejection remains covered. See
[CPU-FEATURES.md](CPU-FEATURES.md) for native versus synthetic evidence and limits.

Startup module update: original4024ca/4029b4 and constructor402c2d prefix execute
from the entry component, reaching unbound resolver402a53 at402c42. Lock/FLS
control cases retain explicitly supplied allocation/destruction observations;
these are not actual API producers. Module-backed bootstrap object41ccc4 and
its FLS callback lifecycle remain unsupported. It is distinct from the recursive
FFFFFFFF marker; no heap PTD identity is granted. See STARTUP-MODULES.md.

Mapped-resolver update: the entry component now reaches LoadLibraryExW at402b00
through the original402a53 resolver. The default entry supplies no load result.
Mapped-resolver tests explicitly supply module/export observations; they do not
close loader initialization or API-set effects. FLS allocation observations
now have separate process-index and fiber-value ownership, with callback-image
lifetime and failure invalidation. Actual FlsAlloc, constructor indirect/fallback
API effects, module-backed bootstrap PTD publication, callback execution and
FlsFree/setter failure composition remain open. See STARTUP-RESOLVER.md.

Resident loader update: established ordinary DLLs can acquire an additional
checked reference through original402af3. The process environment is still an
explicit component premise. API-set mapping and first-load initialization remain
unbound, so actual entry still rejects at402b00. Native named-export/constructor,
FLS allocation/publication and bootstrap PTD callbacks remain open. See
RESIDENT-LOADER.md; missing authority is never converted to an assumed failed or
successful Windows load.

API-set acquisition at402b00 is still unbound. The new pinned x86 observer and
strict namespace validator establish a reproducible mapping-evidence gate;
they cannot authorize native module initialization. Provider construction,
publication/rollback, final-release lifetime, export behavior and unsupported
loader callbacks remain explicit requirements in
[API-SET-BOUNDARY.md](API-SET-BOUNDARY.md). No resident-fixture assumption has
been promoted to actual original-entry acquisition.

Native provider registry construction, publication and teardown now have owned
runtime transitions, including separate target-provider borrows. Published export
descriptors remain noncallable, and the old observed-export entry point cannot
promote them. The callable implementation issuer, API-set mapping and first
synchronization export's actual effects remain unbound at402b00. See
[PROVIDER-OWNERSHIP.md](PROVIDER-OWNERSHIP.md); this replaces no Windows outcome
with a fabricated success callback.

InitializeCriticalSectionEx now has a bounded native global-object implementation
and a specific callable issuer, with protected stdcall transport. Other provider
descriptors remain noncallable. Actual API-set mapping/initial state, resource
failure/error results, general contention and shutdown remain open; original
entry still rejects402b00. See [NATIVE-SYNCHRONIZATION.md](NATIVE-SYNCHRONIZATION.md).

The frozen critical-section Windows/native conformance gate measures only valid
successful operations. Allocation-failure BOOL/LastError and loader initial state
still need a reviewed resource/effect contract; forcing synthetic allocator failure
would be native test evidence, not an observed Windows allocation failure.
[SYNC-CONFORMANCE.md](SYNC-CONFORMANCE.md) records this next decision.

Synchronization resource update: object tracking/map/recursive leases are fixed
32-slot arrays, and the protected stdcall path is tested with every native
allocation denied. Capacity/ownership errors remain converter-domain rejection,
not invented Windows errors. Ex failure triggers/error/poststate and system-provider
initialization remain unproved. Actual original entry is still blocked at402b00;
see [SYNC-RESOURCES.md](SYNC-RESOURCES.md). No additional success samples are needed
to restate this remaining semantic decision.

Native provider construction/reference operations no longer require supplied
load-success observations for their bounded component. API-set/version/flag
binding and the Windows-to-native initial-state/resource contract still block
original0x402b00. The new native initializer is not a Windows DllMain executor;
see NATIVE-PROVIDER-INITIALIZATION.md. Actual FLS publication remains unproved.

## Declared native profile boundary

An explicit `w2l-native-sync-20348-v1` environment replaces the LoadLibrary callback
with real bounded native reference acquisition, after actual native bootstrap.
Original entry reaches GetProcAddress402ae0; its export result is still unbound.
Default startup remains rejected at402b00. This is conditional component execution,
not whole-PE conversion or Windows DLL initialization. The complete prerequisite
classification and next binding are in [NATIVE-PLATFORM-PROFILE.md](NATIVE-PLATFORM-PROFILE.md).

Named GetProcAddress is now bound under the explicit native profile, followed by
original function-cache publication and resolver return. The next cut is original
constructor tail402c47; the guard, indirect synchronization invocation/failure
semantics and fallback remain open. Default admission remains402b00. See
[NAMED-NATIVE-EXPORT.md](NAMED-NATIVE-EXPORT.md).

Constructor tail and original guard execute through the protected indirect CALL
at402c61 under the explicit profile. API resource/failure semantics remain unbound;
no constructor success or lock count is issued. Default admission remains402b00.
[Exact next contract](CONSTRUCTOR-TAIL.md).
