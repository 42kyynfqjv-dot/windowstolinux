# Remaining native startup/formatter boundaries

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
