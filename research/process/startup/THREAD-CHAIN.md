# Shared thread-chain integration boundary

The same-event C++ invocation component is reviewed through `f5cbd05`. It binds
supplied objects to one pending event and executes the original prefix/common/
unwind path, preserving suspension and receipt lifetime. It does **not** derive
handler selection from the original thread chain or acquire a Windows delivery.

## Original reproducer (retained legacy component path)

Run:

```
cargo test --locked --example crt_stream original_cxx_fs_views_do_not_establish_shared_thread_chain_selection
```

The native experiment executes the unchanged PTD prolog twice with distinct owned
activations. Its predecessor token identifies the same real registry head for
both calls. Both `CrtPtdFrame::live` checks succeed, each local `current` points to
its own three-word record, and the shared `ThreadRegistry::head` is unchanged.
A subsequent original EH4 normal prolog therefore inherits the old registry head,
not either C++ local view. Both candidate C++ owners/context objects can bind to
the same pending event through the *supplied-invocation* constructor.

The test deliberately invokes neither candidate. It does not claim Windows has
two simultaneous thread heads. It shows that per-frame liveness and same-event
object binding do not prove actual head publication or selection. The legacy
component helper has explicit incoming-FS inputs; this experiment exposes that
composition boundary instead of promoting it to an OS dispatch implementation.

## Code boundary reproduced at `8efaffc` (before this change)

- `crt_ptd::helper_source` lowers original FS reads/writes through
  `CrtPtdFrame::previous` and `write_fs`. `write_fs` updates only that frame's
  `current`. The prolog/epilog instruction protocol and storage lifetime are real
  component execution; shared-thread publication is absent.
- Normal EH4, owned EH4, temporary local records and borrowed dispatcher scopes
  update the separate `ThreadRegistry::head` through their own ownership APIs.
- `RegistryHead` cannot identify a C++ three-word registration. The reserved
  `NormalRegistrationKind::Cxx` does not supply its representation or lifecycle;
  existing normal registration/image checks require the EH4 four-word layout.
- `CrtNormalException::issue` binds an EH4 normal source. Its pending-source
  validation intentionally requires that registration at the top. A C++ source
  cannot be forced into that layout by changing the kind tag.
- A head walk must execute or prove the disposition of each preceding handler.
  The current `Pending/Calling/Returned/ResultTaken` component path is not an
  ordered search cursor that authorizes skipping an earlier EH4 handler.

Changing only an enum or accepting a candidate's numeric record address would
leave all these producer obligations unresolved.

## Implemented shared-head path

The registered helper path now executes the same certified prolog/epilog with an
FS effect hook at the actual instruction. `CrtCxxChainBinding` binds runtime,
thread, epoch, owner, stack capability and any active delivery-child lease.
`RegistryHead::Cxx` identifies a fresh three-word registration separately from
EH4's four-word layout. Publication and predecessor restoration update the same
`ThreadRegistry::head` used by EH4. Failed later effects preserve earlier writes
and poison the enclosing path; no successful retirement is invented.

Inheritance revalidates the typed predecessor/handler/state words and the live,
unique protected return of each leading C++ owner; a stale owner cannot lend its
registration to a new EH4 or C++ frame.

Full frame extents (including helper continuation scratch) are checked against
module/thread bounds and other live registrations. Nested original C++ frames
and mixed C++/EH4 calls inherit the actual predecessor. Original epilog completion
is required to remove the unlinked lifetime record. Callback completion now also
compares the C++ registration inventory, so merely restoring the head cannot
conceal an unretired child. Ordinary access remains suspended during an event;
only the matching child lease may create and retire child registrations.

`original_cxx_and_eh4_share_live_lifo_thread_head` executes 24 native cases:
14 mixed-chain/lifetime cases, five directly nested/failure cases, and five
pending-delivery child cases. Positive paths assert completion explicitly.
Existing changed-byte helper certificates are reused. The legacy diagnostic
above still demonstrates why the old explicitly supplied helper path cannot
justify selection. Neither that path nor the new registered helper admits an
entire image. These cases add zero original Windows observations and zero
whole-PE pairs; the artifact replay retains the original five wrapper pairs.

## Exact remaining ordered-dispatch gate

Shared publication closes the split-head producer for the registered helper
path. It does not implement ordered exception dispatch. The present
`CrtNormalHandlerReturn` binds identity, epoch, interrupted frame, event, scope
level and scalar result, **not the executing registration/handler target**.
`take_handler_result` explicitly does not interpret an EXCEPTION_DISPOSITION.
Consequently it must not become a cursor-advance permission by testing EAX=1.

The next connected change must bind execution to a live typed chain node and
original handler target, then mint a target-bound disposition receipt only after
that handler returns with its child registrations retired. A same-event cursor
may advance once to that node's validated predecessor on ContinueSearch; it must
reject wrong-target, replayed, changed-head, missing-owner and unsupported
nested/collided receipts. Keep the physical head and search cursor distinct.
The initial EH4 source cannot be skipped to select a later C++ owner. The
existing `bind_unwind` remains an explicitly supplied component constructor,
not a selected-chain constructor. The source activation still has EH4-specific
validation; supporting a C++ interrupted source requires its actual source
identity/lifetime representation, not retagging EH4 metadata.

Sol can review the shared-head code and evidence. Target-bound dispatch and
source-shape separation remain a bounded Astra High semantic integration.

## Cohesive bounded implementation contract

Use one shared thread-head authority for every supported original FS writer.
Keep registration shape separate from activation/source identity. A C++ record
owns previous/handler/state words with its actual prolog/epilog and live activation;
it must not be reconstructed as EH4 encoded-scope/TryLevel metadata.

1. Bind the C++ prolog's incoming head to the shared thread identity and exact
   current head. Publish its actual FS store through that authority at the
   instruction effect point. Couple the local record and registry update; later
   failure preserves already executed effects and prevents further admission.
2. Carry typed predecessor identity across C++/EH4/temporary/borrowed boundaries.
   Validate full stack extents, LIFO retirement, fresh registration identities,
   module target provenance and original saved/guard/return words. An arbitrary
   live pointer or a reusable stack address is not a predecessor capability.
3. Bind the interrupted activation separately from registration shape. Do not
   clear suspension or change its saved context to make a C++ source fit.
4. Traverse the actual chain in order. Advance only on the original handler's
   validated disposition receipt for the same event and live node. Keep dispatch
   cursor, EH4 scope level, child-frame lease and captured context distinct.
5. Mint the existing same-event invocation from that selected registration and
   justified delivery effect. It must no longer accept selection by a supplied
   owner alone in the admitted production path. Missing containment or a handler
   effect rejects before whole-program emission.

Independent acceptance must include two nested original C++ prologs, mixed EH4/
C++ registration order, a normal call inheriting the actual head, mismatched or
stale predecessors, aliasing, replayed identities, premature retirement, nested
pending events, changed code and preserved prior effects on failure. A prior
handler cannot be skipped because a later candidate happens to match the desired
fixture. Keep legacy component inputs visibly labeled in reproduction reports.

## Delivery acquisition remains separate

The current binding validates supplied 80-byte exception and 716-byte x86 CONTEXT
ranges and the fields actually read. It does not initialize unknown captured bits.
The exact supplied flag domain is unwind bit2 plus the original noncontinuable
bit. No original instruction/API effect currently produces that transition here.
The observer's snapshots are evidence about those runs, not a general producer.

Closing acquisition needs a documented native RaiseException/RtlUnwind delivery
contract, captured-versus-call register attribution, incoming-chain containment
and nested/collided effects for the admitted domain. If an observable captured
value cannot be justified, retain rejection; do not populate it from call-entry
registers or substitute zero. A native runtime is allowed to implement guest
semantics independently, but must prove the observables actually consumed by the
unchanged code.

The legacy boundary retains one native diagnostic experiment. The registered
path adds 24 native cases, zero fresh Windows observations and zero whole-PE
translation pairs.
Full startup/rcedit remains unsupported and PR #45 stays draft.

## Independent review of `dd84b13`

Review reproduced a delayed-use defect: after a binding was created, consuming
its C++ predecessor's protected return still allowed the original FS installation
to succeed. The correction checks the live predecessor again at installation and
restoration effect points in both C++ and EH4 adapters. Four native cases require
the exact lifetime rejection and unchanged head, and assert that the intended
boundary was reached. Earlier executed stores remain observable on failure.

The original 24-case suite now requires the intended rejection classes. Its
predecessor-overwrite case is explicitly a protected-store rejection, not an
executed corrupted-record epilog. Delivery cases require reaching their result
checks, preventing unrelated setup errors from passing the outer rejection.

## Next bounded handler receipt contract

Implement these together through original execution and emitted validation:

1. Bind a receipt to registry identity, epoch, event, delivery generation, fresh
   registration ID and shape, exact handler code/proof identity, live storage and
   predecessor identity. Numeric record addresses alone grant no authority.
2. Mint it only after that selected original handler executes. Generic supplied
   callback results and the current `CrtNormalHandlerReturn` remain component
   results; neither may be upgraded by copying a scalar result into a receipt.
3. Revalidate node bytes, owner/capture lifetime, return authority, protected
   context, physical head and complete child inventory before minting and again
   on consumption. Bind the child lease and preserve prior effects on failure.
4. A cursor starts at the actual head for one pending event. Consumption is
   single-use and ordered; only a supported original disposition advances it to
   the validated predecessor. Physical FS head, EH4 scope level and search cursor
   remain distinct. ContinueSearch=1 must not be confused with a filter's
   ExecuteHandler=1. Use separate typed result domains, rejecting unknown values.
5. Keep captured exception state separate from handler call registers. Callback
   completion grants neither restoration nor new capture authority. C++ source
   activation still needs its own representation instead of EH4 metadata.
6. Missing borrowed-chain containment, nested/collided behavior, termination or
   actual delivery contracts retain rejection. Bounded traversal must reject
   cycles and exhausted budgets, including stale identities after address reuse.

Acceptance must execute mixed C++/EH4 order without skipping the first handler,
then reject wrong-handler/proof/event/lease, duplicate receipts, changed heads or
predecessors, expired owners/captures, unretired children and changed code. Check
original dispositions and emitted state together; no externally supplied success
Boolean. This remains a bounded Astra High integration. Full startup/rcedit is
unsupported and historical Windows timeouts remain unexplained.

## Executed-handler receipt checkpoint

The original C++ prefix emitter now exposes its proved entry, metadata and
common-dispatch target identity. Invocation binds that identity before execution;
the return receipt is minted only after the connected original prefix/common/
unwind path completes and includes the actual identity, owner, frame and lease.
Consumption checks these fields again, including the current live handler.
Four added cases reject wrong receipt target, owner or frame and a changed live
handler after return. All 34 invocation cases assert reaching their intended
boundary. Existing duplicate, nested-event and changed-code checks remain.

This is an executed-handler component receipt, not a selected-registration
receipt. No chain node is invented for the legacy supplied owner. It still
cannot advance an ordered search cursor or resume the guest.

A reproducible compiler gate now identifies the first blocked connection. Using
the unchanged original EH4 handler/table with Search at TryLevel=-2,
`handler_dispatch::prove_dispatch` proves ReturnDisposition(value=1), while
`crt_owned_search::emit` rejects with `owned search: no global boundary`.
The current emitter requires a GlobalUnwind action and lowers only the selected
handler path. The native harness asserts both the original disposition proof
and that precise rejection. This is a compiler-boundary diagnostic, not a new
Windows observation or native whole-handler result.

Next bounded integration: lower the already proved return-only EH4 path through
its actual prefix, guard and epilog on the live normal frame; mint the first
registration-bound disposition only after those instructions return. Then wire
the single-use cursor advance to the checked C++ predecessor and original C++
execution. Do not skip that EH4 source, manufacture its return from the proof's
constant, or promote the component receipt into selection authority. C++ source
shape, actual capture/flag production, incoming-chain and collided effects remain
separate. Sol can review this receipt checkpoint; the live EH4 return-path and
ordered cursor connection remains the concrete Astra integration.

## Sol review of `214d585`: precise return-path contract

Independent inspection found no additional defect in the executed-handler
component receipt. It is created after `cxx_handler_prefix` returns; target,
metadata/dispatcher identity, owner, frame, event and child lease are checked
through consumption. This remains a compiler-proved component target identity,
not dynamic module acquisition or a selected-chain certificate. The 34 invocation
cases, four effect-time lifetime cases and original 24 chain cases were rerun.
Committed PE, generated harness and unwind-source hashes match local retained
artifacts. These checks do not create fresh Windows or whole-PE comparisons.

The earlier emitter diagnostic is an intentional interface boundary, not proof
that deleting its rejection is safe. Three connected constraints must change:

* `crt_owned_search::emit` requires a GlobalUnwind action and returns a native
  `Result<()>` at that CALL cut. Its prefix/owner checks depend on
  `CrtOwnedFrameView`, `CrtOwnedStorage`, `Machine` and `pair_return`.
* `crt_stream_emit::emit_proved_path_with_store` requires a terminal CALL and its
  return hook rejects every RET. A return-only caller needs a distinct verified
  terminal contract; old call-cut callers must retain their rejection behavior.
* Pending delivery instead uses `CrtLiveFrame` and `CrtNormalException` source
  authority. Its actual source remains suspended. A completed handler RET must
  consume only the handler's unique protected return and validate its original
  saved registers, ESP/cleanup and local lifetime. It must not finish the
  interrupted RaiseException call, retire the source or mint restoration rights.

The bounded Astra change should lower the recorded original return path,
including branch checks, calls, guards and epilog, through this live source
adapter. Match every instruction/edge and effect to the proof; exclude unresolved
calls. Keep existing CALL-cut lowering unchanged and test terminal RET versus
CALL, changed encodings/edges, stack cleanup and unknown return state. The proof's
ReturnDisposition constant is an expected result to verify after actual
execution, never a replacement body or supplied success receipt.

Only after original RET completes may a receipt bind its actual fresh
registration ID and typed predecessor. Revalidate source suspension, handler
code/owner/capture lifetime and complete child inventory at minting and at
single-use advancement. Test wrong handler/event/lease, stale predecessor,
skipped order, duplicate consumption, nested delivery and changed code, including
failure after earlier visible writes. The existing C++ component receipt must
remain unable to authorize a cursor advance merely because EAX is 1.

This review changes documentation/evidence only. Original handler return-only
execution, ordered advancement and full startup/rcedit remain unproved.

## Original return and first ordered advancement

The new return-path emitter retains the CALL-cut interface unchanged and accepts
only a separately validated terminal RET/RET-immediate contract. Original edges,
branches, instruction extents and cleanup remain checked. The live search adapter
binds the retained prefix/body/table bytes, executes the original prefix (including
its guard and context helpers), then the proved empty-scope branch and epilog.
This path skips the later guard call exactly as the original branch does. It
checks the actual returned EAX against ContinueSearch=1; the proof constant never
replaces execution. RET consumes only the handler return identity. Transient
handler facts and pointer tags into them expire while numeric escaped bytes and
prior guest effects are preserved. The interrupted RaiseException CALL stays
suspended and retains its protected return.

A first-node cursor binds the fresh normal registration, event, runtime/epoch,
source owner, actual handler, predecessor, captured objects and saved ESP, plus
the complete registered C++ inventory and normal-frame count. Only the generated
original handler call can mint its executed receipt. At consumption it rechecks
code/table bytes, suspension, source/capture ownership, predecessor record bytes
and unique live return authority. One successful ContinueSearch advances the
cursor to the actual predecessor, without unlinking the physical FS head or
issuing a restoration permit. Receipt replay and cursor reuse reject.

Twenty-one native cursor cases and one standalone return case exercise this
composition, including varied predecessor allocation sizes. They require reaching
explicit success/error assertions. Negatives cover wrong target, source, order,
serial, duplicate use, changed code before/after execution, retired context or
predecessor, replaced/rebound capture, unexpected child inventory and nested
exception acquisition. The unknown-feature failure preserves prior original
local writes. Separate emitter tests reject CALL-as-RET, wrong/unaligned cleanup
and non-original edges; three retained-handler byte mutations reject compilation.

This closes the first EH4 return/advance boundary only. The predecessor is selected
but **not executed by this cursor yet**. Its C++ search invocation must derive
owner/record authority from that registration and retain the source event, rather
than reuse the older supplied-owner unwind receipt (which requires unwind flags).
Actual capture acquisition, module/fiber acquisition, incoming-chain containment,
collided delivery and termination remain unproved. Prefix helper effects retain
their existing independently proved component contracts; this does not acquire a
Windows runtime or prove every helper's original initialization. No new Windows
observation or whole-PE comparison is claimed. Full startup/rcedit stays rejected.

## Selected C++ search execution

Sol inspection of the return/advance change found the original CALL-cut rejection
intact, actual RET before receipt minting, and explicit intended-boundary assertions
in the native cases. The connected next step now validates the selected C++
registration against its real live owner, record, handler and full stack extent
(including the helper's extra protected scratch word). Selection cannot accept a
supplied owner belonging to another registration.

The normal event's captured ESP is a checked scalar, while the older C++ context
adapter required a tagged pointer. The new normal binding refines that scalar
against the declared live stack root and captured object token without writing a
new pointer into guest memory or deriving saved state from call registers. Both
representations keep their original exact-value/lifetime checks. Unknown or changed
saved ESP still rejects.

After the first actual EH4 ContinueSearch receipt is consumed, only the matching
selected-node operation can move the event into its next protected handler CALL.
It executes the original C++ prefix/common dispatcher and cached PTD/FLS getter.
For the tested software-exception search domain, the original dispatcher returns
ContinueSearch. A distinct receipt retains selected registration, actual compiled
handler identity, cursor serial, owner and captured context. Consumption rechecks
live record/metadata/capture and returns to the predecessor in the actual chain.
The physical FS head and interrupted source remain live throughout. No generic
callback result, supplied unwind receipt, filter result or restoration token can
stand in for this selected-handler receipt.

The native selector now runs 31 cases: the previous 21 plus ten selected-C++
cases. Success requires both actual original returns and both receipt consumptions.
New negatives cover wrong order/owner, changed capture and handler record,
wrong receipt registration/serial, changed metadata, replay and repeated invocation.
No original instruction is replaced with an expected disposition. Unbound search
backend, noncontinuable search, nested/collided delivery, arbitrary handler chains
and termination effects remain rejecting domains. This is a checked two-handler
component using explicit module/FLS/captured-state inputs, not original entry-to-exit
execution or a full startup/rcedit compatibility claim.

The newly connected positive cases use the original zero-extra-local-allocation
C++ owner shape and ordinary continuable software-exception search. Larger owner
allocations still participate in the earlier registration/order negatives; they
are not claimed as new successful handler execution. The compiled original handler
prefix retains its own frame-shape checks. Tests cannot supply a body or a success
receipt to the selected-call operation.

## Pending-call record production and incoming-boundary review

Review of05fc38c confirmed two actual original handler returns, separate receipt
types and strict success assertions. A missing incoming-owner lifetime check was
identified: the C++ predecessor walk stopped at an Owned node without checking
that node remained live and linked. The walk now validates it through the registry
before minting or consuming handler results. A borrowed root/dispatcher is an
explicit unproved-containment rejection; a different source shape needs its own
binding. The linked owned-node check validates registry lifetime only, and grants
no permission to execute its handler from supplied/projected storage.

The pending RaiseException token now produces the three record fields determined
by its validated zero-parameter API arguments: ExceptionCode, ExceptionFlags and
NumberParameters. Production requires the same live suspended source, Pending
phase, a fresh aligned full80-byte Context-region allocation and a single-use
producer slot. Every byte is checked unknown before the first write. Supplied
initialized storage, stale events, replay and replacing the produced record reject.
The producer leaves ExceptionAddress, nested-record link and unused information
unknown; it neither zeros those bytes nor converts CALL registers into CONTEXT.
The existing object binding still requires an explicit supplied nested link and
captured ESP. Allocation of record storage itself remains a component input.

All34 ordered cases now use these actual pending-call field effects. They retain
the31 previous execution/rejection cases and add an unlinked incoming owned
predecessor, changed predecessor inventory and replaced produced record. Additional
assertions cover stale-event production, fresh-versus-initialized storage, producer
replay and unknown address/parameter bytes. This reduces supplied record contents;
it does not establish acquisition of a Windows captured CONTEXT or incoming-chain
behavior. Full startup/rcedit and the historical Windows timeouts remain unresolved.

Next connected gate: compose the actual pending event with nonempty original EH4
search/selection and cleanup/restoration, deriving containment from executed scope
and filter proofs before any borrowed incoming node. Saved-context acquisition
must follow an independently justified observable-effect contract. If only stack
bounds are observed by an admitted domain, prove that restriction over all its
supported paths before using a projected context; never select invented saved
register values or treat successful component traces as that proof.

Record field requirements come from the documented RaiseException arguments and
EXCEPTION_RECORD fields already referenced in [RAISED-EVENT.md](RAISED-EVENT.md).
This producer admits only the existing validated zero-parameter domain. It does
not assign an exception instruction address, infer register capture timing, invoke
debugger stages or provide default handling for an uncontained search.

## Epoch-root containment binding

Review of12e0e22 found record production limited to the documented pending-call
fields, with unknown bytes and replay rejection intact. Incoming-chain validation
now also retains the epoch's established root when the cursor is created. Every
mint/consume step requires the epoch's previous head and selected Owned root to
still match that identity, and traversal must reach that exact root. Merely
finding some linked Owned frame is insufficient. Existing linked/live checks
remain; borrowed and unbound source shapes still reject.

The37-case selector retains all34 earlier cases and adds changed epoch previous
head, changed selected root and retired incoming owner. Record production also
rejects a mismatched interrupted register snapshot and a forged storage role,
before any field write. The stale-event, nested-event, wrong-capture, alias,
replay, handler/table mutation and prior-effect cases remain. These checks close
root-identity/lifetime attribution, not incoming handler effect containment.

## Concrete capture refactor boundary

There are two existing representations, not an absence of all context work:

* `exception_event::CapturedContext` implements the original decoded helper's
  predicate projection (`projection_body`) under the explicit valid-stack,
  fault-free capture premise. It exposes no numeric ESP or general registers.
* The live normal chain binds `CrtNormalObjects::captured_esp:u32`, loads the exact
  word in `bind/validate`, snapshots that word in `CrtOrderedSearch`, and refines
  it into `CrtCxxContext::esp` plus `esp_value`. Delivery/unwind has its separate
  full storage/snapshot contract. A predicate token cannot satisfy those numeric
  contracts, and the saved value must not be filled from CALL registers.

A bounded Astra High pass is warranted for this semantic connection. Define a
capture-view sum type retaining the numeric supplied boundary while allowing an
event-owned predicate view only after a certificate proves the admitted original
path's observations. Bind the certificate to code/targets, source event, stack
bounds, all reachable helper/filter effects and permitted context operations.
Use the existing decoded context decision tree, including selector and original
failure edges. Keep lifetime validation even on selector bypass. Unknown raw
fields remain unknown in storage; any raw field read, mutation, pointer escape,
new callback or API effect outside the certificate rejects before emission.
Do not turn the explicit valid-stack/no-unproved-interception premise into an
assertion about arbitrary Windows executions or incoming OS handlers.

Acceptance should remove the manually supplied numeric ESP from the connected
original EH4-to-C++ path, while retaining actual instructions and both receipts.
Require independent lower/upper predicate outcomes and ordering, stale/foreign/
nested capture rejection, raw-read/escape/mutation and changed-code negatives,
then same-artifact host comparisons with component/whole-PE labels intact. New
nonempty scope selection, cleanup/restoration, real startup producers and incoming
handler effect closure remain their own admission obligations. An enum alone or
a passing sampled trace is insufficient. This pass has not implemented that
semantic refactor; full capture acquisition and startup/rcedit remain rejected.

The root regression was independently challenged by compiling the generated
harness with just the epoch-root guard removed. It compiled, then case34 returned
Ok(1) where the changed-root rejection was required. The strict regression failed
with that exact unexpected-success assertion (exit101); an unrelated build or
runtime failure does not count. Reproduce on the native Linux validation host:

```
python3 research/process/startup/check_root_guard.py GENERATED_NORMAL_WRAPPER.rs NEW_OUTPUT
```

This is a deliberately weakened authored-component mutation, not a PE conversion
or Windows observation. The unmodified37-case selector passes. Counterexample
source/report hashes are retained in the component evidence JSON.

## Reserved flag correction from this review

The earlier record producer overclaimed complete ExceptionFlags knowledge from
dwExceptionFlags. EXCEPTION_RECORD reserves additional bits for system use;
this component has not closed that delivery footprint. Production now sets only
the known noncontinuable bit (`known=1`) and leaves every other bit unknown.
Code and zero parameter count remain known. The ordered harness independently
asserts that exact known-bit mask and that object binding rejects before the
explicit delivered-flags input is established. Only afterward does the existing
conditional handler composition receive flags0. This is a supplied delivery
contract, not a consequence of the RaiseException argument or a sample run.

The producer/assumption table in DEPENDENCIES.md supersedes earlier shorthand
saying the full flags word was produced. No reserved bit silently becomes zero,
and no new complete capture/API-effect claim follows. A mutation restoring the
old full-known flags store must fail the known-bit regression before dispatch.

The flag correction was independently challenged with `--mutation flags` on the
same checker. Restoring the old full-known store compiled but failed the exact
native assertion: actual known mask4294967295 versus required mask1. Both root
and flags mutations require compilation followed by the intended assertion;
other errors or timeouts cannot count as a detected proof defect.

## Partial capture representation integration

The live normal-event and ordered-search objects now retain a `CrtValue` snapshot,
including its exact known-bit mask, instead of demanding an exact u32 ESP.
`CapturedStackView` distinguishes numeric and masked representations. For a masked
word, the minimum is `bits & known` and the maximum is `bits | !known`. A comparison
returns a Boolean only when every represented value agrees; an ambiguous bound
rejects. The view is ephemeral observation data, not independent event authority.
The enclosing event, frame, storage and cursor still validate lifetime and the
exact live snapshot before use or receipt consumption.

The same decoded context-helper decision tree is emitted for these observations.
Normal EH4 and selected C++ search share the view. A partially known word never
becomes a `CrtPointer`: the C++ numeric refinement is absent, raw numeric extraction
still rejects, and the numeric unwind contract cannot consume it. No context byte
is filled or rewritten by this connection. Existing numeric capture behavior and
all incoming-root/reserved-flag checks remain.

The 47 ordered cases retain the earlier 37 and add two partial-value successes,
three ambiguous-bound rejections, numeric-authority rejection, changed partial
bits, stale event, retired context storage and replacement capture. Assertions
require the intended outcome; an earlier unrelated failure cannot pass a case.
The helper oracle independently enumerates all concrete values for each of 6,561
eight-bit masks/assignments, checking both bound predicates, plus unsigned extremes,
original failure edges, unknown comparison and owner checks even on bypass.

The connected C++ path still requires the existing validated indirect-guard
selector, which also bypasses the original context helper's numeric comparison.
The non-bypass helper is independently exercised with the partial capture before
that test input is installed. Setting an arbitrary guard target was rejected by
`C++ live guard target unbound`; this work does not widen that call contract.

This is a connected representation advance, **not complete capture acquisition**.
The harness supplies partial high-bit knowledge instead of an exact ESP for its
new successes. Windows acquisition has not established those bits. In particular,
the older `OwnedExceptionEvent` predicate capability cannot yet authorize a normal
pending event's raw context storage. A wholly unknown word still rejects. The next
semantic gate must bind a predicate-only capture to the same actual source event,
stack lifetime and a complete original-path observation/effect certificate before
removing the remaining supplied capture cut. Raw field reads, mutation/escape,
uncertified callbacks and incoming-handler effects cannot be inferred safe from
this passing component. Full startup/rcedit and historical timeout causes remain
unresolved.

`check_root_guard.py --mutation capture` deliberately changes the upper-bound
proof to ignore unknown bits. It must compile and fail the exact assertion that
an ambiguous capture was admitted; unrelated build/runtime failure does not count.
This is native adversarial evidence, not a new original-Windows observation.

Independent review adds cases 47 and 48: ambiguity against the C++ stack region
must reject despite valid outer thread bounds; changing only the knowledge mask
must invalidate the live snapshot and receipt. All 49 ordered cases retain strict
expected outcomes. The bounded next producer, observation certificate and event
lifecycle integration is specified in [CAPTURE-ACQUISITION.md](CAPTURE-ACQUISITION.md).
