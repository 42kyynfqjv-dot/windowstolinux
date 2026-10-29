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
