# Shared thread-chain integration boundary

The same-event C++ invocation component is reviewed through `f5cbd05`. It binds
supplied objects to one pending event and executes the original prefix/common/
unwind path, preserving suspension and receipt lifetime. It does **not** derive
handler selection from the original thread chain or acquire a Windows delivery.

## Reproduced representation gap

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

## Exact code boundary

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

The next semantic refactor warrants bounded Astra High reasoning. Sol can handle
review, regression/evidence work and CI. This boundary adds one native diagnostic
experiment, zero fresh Windows observations and zero whole-PE translation pairs.
Full startup/rcedit remains unsupported and PR #45 stays draft.
