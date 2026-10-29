# Registered C++ unwind component

The unchanged authored `unwind.exe` now supplies a connected component path:
wrapper4041a4 → EH4 body4041bc → owned state getter4043e9 → checked PTD counter
→ state traversal → either original normal epilog or action bridge404380 and
notification402a20. The original PE SHA256 remains
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
The artifact checker compares all new code/scope bytes with that PE before testing.

This is compiled native component execution. The converter's whole-startup
admission is unchanged. There are **zero new Windows observations and zero new
whole-PE comparisons**. Existing recorded Windows wrapper comparisons retain
their original component scope. rcedit remains unsupported.

## Ownership and executed effects

The body uses its actual allocation16/scope41b298 EH4 prolog, a live normal-call
registry, and the original FS restoration, saved-register pops and RET. The C++
owner retains its distinct PTD-frame protocol. Its record, map and metadata are
checked against live bytes; they are not projected back after callbacks.

The connected cached entry now executes original required/getter4028c3/4028d1,
lookup402bb4, guard and FlsGetValue on the live owned slot. It exposes no PTD
provider or loader callback. The legacy provider entry is retained only for
independent mutation/failure-order tests. Module/export and fiber/slot acquisition
remain supplied initial contracts. Every successful result must
be the same live ThreadData root with at least40 bytes, and its counter at+24
must retain its known value across provider calls. The original INC/CMP/DEC
instructions execute. The bounded initial counter domain is0..2147483646;
unknown, negative and overflow-boundary counters reject. This restriction does
not claim Windows itself rejects those values. Nested normal frames and a
differently sized C++ owner are tested.

The original loop's state write occurs before the action. A local pending-action
owner retains the old index, next state and target across that write. It cannot
be consumed by reading the new state. The exact action arguments, record owner,
map and PTD counter are revalidated before the protected bridge call. The bridge
executes the original frame switch and notification, which writes reason0x103,
action4026fc and the owner's actual EBP to module words41c078/41c074/41c07c in
instruction order. A later write failure preserves earlier writes.

The bound action is an unconditional jump to terminate40770c. Its PTD+12 callback
and abort effects remain unbound, so the component rejects there with the pending
action and counter still active. No action-completion, restoration or shutdown
receipt is produced. The loop-advance point also rejects without an executed
action receipt. Exceptional funclets404241/40424b/40428d remain unbound; a failed
component call poisons the normal epoch and cannot masquerade as an epilog.

## Independent checks and proof limits

Twenty-four native scenarios cover:

- empty-state normal return, nested EH4 registration and differently sized owners;
- both retained map states reaching the original notification and termination cut;
- unknown/overflow/typed counters, wrong PTD role, truncated roots and changed PTD;
- expired storage, changed owner return, guard/scope/metadata corruption;
- protected scratch overlap and interior metadata aliases;
- provider failure with prior writes, and a truncated notification record preserving
  its first two writes before the third fails.

All wrapper/body/scope/action/notification bytes undergo individual mutation
rejection. Existing helper proof tests cover the prolog and epilog protocols.
These tests check original instruction effects against independent expected
memory/register/order assertions. They do not establish actual Windows exception
delivery, fresh Windows unwind observations, loader acquisition, concurrent PTD
access, or the exceptional funclet behavior.

The native harness starts from an explicitly completed-event registry fixture
and supplies module/export/fiber/slot acquisition. The connected entry executes
the actual cached getter. This is not proof that the new body can be
entered from a pending Windows exception. That registry-phase connection remains
an admission gate, alongside actual delivery and termination effects.

## Next connected gate

The cached PTD binding is connected. Fourteen additional native scenarios cover
normal and unknown-LastError return, the pending action, null FLS result, retired
and reused slots, unloaded modules, foreign fibers, cache miss, interior PTD
corruption, truncated/retired PTD, changed guard, unknown and sentinel indices.
Cache bytes, module reference count and initialization phase remain unchanged.
A completed call cannot be replayed. Existing getter/lookup mutation checks still
bind the original code and imports to the retained PE.

The next concrete gate is a registry-phase adapter: `NormalCallEpoch::state`
currently rejects `pending_exception.is_some()`. This correctly protects the
interrupted normal frame. Binding an EH4 child under that epoch would require
separate delivery-owned child authority, keeping the interrupted frame suspended,
with independent nested-handler return, failure and restoration checks. Removing
that check or treating the finished-event permit as pending delivery is unsound.
This is a bounded ownership transition design suitable for Astra High if Sol
cannot establish it from existing delivery leases. No bypass is implemented.

Then execute terminate40770c's own EH4 frame and PTD+12 callback/guard contract,
followed by abort4077ff's signal/lock/debug/exit dependencies. Cleanup exceptions
must enter the actual scope funclets with owned delivery state; no successful
callback default is allowed. Sol can review this connected component and bind the
existing getter. A concrete pending-exception registry transition or terminal
control-flow question may warrant a bounded Astra pass.

See [DEPENDENCIES.md](DEPENDENCIES.md) for whole-program acceptance and other
remaining producers. No full startup or utility support is inferred from this
component.
