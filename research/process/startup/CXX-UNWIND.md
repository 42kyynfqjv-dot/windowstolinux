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

## Delivery-owned child frames

The completed-event harness remains for the earlier 24 unwind and 14 cached
getter scenarios. A separate connected test now executes the original cached
unwind body while an actual `CrtNormalException::issue` CALL is pending. It uses
supplied handler selection and module/export/fiber/slot acquisition; it does not
claim to acquire a Windows delivery or close incoming-chain containment.

`execute_child_handler` lends a scoped child-frame grant during the protected
handler CALL. Its identity includes the event, a fresh registry lease, the
interrupted frame, the existing frame depth and the handler stack ceiling. The
registry stores the same grant. Ordinary `NormalCallEpoch::state` still rejects
throughout the pending exception. The child handle cannot consume the interrupted
frame or any earlier frame. Child allocation must fit below the handler arguments
and avoid every live registered frame, including a check before prolog writes.
Original prolog/epilog, guard, saved-register, protected-return and LIFO checks
remain in use.

Successful callback return requires all child registrations retired, the original
head/context unchanged, the suspended CALL still unique and the live source frame
revalidated. The grant expires before any result receipt is returned. A callback
result is still not restoration authority. Failure preserves earlier writes and
poisons the registry; it does not clear suspension, roll back memory, manufacture
cleanup or mint a finished-event permit. Nested native helpers are supported;
a second exception rejects explicitly because nested delivery/containment is not
proved by this grant.

Fourteen independent native scenarios cover child and nested-helper completion,
parent retirement rejection, overlapping storage, revoked or mismatched event/
lease, missing RET, corrupt guard, nested-exception rejection without effects,
prior writes on callback failure, changed suspended storage and expired/replayed
authority, changed saved context and mismatched frame depth. Four connected scenarios run the original cached PTD/unwind path:
empty-state return, two sequential child calls, stale/reused FLS rejection, and
the original notification followed by the unbound terminate target. The last
case preserves the next-state store and incremented counter; it produces no
successful unwind receipt. Existing byte-mutation tests continue to bind the
executed instructions to the unchanged artifact.

These 18 new cases are native component checks, with **zero new Windows
observations or whole-PE comparisons**. The five recorded Windows wrapper pairs
retain their original component meaning.

## Next connected gate

The original common dispatcher now executes call403de2 → wrapper4041a4 under
the same child grant, including the original argument pushes, ADD ESP, return
branches and common epilog. The common/thunk/entry/tail are validated against
unchanged bytes; all other search and indirect targets still reject. Entry checks
require live delivery authority and the exact C++ owner/context arguments before
body effects. The original wrapper and registered EH4 body use the same epoch.

Eight native cases cover empty-state completion, original notification then
unsupported termination, stale FLS, unknown flags, retired or changed captured
context, expired grant and an interior establisher alias. Mutation checks also
exercise this emitter mode. Positive delivery cases now assert callback success
explicitly: propagating a failure to an intentionally rejecting outer fixture
cannot count as successful execution. The actual common result is checked before
returning it.

The component still supplies the common entry and its metadata register as
produced by the separately validated prefix. Next thread child authority through
that original prefix, replacing this entry cut. The C++ context, exception bytes,
module/export/fiber/slot and interrupted-frame fixture remain supplied. Actual
Windows delivery acquisition, nested/collided-unwind effects and incoming-chain
containment are unproved. These eight cases add no fresh Windows observations or
whole-PE pairs.

Then execute terminate40770c's own EH4 frame and PTD+12 callback/guard contract,
followed by abort4077ff's signal/lock/debug/exit dependencies. Cleanup exceptions
must enter the actual scope funclets with owned delivery state; no successful
callback default is allowed. The new child authority solves the registry-phase
restriction for this bounded component; it does not solve those external effects.

See [DEPENDENCIES.md](DEPENDENCIES.md) for whole-program acceptance and other
remaining producers. No full startup or utility support is inferred from this
component.
