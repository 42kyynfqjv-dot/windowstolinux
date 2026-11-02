# Original RaiseException CALL suspension

Under the explicit native profile, the unchanged entry now executes Inner's
RaiseException CALL at `0x401117`, through the proved named import at `0x415000`.
The protected return word is `0x40111d`'s continuation identity. Execution stops
with a pending event before Windows delivery or captured-context acquisition.
This is component execution through original startup, with zero whole-PE pairs.

## Producer and lifetime

The compiler re-proves the complete Inner prefix, including its four pushes,
and the actual six-byte CALL. It derives argument SP `entry−68`, CALL slot
`entry−72`, frame low `entry−52`, register expressions, known flags and preceding
scalar stores. The runtime checks these against live owned storage, immutable
original bytes, the PE's named RaiseException import, the application lease,
installed frame and registry epoch. It preserves additional incoming knowledge;
it does not overwrite registers with symbolic proof values. A differently sized
prefix derives different stack offsets. A real saved-SP store remains distinct
from the absent field in Inner and Outer.

The existing component issuer still rejects absent saved-SP frames. Only the
producer-bound issuer admits suspension for the original prefix without that
field. Shared CALL preflight checks the actual return slot, permissions,
protected aliases and identity space. The protected push must succeed before
the generation and pending event are published. Preflight rejection leaves
registers, flags, tags, chain and event state unchanged. Earlier original stores
remain visible. The startup/Main/Outer/Inner chain stays installed and normal
epoch execution rejects while suspended. Constructor permission stays revoked.

The receipt retains the original producer and revalidates the process image,
import, application lease, thread/fiber, registry generation, frame, and unique
protected return slot. It cannot outlive those owners. Failure and drop cannot
create a normal-return receipt or unsuspend the epoch.

## Deliberate delivery boundary

Actual CALL registers and typed stack positions are not Windows CONTEXT bytes.
The record producer can write only code, zero parameter count and knowledge of
the documented noncontinuable bit into independently owned fresh storage. Tests
exercise those limited effects and verify all CONTEXT bytes remain unknown.
Production currently has no acquired record/context storage producer, so it
stops before that step. It does not allocate or publish a synthetic OS context.

Acquisition events explicitly reject supplied captured objects, no-read context
leases, direct handler calls and child handler calls. Existing component helpers
retain their separately declared input boundaries; their successful callbacks do
not authorize this event's delivery or resumption. The next contract must acquire
same-event objects with justified observed effects and prove actual handler
selection and incoming-chain containment before admitting delivery. Ordered
cleanup and single-use validated restoration must precede any resumption.
Nested/collided delivery remains unsupported.

## Evidence and review scope

The canonical original-entry tests cover empty and three-entry synthetic
environments, four distinct frames, preserved locals/arguments/protected returns,
and pending CALL ownership. Twenty-two independent acquisition cases cover
changed CALL/IAT, partial or wrong arguments, prior-store corruption, protected
and partial aliases, exhausted or colliding identity, application/fiber expiry,
changed interrupted state/argument storage, capture rejection, failed events, and no constructor
permission. Source proof tests cover changed pushes/CALL and differently sized
frames with both absent and present saved-SP stores. Expected success and errors
are asserted explicitly.

All prior low-stack cases and the 512 KiB limit remain. Final replay must be tied
to one clean commit and all covered sources; five retained Windows comparisons
remain component observations. This change adds no Windows delivery measurement.
The predecessor b4fd086's three workflows passed. Historical original Windows
C01/case26/case28 and other launch timeouts remain unresolved; passes do not locate
the stalled instruction. A local linker bus error was retained separately and
its inactive output losslessly compressed during disk recovery.

Independent Sol review should inspect proof/emitter correspondence, retained
producer lifetime, preflight/push/publication ordering, the delivery gates and
strict negative expectations. Full startup/rcedit, default admission, resource
failure equivalence and exceptional cleanup remain unproved.
