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

## Inner search emitter prerequisite

The dispatch certificate now retains its initial live frame level separately
from its final live level. Return emission requires those levels to agree and
checks that proved initial level at runtime. It no longer assumes every search
starts at -2. Original Inner's finally-only rows preserve live level1; original
Outer's one row preserves level0. Traversal changes the search cursor, not the
interrupted frame's scope word. Original Outer return emission is checked against
its decoded proof, helper sources and table; this is not connected delivery.

A reproduced additional gate remains: original Inner's two-row traversal revisits
instructions, and emit_proved_return_path rejects with `CRT path: repeated
instruction requires loop proof`. Its PC-keyed expected-successor map cannot
represent different edges on successive visits. The regression preserves this
rejection. A sound follow-up needs occurrence-bound original edges and a derived
visit bound, with independent changed-edge, early-exit, repeated-effect and loop
failure tests; simply deleting the duplicate-PC check would lose proof agreement.

Same-event object allocation, partial flag knowledge, Normal predecessor views
and actual Inner-to-Outer advancement are still unimplemented. Production still
stops at the protected RaiseException CALL; the first delivery acceptance target
has not been reached. No delivery gate or context knowledge was widened by this correction.

## Finite original search visits

The bounded return emitter now consumes the actual DispatchProof instruction
visits. The semantic scope-chain walker rejects repeated abstract states and
traces above 2048 instructions. Lowering derives its exact instruction budget
from that successful proof, checks original successors and byte-identical repeated
instructions, and retains disjoint instruction boundaries. Each PC has one
instruction body but a list of allowed visit positions and edges. Every runtime
visit checks its position before the instruction's memory effects; conditional
edges additionally evaluate and check the real flags on that occurrence. The
terminal RET must match the proof's terminal disposition and position.

The old acyclic emitters keep their duplicate-PC rejection. There is no public
raw-path flag or caller-supplied loop bound. Calls and memory operations still
use the original lowering and existing bound effects. The original Inner search
at level 1 now passes return emission; its frame's live level remains 1 while its
scope cursor walks both finally-only rows. Changed scope bytes reject separately.

Independent native loop tests execute actual arithmetic, stores and branches:
normal completion, early-edge disagreement, shortened budget and wrong occurrence.
They check exact failures, no successful return on failure, and preservation of
preceding stores. Compile-time tests reject changed repeated bytes and invalid
successors, and retain the old duplicate-PC negative case.

These tests close the finite-trace emission prerequisite, not object acquisition
or production handler delivery. Runtime-owned same-event record/context storage,
observed search-phase flag knowledge and selected Normal predecessor views remain
unimplemented. Original startup still stops with its RaiseException CALL suspended;
Inner-to-Outer advancement and all restoration remain outside admission.

## Search flag knowledge prerequisite

The prefix proof and return emitter now require only the bits selected by the
original TEST mask (0x66) to be known and clear. The dispatcher begins search
with exactly that mask, rather than full-zero knowledge. Reads of other record
flag bits still reject in the semantic interpreter. An independent exhaustive
byte-completion oracle checks that admission agrees with every possible value
of unknown bits; every missing tested bit and every set tested bit rejects.

This changes the instruction-proof domain only. The existing object validator
still requires its older supplied record contract, including flags and nested
link. Production object acquisition and Normal predecessor views remain closed;
this prerequisite does not issue delivery, capture or resumption authority.

## Pending event-owned storage prerequisite

A producer-bound pending RaiseException event can now acquire native-owned,
disjoint 80-byte record and 716-byte opaque CONTEXT regions. Placement uses live
memory reservations and fresh capabilities. This is native internal storage,
with resource rejection, rather than a supplied Windows allocation outcome.
Failure acquiring the second region releases the first and publishes no token.
Only argument-derived code/count and bit0 are initialized. The nested link,
address, unused record words and all CONTEXT bytes remain unknown.

A distinct pending-storage token validates the actual suspended source, event,
process/thread/epoch, exact object identities, record knowledge and opaque bytes.
Typed CONTEXT reads/writes through aliases reject; failed validation, event
failure and event drop revoke the shared token. Revocation never unseals bytes.
Backing storage stays reserved until runtime destruction; this step grants no
reclamation or guest cleanup authority. The old supplied-object validator and
all handler delivery gates remain closed.
No search-phase flag producer, captured register, Outer view or resumption token
is issued by this storage step.

Nine producer-bound original-prefix component cases cover storage identity, token substitution,
replay, invented NULL-link knowledge, opaque alias mutation, changed interrupted
CPU, failure/drop, stale backing and second-allocation rollback. Original CALL
state and existing frame count are checked. Actual Inner-to-Outer routing still
requires justified search-phase flags, the no-read consumer certificate and a
selected Normal view distinct from interrupted Inner.
