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

## Native initial-search phase and original context-helper check

The native pending event now has a one-time initial-search transition, available
only with its acquired object token, unchanged interrupted source and no active
handler/child delivery. The dispatcher has not begun an unwind or selected an
unwind target in this phase. It therefore produces known-clear 0x66 phase bits,
retaining argument-derived bit0. Flags carry mask0x67; stack-invalid/nested and
reserved bits, the nested link, and CONTEXT remain unknown. This is explicit
native dispatch phase production, not acquisition of a Windows saved CONTEXT.
Failed preflight leaves the flag word and phase unchanged; reentry rejects.

The independently decoded original context helper has a separate no-read check
on the pending search token. Each use validates actual process-image helper
bytes and reads its actual selector cell. It runs the proof's original decision
projection over a view that rejects every captured-stack predicate. Only the
proved selector bypass can succeed. A loader-patched/non-bypass selector still
rejects; no Windows delivery bypass is inferred from mapped IAT bytes. This
returns no generic lease, callback
receipt or delivery permission; it does not certify all other handler consumers.
A changed selector requiring capture observation, changed helper, changed source
CPU or expired event rejects and revokes the underlying token.

Eight additional component cases retain exact bit knowledge, no nested-link
fact, source registers and frame count, and cover reentry, wrong phase, invented
flag knowledge, changed selector/helper and source/event expiry.

## Protected original context-helper execution

The original context helper now executes its proved selector-bypass instruction
path inside a real nested protected CALL/RET pair. The generated wrapper re-proves
the complete handler prefix and validates the actual helper bytes, selector IAT
cell, application-image capability, handler continuation, three handler arguments,
context argument, stack bounds, activation depth and unique protected return
tokens. It executes the original PUSH, MOV, CMP, conditional branch, POP and RET,
including the real compare flags and scratch writes. The interrupted Inner CPU,
pending objects and parent activation are revalidated after return.

This is an explicit handler component cut. The test creates the actual protected
handler activation, executes the original handler prolog and positions the live
stack at the proved context CALL. It does not execute the preceding normalizer or
guard calls, the remainder of the handler prefix, handler disposition, selected
Outer view, cleanup or restoration. The wrapper returns no delivery, selection or
resumption authority. Failure revokes the pending objects and preserves prior
helper writes.

Nine new cases cover successful original helper effects, changed selector and
helper bytes, wrong handler continuation and activation, duplicate return tokens,
wrong helper or handler arguments and expired objects. Total producer component
cases are 48. The original-entry caller is still stopped at the pending
RaiseException delivery gate. Full prefix composition, selected Normal views and
original Inner-to-Outer advancement remain unimplemented.

## Original handler entry through normalizer writeback

A further component path starts at the protected handler entry and executes the
original prefix through its first helper CALL and record-code writeback. The
normalizer now uses native instruction lowering over the instruction domain
explored by the original code-identity proof. Instructions outside that event
domain remain explicit rejection nodes. Both possible initialized global-guard
branches retain their original loads, comparisons, flags and helper stack
effects; an unknown global rejects at its actual compare operand read. The
normalizer's return value is obtained by executing the original body and RET.

The entry validates the same-event objects, exact handler arguments, unique
protected return, application image and original prefix/helper bytes. Global
reads resolve only to the same process-image capability. Prefix source is
re-proved before emission, including the generated front and CALL depth. Failure
revokes the pending objects while retaining earlier handler/helper stores.

Six additional cases cover both global branches, unknown global knowledge,
changed helper code, substituted handler arguments and expired objects. Total
producer component cases are 54. A compiler mutation also checks that changing
the generated prefix front rejects. The handler still begins at an explicit
protected test cut; production handler entry is not admitted by this component.

The next connection is the original caller after writeback, guard arguments and
guard helper, followed by the already lowered context helper and remaining
prefix effects. Guard validation must preserve its original scope-header reads,
cookie comparisons, nested security-check CALL and tail transfer/RET semantics.
The older guard projection/clobber wrapper is insufficient evidence of those CPU
effects. Selected Outer views and actual-handler-bound ordered receipts remain
separate requirements. Original startup still stops at its suspended
RaiseException CALL, with zero whole-PE comparisons.

## Original guard and context caller joined

The protected handler component now continues from normalizer writeback through
the original scope-table decode, guard argument pushes, guard helper, security
checker and context-helper CALL/RET. It stops before original caller instruction
0x402254 (correcting the earlier reported0x402251, which was inside the CALL).
Remaining argument cleanup, flag test, pointer-pair installation,
handler search/disposition and Outer selection are not executed by this cut.

The guard lowers its actual instructions. Scope-header values are checked at
their corresponding original reads, after the original prolog stores. The
optional first cookie check executes a nested protected CALL; the final check
tail-transfers to the security routine on the same CPU and consumes the guard's
original return token. The security routine executes its real CMP/branch/RET.
Its failure tail rejects as unsupported; no Windows fail-fast outcome is
invented. Live original code, cookie-image identity, argument identities, CALL
depth/continuation, stack extent, pending objects and interrupted source remain
checked. Compiler reproof rejects altered caller statements or CALL metadata.

The joined path reproduced a normalizer-local lifetime defect: LEAVE discarded
an unused saved ECX local, but its OpaqueSaved tag survived the validated RET and
blocked the next helper's scratch. Successful original normalizer return now
expires only OpaqueSaved tags in its instruction-proved local extent. Actual
bytes, other tags, active control tokens and every failed-call write remain
intact. Scratch containing an active control token still rejects.

Nine additional cases cover the joined original path, changed guard/security
bytes, malformed header reads with earlier guard saves retained, the optional
nested check, a context selector requiring unsupported observation, occupied
scratch, wrong activation and expired objects. The optional-check case uses an
explicitly altered header with a separate guard proof; it is component evidence,
not an observation of the unchanged binary. Total producer/component cases63.
Actual CALL counts distinguish the optional nested CALL from the final tail
transfer. Source CPU and frame count remain unchanged in these cases.

Production handler entry from the pending event remains a separate gate. This
component grants no complete-handler disposition, selected-frame view, ordered
advancement receipt or restoration authority. Full startup/rcedit admission,
exceptional cleanup and historical Windows launch-timeout causes remain open.

## Original caller cleanup, flags and pointer-pair stores

The protected component now executes the remainder of the original prefix,
0x402254 through0x40226f, reaching before0x402272. Independent disassembly confirms
that the preceding CALL is at0x40224f and returns to0x402254; the earlier reported
0x402251 was inside that CALL's immediate operand. Runtime lowering always used
the decoded continuation, so this corrects reporting rather than execution.

The original MOV, ADD ESP, level read, TEST0x66, conditional branch and installer
stores execute in order. ADD retains its actual arithmetic flags if the later
level read rejects. TEST observes only its original mask, preserving unknown
reserved bits and nested-link/CONTEXT knowledge. The actual record/context
pointers are stored in separate handler-local words; the original establisher
slot receives a pointer to that pair. The producer-bound event, interrupted
CPU and existing frame ownership remain unchanged.

Entry checks bind the actual handler activation/root, continuation stack shape,
original handler/deferred arguments, same-image source and exact pending
objects. Compiler reproof includes the pair offsets. Post-store validation
checks all three pointer identities. Unit success grants no disposition,
selected-frame view, return/selection receipt or resumption authority. A replay
rejects on the actual changed stack state. The handler remains active and its
pair must remain live until separately justified retirement.

Nine additional native cases cover completion, altered tail source, stale
activation, wrong deferred or handler arguments, invented flag knowledge,
failure of the second pair store, a forbidden source alias after cleanup and
replay. The alias failure retains ADD flags and cleanup; the second-store
failure retains TEST flags and the first pointer store while leaving the
establisher's pair slot untouched. Total producer/component cases72. Unknown
record words and raw CONTEXT reads remain checked. Production is still stopped
at the original pending RaiseException gate. Original finite search/RET and
separately validated Outer selection remain next requirements.

## Original Inner finally-only search and actual RET

The component adapter now executes the original finite search beginning0x402272
after the completed prefix. Its certificate permits only a finally-only path
with no executed helper/API/filter calls, unchanged live scope level and a
terminal ContinueSearch result. Original instruction visits, bytes, successors
and finite occurrence bound remain enforced. Inner walks both finally-only
rows while the interrupted frame stays at level1; its cursor is not written
back as a new live level.

The adapter validates the exact pending event-owned record and opaque CONTEXT,
installed pair, handler root/registers, same-image original code and scope table.
It does not use the older supplied-object validator or manufacture NULL/full-zero
record facts. The original epilog restores saved registers and executes RET.
Only afterward does checked retirement remove the handler-local pair's borrow;
the establisher retains numeric pointer bytes without dereference authority.
The interrupted source CPU, pending RaiseException return and normal registry
frames remain live.

An explicit native component invocation runs the whole original handler path
from its protected entry through shared CALL/RET completion. It still starts
with component-supplied dispatcher scratch, not an original Windows dispatcher
or production entry integration. A private, non-Clone result is issued only
after the enclosing protected call also verifies completion. Its one-time stamp
binds the actual activation, handler, root and exact same-event objects. Taking
that result returns the observed scalar1 and consumes the stamp; it grants no
ordered advancement, selected Outer view, containment or restoration authority.
The production delivery/capture gate remains closed.

Fourteen new cases cover the successful original search/RET, changed table or
body, wrong arguments, opaque-context corruption, changed interrupted CPU,
occupied return slot, wrong handler receipt, replay, actual saved-register RET
failure, aliased pair, premature result, cross-event receipt and failed event
lifetime. RET failure retains its protected return and installed pair; no result
is issued. Success preserves mask0x67, unknown nested link and sealed CONTEXT.
Total producer/component cases86. At that checkpoint, full entry-to-exit and
Outer selection remained unproved; the next section records the subsequent
selected Normal view and checked ordered advancement.

## Checked advancement to the live Outer predecessor

A read-only predecessor view is now issued from the actual live Outer activation
before its protected CALL to Inner. The view retains exact runtime, epoch, frame,
caller activation and register knowledge. It grants no instruction execution or
restoration. After Inner suspends at RaiseException and its original handler
returns, the view reconstructs Outer from current guest storage and checks it
against the retained registry frame. The live chain must contain exactly the one
new direct Inner child; both frames must remain installed, unlinked and at epilog
step zero.

Advancement also checks the original Outer-to-Inner CALL bytes at0x4011e5 and the
typed child return-site identity0x4011ea. The actual handler-bound Inner receipt is
then consumed once. Only after a second live Outer storage validation does the
search cursor move from the interrupted Inner ID to the exact Outer ID. The
registry head, interrupted CPU, live normal-frame chain and same-event opaque
objects are unchanged. The returned selection value is descriptive only and has
no cleanup, handler-invocation, CONTEXT-read or restoration method.

Eleven new cases cover successful advancement, changed selected identity,
premature cursor movement, protected storage aliasing, changed interrupted CPU,
cross-event receipt identity, replay, changed Outer layout/scope, changed original
CALL bytes and wrong protected return site. Failure revokes the event while
retaining the original Inner handler's earlier level and pair effects. Total
producer/component cases are97. The canonical component proves original Inner
search selects the actual Outer predecessor; it still begins with component-owned
dispatcher scratch. Production RaiseException delivery, Outer's original search,
cleanup, restoration, Main completion and whole-PE entry-to-exit remain open.

## Original Outer search on the selected live view

The selected predecessor is now usable as a separate live handler view without
relabeling the interrupted event source. `CrtLiveFrame` retains both bindings:
every operation revalidates the suspended Inner CPU/storage through the event,
then independently reconstructs the selected Outer from its pre-CALL view and
current guest storage. Nested helper calls carry both identities. Pending object
checks always use the interrupted Inner source, while ordinary handler frame
reads and writes use only the selected Outer binding.

After the single-use Inner result moves the search cursor, a second protected
component invocation executes the original handler prefix, normalizer, guard,
context helper, pointer-pair installation, finite Outer search, epilog and RET
against Outer's actual scope table at `0x41b1f8` and live level0. The same exact
event-owned record and opaque CONTEXT are used. The registry head and interrupted
CPU remain Inner throughout. Completion consumes the descriptive Outer selection
once and returns an actual handler receipt; it does not advance to Main or grant
cleanup, restoration, resumption, or CONTEXT-read authority.

Eight additional cases cover successful Outer execution, receipt replay, stale
selected identity, premature cursor reversal, changed Outer layout, changed
interrupted CPU, wrong handler arguments and cross-event selection identity.
Failures revoke the event and preserve earlier original effects. Total
producer/component cases are105. Production dispatcher invocation, checked
advancement from the Outer result to Main, incoming-chain containment, cleanup,
restoration and whole-PE entry-to-exit remain open.
