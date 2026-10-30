# Delivery identity and the observable collided-unwind boundary

This is a component contract and implementation checkpoint. It adds no Windows
API-effect certificate, PE admission or new Windows/ELF translation pair. The
original converter still rejects full startup/rcedit.

## Evidence reviewed

The retained original-Windows observer report from artifact 12861766580 has
SHA256 `b80bb88abe3a07321ac95fe0debf32083ee6d90f66084ffbdef69f18f3fec51e`.
Its PE is `836e40be0afaa83b399d392a12a562330e5ed141013750093d6c6e16e515281d`;
it is a separately instrumented Server 2022 build 20348 run, not the local
`1e96cb39...` component PE. The executable loaded at 0x110000. The observed
x86 kernel32 RtlUnwind export is RVA 94144 in version 10.0.20348.5756, module
SHA256 `f68966e72d3f8c60afa30d99d26b6b223ee1b6df24f89278cab743a49d0d6b2f`.
The x86 ntdll is version 10.0.20348.5756, SHA256
`1e78588dcb44d47c1656f9f6eab8ab5beb5279959bcebf74c0f869d8d1c73322`.

The report's captured CONTEXT is 0x4fed88; normal unwind callbacks use CONTEXT
0x4fe908 and nonzero dispatcher context 0x4fe864. The older text's 0x4fe8c8 for
this particular report was inaccurate and is corrected. Addresses are observations,
not native mapping requirements. Repeated callbacks share an observed dispatcher
address; this alone says nothing about its contents or longer lifetime.

The report has **zero nested-handler hits**. Its `cleanup-failure` run injects an
observer failure and proves owned-child cleanup; it does not exercise a guest
collided unwind. It cannot establish that exceptional callback branches are
unobservable or that their writes are harmless.

Primary Microsoft documentation rechecked on 2026-10-29:

- [RtlUnwind](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind)
  specifies target frame, continuation and integer return value. It does not
  specify the complete callback register/CONTEXT mutation footprint.
- [EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
  marks the other exception flag bits as reserved. The component's flags=2 and
  reserved-field restrictions require their own closed effect contract.

## Original instruction effects and limits

| Original region | Proven or observed use | Remaining obligation |
| --- | --- | --- |
| Main/Inner handler prefix | Reads record code, normalizes it, writes code back; reads encoded table and TryLevel; passes CONTEXT to the guard | Whole API footprint and exceptional helper behavior are not inferred from that prefix |
| Context guard | Reads CONTEXT+0xc4 (ESP) on the non-bypass path and compares with live thread bounds | The delivery object's acquisition is still supplied; neither zero filling nor copied callback registers establishes it |
| Ordinary handler unwind route | Reads record flags and owned table/frame state; runs cleanup and notification; does not dereference the fourth callback argument in the admitted route | New instructions, unknown calls and collided delivery require additional proof |
| Nested handler 0x4027e6–0x4027ef | `MOV EAX,[ESP+8]; MOV EDX,[ESP+16]; MOV [EDX],EAX` writes the establisher through dispatcher context | Requires a writable OS-delivery object, its valid extent/identity, and the subsequent dispatcher's interpretation |
| Nested handler 0x4027f0 | Returns disposition 3 after the store | Cannot be treated as ordinary successful cleanup or ignored |
| Global wrapper continuation | Original POP/RET restores saved words after unknown working registers | API continuation authority still requires complete effects and actual younger-frame completion |

The collided store is in the unchanged original bytes. A newly generated negative
case executes those three actual instructions with an opaque dispatcher token and
rejects the store, retaining the cleanup writes already reached. It does not
substitute success, a null pointer, or a made-up writable record.

## Implemented bounded advance

`CrtDispatcherContext` is an opaque value tied to the runtime arena, thread,
unwind epoch, callback and fresh serial. It supplies no guest numeric address,
byte extent or contents. Full-word stack transport preserves it; arithmetic,
partial reads, pointer conversion and output of its underlying bytes reject.
A live callback must match the token's epoch/identity and the actual fourth stack
argument at every validation. Ending the delivery revokes aliases on both success
and failure. A nested callback cannot reuse the parent's lease. Sequential
callbacks can use fresh leases even when Windows reused a numeric address: this
model makes no observable address-equality promise.

Legacy zero-argument component inputs remain explicitly separate. This change
only enables opaque **delivery** arguments; the older search/capture entry still
has its own restricted input contract. A guest path that observes dispatcher
contents must be rejected during conversion before any complete-PE emission.
The current private component's runtime rejection is an additional guard, not a
replacement for that absent admission proof.

Ten new connected scenarios cover normal opaque input through cleanup, conditional
wrapper return and selected-caller transfer boundary; wrong epoch/callback;
expired or changed argument; nested reuse; forbidden bit/partial access; failure
after writes; changed original caller; and the original collided store. Independent
runtime tests cover same-number cross-arena identities, aliases after expiry,
transport widths/roles, external output and the 16-live-token budget. A symbolic
prefix mutation reading argument four instead of CONTEXT is rejected.

No callback snapshot, opaque token or successful conditional continuation can
initialize Machine's saved state or authorize guest resumption.

## Shortest connected next steps

1. Sol can review this bounded change and connect the already proved original
   selected-transfer instructions to owned landing/context stores. The resulting
   test must still label the supplied API continuation as a conditional cut.
2. Before admitting an actual API, acquire independent original delivery evidence
   for a guest nested/collided case, recording callback entry/exit, actual CONTEXT
   fields consumed, dispatcher word before/after, chain transitions and final
   outcome. Retain source/artifact/module identities and ordinary baseline apart
   from observer instrumentation. Existing observer cleanup-failure evidence is
   insufficient for this purpose.
3. A bounded Astra High contract pass is warranted if that evidence requires a
   new dispatcher traversal rule or context ownership transition. Define a typed
   writable dispatcher object and consume disposition 3 only after its original
   store and validated ownership. Reject foreign-root, unknown/context writes,
   unproved failures and missing containment before whole-PE emission.

Captured/delivery CONTEXT acquisition, complete source-memory footprint, incoming
loader handler containment and selected landing restoration remain explicit gates.
The historical output-present/process-alive Windows timeouts remain unresolved.
