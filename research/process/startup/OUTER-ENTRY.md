# Outer entered without a saved-ESP store

The controlled native-profile path executes Main's original CALL
`0x401316 → Outer 0x4011a0`, Outer's inline EH4 publication at `0x4011ca`,
and its original stores of local 200, cursor 2 and scope 0. It stops **before
CALL `0x4011e5 → Inner 0x4010c0`**. Inner's later RaiseException CALL is
`0x401117`; none of that acquisition or delivery has executed on this path.

The authored names come from `unwind_probe.c`: Main calls Outer, which calls
Inner. The proof/replay checks unchanged PE bytes, not source-name dispatch.
The canonical test reaches this point from the actual entry and prior startup
initializers for both controlled synthetic environment variants. Additional
cases use an explicit component cut beneath a live Main frame; those cases
are not separate whole-program evidence.

## Proving absence and preserving storage

The complete original prolog is call-free and ends at `0x4011d0`. Its existing
symbolic frame proof has no stack-address stores or pending arguments; the
decoded instructions contain no memory MOV from ESP. The checked header is
`[-2, 0, -48, 0]`, and the frozen scope entry is finally-only. The original
epilog is separately decoded and checked for predecessor restoration, guard
discard, saved-register order and RET. That supplies a normal-frame reservation
plan, not proof of any executed finally body or return.

`CrtNormalLayout.saved_sp` now explicitly distinguishes `Some(offset)` from
`None`. Existing helper frames and Main retain their proved present fields.
Only a present field enters Main's delayed-store stage. Outer has no such stage
and no eventual write: its image permanently omits the absent word. Image ESP
describes the owned frame extent; it is not a memory-loaded restoration value.

The live projection does not read, compare, initialize or tag a guessed slot at
EBP-24. Unknown bytes, an old scalar, or an old matching pointer there cannot
create saved-SP authority and remain unchanged. The explicit saved-SP store
method rejects absence without writes. The pending-exception issuer rejects
absent-slot layouts until a distinct delivery contract is proved; this change
does not create capture, restoration or exception-containment authority.

Relative to the protected call entry, Outer has EBP -4, low/guard -52, record
-20, saved EDI -48, ESI -44, EBX -40 and EBP -4. The actual parent is Main's
normal-frame identity, which still points to startup. It is not a copied
Machine root or an empty incoming chain. Original CALL machinery creates the
new unique return at continuation `0x40131b`.

## Ordering and rejection

The original FS instruction publishes the checked child frame. The body writes
200 and 2 before changing try level from -2 to 0. If the final transition rejects,
the first two stores and published head remain. Invalid ownership, code, layout
or protected aliases reject at their checked boundary; no callback success or
Windows exception result is invented. Corruption injected after publication
does not roll back that prior publication.

Scope, prolog, initial body, epilog and caller bytes remain frozen against the
unchanged PE and checked for live code/image ownership. Forging a present slot,
duplicate prolog/install, stale initialization/code, wrong frame base, guard or
cookie state and unsupported exception issuance have explicit rejection cases.
Twenty-two native artifact cases run at two stack placements. Added proof tests
reject a new saved-ESP instruction and all selected byte mutations. Existing
Main delayed-store, signed-stack, module-ABI and low-stack checks remain.

## Review, evidence and next scope

Review of `045bf3c` found no additional Main publication, caller ownership or
signed-stack defect. All 570 predecessor source hashes and report/Rust hashes
were reverified. Both predecessor Rust CI workflows passed; inventory remained
active at the initial review and subsequently passed as well. Local gates
passed: 366 CRT tests (two separately gated ignores), 185 unwind tests, 182 root
tests, canonical live entry, 115 Python tests (one skip), all-target Clippy with
warnings denied, formatting and all 152 word/register cases at the unchanged
512 KiB child stack with 64 KiB padding. See the tracker for exact-head CI and
the final clean source-pinned replay, not an interrupted or mixed-source run.

An initial compile hit temporary-disk exhaustion, including a sandbox-start
failure. Inactive generated binaries were losslessly archived with hash checks;
the failed logs remain separate from subsequent passing checks and historical
Windows launch failures. One initial component fixture also retained the generic
helper's RET12 setting; it was corrected to the actual startup RET0 ABI without
changing runtime validation. No stack, timeout or assertion limit was increased.

Next, review this absence representation and bind Inner's real original frame
under live Outer, preserving the distinct larger Main frame. Inner likewise
requires proof of actual storage effects, not an initializer filling a supplied
Machine model. Stop at or separately prove its software-exception acquisition;
callback completion or an unobserved CONTEXT lease is not resumption authority.

Main/Outer completion, actual exception acquisition/delivery, exceptional
cleanup, resource-failure equivalence, concurrency and full startup/rcedit/default
admission remain unsupported. Five retained Windows comparisons are component
evidence; there are zero whole-PE entry-to-exit pairs. Historical original C01
and case-26 timeouts occurred before conversion and remain unresolved. Retained
ToolHelp/WCT records contain no stalled IP/stack; separate passes do not locate
the stall. Synthetic environments only.
