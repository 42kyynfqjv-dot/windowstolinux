# PTD C++ record: owned prefix, unresolved dispatcher

This is a test-only connected component, not a new PE admission path. It uses
the unchanged authored PE identified in [PTD-FLS.md](PTD-FLS.md). No C++ runtime
source has been imported. The private layout is justified by the actual emitted
instructions and data; it is not asserted to be a stable, general Windows ABI.

## Evidence and representation

The original prolog at `414268` creates three words: previous handler, handler
address, and state. The record begins at EBP-12, state is EBP-4, and the getter's
zero-local frame has its cookie guard at EBP-28. This differs from the existing
EH4 encoded scope-table/four-word adapter. The reserved registry Cxx variant
continues to reject; the new adapter does not borrow EH4 admission authority.

`src/crt_cxx_record.rs` checks the exact 36-byte metadata and complete unwind map
against live typed module storage on every query. The supported metadata shape
has magic `19930522`, no catch/IP/exception-specification tables, and at most 32
strictly decreasing unwind-state edges. These restrictions bound inspection;
they do not prove the actions' effects. Runtime, thread, call, frame, original
handler and metadata identities remain distinct. Unknown or invalid states,
mutated metadata, wrong owners and retired frames reject.

The original handler at `414ad6` is lifted through its load/LEA/XOR instructions,
the independently validated cookie-check helper, and the original metadata load.
The checked establisher argument must be the actual typed record pointer. Its
call stack must not overlap the owned frame, and the cookie CALL uses a fresh
protected activation. A valid prefix now enters the original common wrapper `403002` and thunk
`403e78`, then dispatcher `403d76` and the actual context-validator
call `402877`, rejecting at the dispatcher PTD lookup `4028c3`. It cannot return
a successful disposition. A guard
failure remains an unsupported effect, with prior register/flag effects retained.

## The cleanup dependency is termination, not a successful return

The actual metadata at `41b42c` points to two unwind entries at `41b41c`:

| State | Next state | Action |
| --- | --- | --- |
| 0 | -1 | 4026fc |
| 1 | -1 | 4026fc |

The original action is `JMP 40770c`. That body obtains PTD through `40a2e1`,
reads a callback from PTD+12, checks/calls it when non-null, and reaches
`CALL 4077ff; INT3`. It also has its own EH4 scope and exceptional path.
This is static call/effect evidence. It does not prove which branch a delivered
exception takes, the callback identity, or the downstream termination effects.
The existing five Windows wrapper observations do not observe this PTD cleanup.

Consequently, the adapter exposes only a required-action query. It does not
change the state, issue a cleanup receipt, provide a dispatcher disposition,
install a live registry record, or authorize restoration. Repeated queries are
read-only; no single-use control authority is created to replay.

## Independent checks and reproduction

The native test executes the original prolog, valid and corrupt handler prefixes,
and original epilog. The common wrapper saves its actual registers and metadata,
forwards all eight original arguments, and the dispatcher pushes the context
argument. CLD is explicit: this component
uses the existing `Cdecl32Forward` constructor domain, which guarantees DF=0;
the admitted operations preserve it. This does not capture unknown thread DF.
Cases include scalar-forged/wrong-offset establisher pointers,
handler-stack overlap, unknown/corrupt guards, unknown/out-of-range state,
a short-stack failure after the original metadata write (the write persists),
cross-runtime and wrong-call identity, metadata corruption, and retired-frame
reuse. Compile-time checks reject all 29 one-byte handler mutations, metadata
field changes, alias/overflow and nondecreasing unwind edges. Invalid handler
execution does not complete the handler or produce a cleanup receipt.

`check_normal_wrapper.py` binds handler, metadata, map and action bytes to the
unchanged PE, records their hashes, retains the original termination body, and
runs this test separately. It reports zero new Windows pairs for this component.
The existing five recorded Windows wrapper comparisons remain separate evidence.

## Next connected implementation gate

Sol can review this bounded adapter and continue instruction inventory/test work.
Context-validator `402877` now uses the existing decoded decision proof, bound
to an explicit same-thread capture token. That token owns the actual Context
root, stack root, saved typed ESP, runtime/thread/call and frame identity. Both
roots must remain live; narrower aliases cannot invent thread bounds. ESP and
the live selector word are re-read and must retain their required knowledge.
Valid limit/base endpoints are inclusive; malformed or unknown values reject,
including when the original selector would bypass its check. This narrower
admission domain does not emulate INT29 or claim unknown Windows acquisition.

The helper call uses a fresh protected activation and conservative unknown
volatile registers/arithmetic flags; the original caller POP ECX consumes the
actual context argument. The next rejection is the dispatcher PTD call4028c3.
Before registry integration, establish its PTD calls, exception-code/flag branches, action invocation and failure effects.
For these two action entries, bind PTD+12 and the termination/abort path, including
recursive PTD acquisition and callback exceptions; do not replace termination
with a returning cleanup. Only then can an appropriate disposition or nonreturn
effect compose with the live registry. A concrete uncertainty in these effects
can justify a bounded Astra pass. Full formatter/startup/rcedit remains unsupported.

Historical original-Windows timeouts, including case24, remain unexplained.
The separate projection-budget diagnosis and optimization did not explain them.

The connected context checks cover the two inclusive endpoints, wrong runtime,
wrong stack, a narrowed root, context/stack alias, changed/unknown/scalar-forged
ESP, wrong context argument, unknown selector and retired capture token. The
existing decoded-helper tests independently reject invalid limits, reversed
bounds, out-of-bounds ESP and changed instruction/control-flow forms. The explicit
capture may be read repeatedly while live; it grants no event completion,
restoration receipt or replayable control authority. Acquiring this capture from
an actual Windows delivery remains unproved.
