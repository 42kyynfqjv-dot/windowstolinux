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
protected activation. A valid prefix reaches an explicit rejection at the
unbound dispatcher `403002`; it cannot return a successful disposition. A guard
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
and original epilog. Cases include scalar-forged/wrong-offset establisher pointers,
handler-stack overlap, unknown/corrupt guards, unknown/out-of-range state,
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
Before live registry integration, execute and validate the common dispatcher
`403002 -> 403e78 -> 403d76` against the actual exception/context objects. Establish
its PTD calls, exception-code/flag branches, action invocation and failure effects.
For these two action entries, bind PTD+12 and the termination/abort path, including
recursive PTD acquisition and callback exceptions; do not replace termination
with a returning cleanup. Only then can an appropriate disposition or nonreturn
effect compose with the live registry. A concrete uncertainty in these effects
can justify a bounded Astra pass. Full formatter/startup/rcedit remains unsupported.

Historical original-Windows timeouts, including case24, remain unexplained.
The separate projection-budget diagnosis and optimization did not explain them.
