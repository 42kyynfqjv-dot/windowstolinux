# Formatter and deferred teardown checkpoint

This checkpoint preserves interrupted work on SUB-579 and PR #45. It does not
admit a complete formatter, CRT startup, rcedit, or another whole PE. Production
admission barriers remain in place. No new Windows/ELF whole-program pairs are
claimed here.

## Implemented boundaries

The shared CRT IR and native emitter now represent bounded integer division,
carry, signed dividend extension, partial-width operations, guarded jump tables,
callee argument cleanup, and explicitly bound thread-chain operations. Unbound
FS effects and unresolved external tails reject emission. Modular indexed
addresses must remain inside the original live memory capability.

Original formatter state, modifier, parser, decimal, magnitude, length,
character/span output, descriptor validation and classification components have
separate graph certificates. Their callee effects, initialized input, locale,
buffer capacity and argument bounds remain composition requirements. Certificate
construction and component execution do not establish complete formatter
execution. `formatter_binding.py` retains code/data and exception metadata from
the unchanged authored PE; measured addresses are evidence extraction inputs,
not application identities used by the converter.

Normal calls use a one-shot finished-event permit and distinct registration
identities. The original EH4 prolog proof records its protected continuation
relocation. Native execution now lowers the actual helper instructions on the
same checked stack, with the outer activation preserved and a separately owned
helper continuation. The mandatory installation callback still requires real
registry integration; callback success alone is not a registry certificate.
An ordinary call cannot substitute for this helper ABI. The integer dispatcher's
C++ record and state are distinct from an EH4 record.

The Main-return receipt now captures the complete returned register projection.
The teardown bridge binds the exact CRT memory arena and registry before Main's
return, then checks the consumed receipt, retired frame and returned context.
This provides local ownership authority only. It does not prove that shutdown
is the next original action or perform callbacks, flushing or termination.

## Confirmed defects repaired

An independent mutation of a returned unknown register into a known value could
previously pass the teardown handoff. All ten context positions are now checked.

A FILE B lease could previously adopt or free a live buffer allocated for FILE
A. Buffer allocation/first FILE adoption now records exclusive FILE ownership;
cross-FILE adoption and release reject before effects. Initialization/shutdown
retain separate authority. Retired pointer bits remain transportable without
restoring dereference or release authority. Shared buffers need a separate
reviewed contract and are outside this component subset.

## Verification and reproducibility

Run `cargo test --locked --example crt_stream`,
`cargo test --locked --example frame_unwind`,
`cargo test --locked --bin w2l`,
`cargo clippy --locked --all-targets -- -D warnings`, and
`python3 -m unittest discover -s research/process/startup -v`.
Example suites include inherited tests; do not sum their counts as unique
coverage. The shutdown suite also reuses the runtime conformance tests.

The retained original PE SHA-256 is
`4754a949898e06601e3c84cd9e78d93bee60e73e6e9eb69f816a2479ade2564c`.
Existing Windows observations and translated component comparisons at
`9a260e1f61beb0f9e4382c6eda2c886d33209f00` remain historical evidence;
local tests in this checkpoint are not fresh Windows observations.

## Connected implementation still required

1. Bind the native EH4 prolog installation callback to the live registry and
   execute the enclosing FILE/descriptor wrapper effects on that same stack.
   Protected continuation relocation itself is now mechanically executed.
2. Compose the original integer dispatcher and distinct C++ registration with
   actual parser/output/buffer calls. Any no-escape domain requires proof over
   every reachable instruction and effect; sampled success cannot supply it.
3. Close original context construction/destruction and lazy thread-state
   acquisition. A cached getter cannot justify a fresh constructor's error path.
4. Lift the actual exit caller and encoded callback traversal before stream
   teardown. The forward null-skipping walker at 0x406ca1 is also used during
   initialization; it is not a standalone exit operation. Preserve callback
   order, partial-write loss/error behavior, final flush and termination.

These are connected proof/emitter architecture tasks suitable for a bounded
Astra reasoning pass. Routine tests, review and CI stay on Sol. Ultra is not
authorized by the current user direction. Historical Windows timeout causes,
ordinary CRT/application coverage and XP/7 validation remain unresolved.


## Native prolog integration review

The native helper preserves the enclosing CPU entry/return identity and does not
mark the outer wrapper returned. It requires distinct, unique helper and caller
continuations, complete scratch capacity, original scope/allocation words and a
valid typed predecessor. At the proved relocation instruction it consumes only
the old helper token after verifying both copies; the original MOV then writes
the encoded scope. Before the special RET, it rechecks the actual record, guard,
saved slots and installation result and consumes the sole relocated token.

Three allocation layouts execute in native regression tests. Wrong/duplicate
returns, occupied scratch, foreign predecessors, callback record corruption,
unknown saved bits and ordinary-ABI misuse are checked. A callback's write before
failure remains observable; failure leaves the reached helper state intact.
These are local component tests, not fresh Windows differential observations.

Independent review reproduced ordinary overwrite and storage retirement of a
live thread-chain token. Both now reject, while the explicitly checked POP
consumes the token. Full formatter exception/registry and exit composition stay
open. Dedicated CI40686009789 passed for the preceding b94e90ef checkpoint; its
broader regression runs were still progressing at review time.
