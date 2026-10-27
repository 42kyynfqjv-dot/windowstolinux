# First production refactor after the stalled integration turn

The preceding turn stopped without implementing its broad scope. No execution
environment or approval failure caused that stop. The working tree at resumption
was clean; there were no unpublished implementation files to recover.

Inspection identifies a concrete coupling in `src/linker/input/proof.rs`:
`Op::Call` requires `s.calls == 1`, meaning environment acquisition already ran.
`State` carries six registers, five input-expression ranges and a twelve-byte
input-buffer model. The emitter uses stack indices and two flags. That state
cannot represent a general startup call, numeric x86 ESP/EBP, full saved CONTEXT
or nonlocal cleanup merely by adding a Resume variant to Flow.

The first implemented step extracts call/return graph validation into
`src/linker/control.rs`. The production input proof now invokes it through an
operand-independent edge adapter. Return contexts, cycle/depth limits and error
diagnostics are preserved. The validator deliberately returns no emission or
memory capability. A focused production regression admits a small call graph
structurally and then confirms the input state proof still rejects it before
emission because no environment acquisition took place. Separate tests exercise
shared-helper continuations, a missing return destination, recursion and budgets.

This is a production refactor, not saved-context/exception support. It does not
change the accepted input subset or authorize startup emission.

## Bounded remaining refactor

Keep the input acquisition state as a client-specific policy. Build a separate
general guest activation state with eight x86 registers, numeric stack provenance,
valid-bit context fields and explicit thread/activation generations. Reuse shared
control validation where applicable; exception edges need their own validated
search/unwind/restore transition graph and must not be encoded as ordinary Next.

The proof must produce a private certificate containing closed target sets,
context field validity, root containment and live cleanup ordering. Only that
certificate may feed the exception-aware emitter. Original guest instructions
must perform handler and cleanup effects; no filter-result stencil or arbitrary
address callback. Input's existing certificate cannot be cast or reused as this
new certificate.

Acceptance remains the composed original path in REVIEW-INTEGRATION.md. Before
enabling any path, test wrong-thread/stale context, unknown register fields,
noncontinuable resume, root escape, cleanup fault and invalid target against the
real proof/emitter, with no executable emitted on proof failure. Positive native
execution must retain original cleanup order and restored state; slice evidence
must remain distinct from whole-PE translation. Do not remove the input acquisition
check to make startup calls pass: that would erase a policy without implementing
the missing state and effects.
