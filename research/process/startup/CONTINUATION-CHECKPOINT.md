# Production continuation checkpoint, SUB-579 / PR45

The environment-input production emitter now lowers compiled basic blocks to
explicit `Next`, `Call`, `Return` and `Terminal` effects. Calls no longer recurse
through Rust functions. An iterative dispatcher carries protected guest return
slots, caller stack extent and saved ESI/EDI/EBP values. Normal return validates
these before removing the activation or return slot. Terminal acquisition failure
bypasses all ordinary continuations. The same call-depth constant drives graph
validation, ownership proof and generated code.

This is used by existing admitted PE conversion and native helper programs. It
does not widen instruction/API admission or translate the exception probes. The
input proof still tracks symbolic register values, borrowed buffer ownership and
initialized ranges; the runtime checks supplement that proof. The generated
dispatcher selects statically emitted blocks and never decodes PE bytes.

One new native harness uses the exact emitted continuation core with independent
nested-return expectations (30 + 10 + 1 = 41), terminal failure77 that must not
execute either caller continuation, and corrupt/missing return, saved-register
violation and depth-limit negatives. These six cases are native control checks,
not six Windows/ELF comparisons. Existing decoded-helper tests continue through
the production proof and new emitter, including runtime-dependent inputs.

Remaining integration is substantive: the streaming/startup path does not yet
share this activation representation; owned x86 context fields, scope cleanup,
exception search, nonlocal unwind and validated restoration remain unimplemented.
`Terminal` represents the existing host acquisition failure policy, not a Windows
guest exception. The permanent startup pending barrier stays in force.

Next work in this same PR must combine actual handler instructions and controlled
event/context effects with generation-bound activation ownership and checked
memory. Preserve cleanup scopes and selected-frame lifetime. This checkpoint is
recoverable production groundwork, not completed SUB-579 acceptance or a reason
to merge. Frozen Windows experiment source and expectations remain unchanged.
