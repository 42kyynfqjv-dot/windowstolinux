# Experimental original-handler slice compilation checkpoint

`examples/handler_slice.rs` invokes the shared production graph decoder and the
new private-constructor proof in `src/handler.rs`. It emits native Rust only after
proving a bounded straight-line raw x86 handler returns disposition0 and updates
saved IP to its declared continuation. Context reads/writes use typed ownership;
unknown register reads, pointer arithmetic/escape, protected ESP/EBP/flags writes,
unsupported effects, noncontinuable input and unproved resume reject before the
output file is written. Native code executes the admitted original operations;
it does not embed an expected result or dispatch by application name/hash.

This API has an explicit **trusted slice ABI premise**: third stack argument is
a complete writable same-thread integer CONTEXT, and fault/continuation addresses
are externally validated instruction boundaries. The slice compiler cannot prove
these premises from raw bytes alone. It is not wired into whole-PE admission and
does not supply the missing thread/root/scope certificate. Cleanup, nested events,
actual startup dispatch and arbitrary context restoration remain unsupported.

The frozen independently authored Windows source manually registers its raw
handler in its own x86 process, executes UD2, and expects resumed EAX42. It also
calls the same compiled handler on a literal context vector, expecting only
EAX and IP changes. `/SAFESEH:NO` applies only to this authored test executable's
manual registration; no system policy or security setting is changed. The image
is an ordinary CRT test harness, not a newly admitted whole program.

The measurement retains the unchanged executable hash, handler RVA and extracted
24 instruction bytes, verifies the original fault is UD2 and compares independently
fixed register values. Linux compiles those same extracted bytes into Rust/ELF
and compares the full declared integer vector. This is **handler-slice execution**,
not a PE-to-ELF startup pair. Windows actual exception restoration and Linux direct
handler invocation are different harness paths and must not be conflated.

At checkpoint creation, local example tests pass: two new proof tests plus ten
inherited graph tests. Clippy passes. Windows/native workflow results are pending.
No observed outcome is claimed before CI executes. Original-handler slice evidence
is the next step; full containment and cleanup/restoration integration remain open.

The user has approved Astra Ultra and parallel agents for the next turn. Current
independent agents review proof/emitter soundness and original Windows evidence.
Preserve this same PR45 and workspace; do not merge the incomplete milestone.
