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

## Reviewed checkpoint and observed evidence

Run [40605743543](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40605743543)
at `435358f474cc51c196335f0d66d890aaed4984ff` passed all three dedicated jobs.
The Windows Server 2022 observation resumed with EAX 42; the extracted handler's
native Linux invocation matched all ten declared context words. The retained PE
SHA-256 was `8d15579af1ac6972c0182941070b67de2032e6c02f119e667792cdfdf7359f71`,
and handler SHA-256 was `51d316bd5174061a884b78417fb94265a1a8c3ee2b38639a31b0906d454e644d`.
This is one slice comparison, zero new whole-PE startup translations.

Parallel review reproduced acceptance of nonvolatile working-register clobbers.
The proof now rejects those writes; independent prefixes cover EBX/EBP/ESI/EDI.
The emitted slice checks its fault-IP precondition before any mutation and returns
an error for a mismatched context. A local compiled literal-vector test checked
both the valid transformation and unchanged state on error. The Linux harness now
hashes the retained PE, re-extracts the handler bytes, and bounds subprocess launches
with retained failure output. Windows expectations use the frozen manifest.
These follow-up fixes pass formatting, Clippy, and the same twelve example tests;
their own cross-host CI must be checked separately from the earlier run above.

## Next architecture boundary

The slice ABI is still a trusted premise, not a whole-program certificate. Next
connect a privately constructed context/continuation capability to the production
activation identity, original instruction boundaries and contained event proof;
then execute original handler effects, ordered scope cleanup and validated native
restoration through that capability. Reject missing ownership, stale identities,
uninitialized context, borrowed-root escape and incomplete cleanup before emission.
Independent nested/failure tests must exercise the composed proof/emitter path.

That work warrants Astra Ultra with independent proof and emitter review. Routine
CI checks and review of this checkpoint need only medium effort. Preserve PR #45
and the workspace; do not merge the incomplete milestone.
