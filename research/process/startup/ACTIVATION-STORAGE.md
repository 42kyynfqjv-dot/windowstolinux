# Shared native activation storage checkpoint

The production input emitter now uses `src/linker/activation.rs` for helper
activation storage. The existing state proof still gates emission and checks
input-specific ABI/memory rules. Generated normal calls snapshot eight x86
register positions with explicit unknown values: the input client cannot supply
numeric ESP, EBX, full flags or a saved instruction address, and does not invent
them. Normal returns preserve the previous protected-word/stack-depth and
ESI/EDI/EBP checks before removing the frame.

Each stack has a unique owner and monotonically increasing activation generation.
Foreign and retired IDs cannot select a current frame. Captured context is owned
storage, not an alias of the caller's mutable value. A shared phase machine keeps
ordinary calls/returns unavailable during search, unwind, restoration or blocked
states. Incomplete integer context blocks the machine; a noncontinuable event
cannot produce a retry candidate. Ordered cleanup exposes each abandoned frame
while live and retires only that innermost frame, retaining the selected frame.

## Exact integration limits

Normal call/return storage is used by actual emitted input programs. Exception
phase methods are exercised by native compiled conformance tests using the same
source; no current decoder or proof emits calls to those methods. They enforce
lifecycle mechanics and do not establish guest semantics. Cleanup completion is
a trusted internal caller obligation: this API does not prove the original
cleanup instructions executed. Stack bytes are not restored by this component.
The current one-frame cleanup traversal must be extended for multiple scopes in
one activation before handling original local unwind.

The retry result is only an immutable candidate. It does not grant target,
pointer or context-field provenance, execute a handler, mutate guest registers,
reset the phase to normal or bypass the borrowed root. No public "handled" Boolean
grants restoration authority. Complete integer values alone are insufficient for
Windows CONTEXT semantics, floating-point state or validated continuation.

The next proof/emission integration must produce a private certificate for actual
event and handler paths, including original cleanup effects, field validity,
same-thread target/stack ownership and containment. Only that proof may add a
restoration transition or original handler dispatch. Startup admission remains
rejected. This is neither a new Windows/ELF exception comparison nor full rcedit
support.

## Independent native validation

The new compiled test checks literal eight-register snapshots, unknown-context
rejection, context-copy isolation, innermost cleanup order [300,200], retention
of selected activation100, wrong-owner/stale IDs, noncontinuable retry and invalid
ordinary operations during exception phases. Existing nested-call native tests
exercise the newly shared storage through the emitted runtime and preserve
ordinary result41, terminal result77 and protected-stack/register failure checks.
Existing production input fixtures exercise real decoded and proved programs.
