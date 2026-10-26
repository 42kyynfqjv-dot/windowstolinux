# SUB-526 bounded nested compiler integration

Implements SUB525-NESTED-DESIGN.md in the strict linker profile. Exact new forms
are FF742408, C744240803000000, C74424040C000000, short forward74 JE, direct E8
with backward targets allowed only under acyclic routine validation, and E9 tail.
No new data types, memory addressing families or pointer operations.

The decoded graph gathers entry/CALL/tail roots, walks each routine using local
fallthrough/branch/continuation edges and rejects cross-root or shared regions.
Transfers contribute separate routine edges; leaf removal rejects cycles without
recursive host traversal. Local branches remain forward. Every decoded instruction
must have a routine owner. Existing complete bounds/overlap/relocation checks and
1024 instruction/path,4096 explored-state limits remain. Runtime emits the same
checked State transitions; it needs no decoder or Windows runtime.

Copy resolves current ESP-relative source before pushing, using the current
frame's unique protected Return owner to find its boundary. Only zero/one owned
local Data word may precede the next copy. Source must be one of two complete
immediate-caller scalar arguments; destination receives current ownership and
an independent Integer value. Stores validate BOTH scalar arguments and balanced
Return before mutation, retain caller ownership, and admit only the two literals.
Tail verifies that window, balance and ESI, changes PC only and retains the actual
return/owner/frame. Static graph proof excludes cycles; existing runtime step caps
remain in force. JE consumes known ZF, preserves flags and validates both paths.

Two new Rust functions bring the root total to60, covering literal frame traces,
copy/store pointer/unknown/protected/foreign rejection at both positions, atomic
word preservation and routine graph boundaries/cycles. The new production CLI
suite executes two independent literal programs (tail success0 and non-tail99)
and49 rejection cases: exact-form neighbors/prefixes, executable truncations,
recursion/tail cycles, interior/out-of-range targets, unbalanced/untaken paths.
It requires deterministic Rust and Hello/empty stderr observations. Existing
compiler-shaped suite now executes11 cases: prior JE rejection is replaced by
explicit JE behavior (99), with unsupported JBE retaining that negative slot.
The existing18 conditional native/70 rejection cases remain. These literal native
cases are separate from actual compiler Windows/Linux comparisons.

The unchanged prior nested MSVC PE from CI40284109464 was converted and run locally:
Nested/empty stderr/exit0. Final CI must additionally build the frozen source with
unchanged flags, run original Windows, transfer the hashed unmodified PE and require
independent Linux conversion to identical Rust and matching ELF observations. Both
host harnesses now require all three structural programs, for eight compiled
programs total, plus102 authored pairs and18 launch samples. Source/flags are not
rewritten. Ordinary CRT, XP/7/general applications remain unvalidated. Existing
valid-stack/no-fault/regular-file output assumptions apply; historical timeout
causes remain unresolved. No merge/release.

Next medium review: routine recovery and ambiguity rejection, protected frame
boundary discovery, both-word borrowed-write validation, tail ESI/return identity,
independent byte layouts and final compiler artifact hashes. Primary instruction
and ABI provenance is in SUB525-NESTED-DESIGN.md; original implementation is
MIT OR Apache-2.0 with no Wine source/runtime or AI runtime.
