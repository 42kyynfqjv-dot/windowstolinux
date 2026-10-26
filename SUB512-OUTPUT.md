# SUB-512 imported output implementation

Implements the conditional contract in SUB511-OUTPUT-DESIGN.md. The production
converter accepts a three-section variant: RX code, immutable R data, loader-owned
RW import metadata. Only import/IAT directories are permitted, exactly one named
msvcrt.dll!_write thunk, disjoint complete metadata spans, no ordinals/binding/delay
imports. Existing one/two-section policies retain empty directories.

An image-aware iced call recognizer accepts only prefix-free FF15 at the validated
IAT VA. The byte-only decoder/oracle stays unchanged and rejects this form without
image context. There is no dynamic lookup or original-PE execution in native output.
Buffers are resolved from the same Pe, entirely inside declared raw and virtual
immutable data, with checked VA/RVA arithmetic and printable ASCII1..64 validation.

The import validator explores both branch successors with cloned tagged-stack
state, checks every hypothetical argument and continuation, and rejects unknown
flags, invalid ownership, repeated calls or differing payloads at one call site.
It caps total hypothetical instruction visits at16384, each path at1024, and uses
the existing128-word/32-call stack bounds including the transient external return.
This conservative policy can reject programs whose selected native path is valid.
Validator performs no I/O. Emitted code calls native support only on its runtime
path, preserves caller arguments for LEA cleanup, sets EAX=count, and clears flag
knowledge. Native support duplicates stdout into a File, verifies regular-file
metadata and performs one unbuffered write. Errors/short writes abort with125 and
a diagnostic, never fabricated success. It is independent std-only Rust support.

Evidence harness scripts/check_imported_output.py constructs six authored programs:
Hello, changed World payload, one byte,64 bytes, untaken output and helper output.
Linux performs actual PE-to-Rust-to-ELF translation, repeated-source equality and
exact stdout/stderr/exit assertions; Windows executes the identical fixture builder
against independently specified expected bytes. It also checks2048 truncations and
36 malformed metadata/address/argument/flag/cleanup cases through the real CLI.
Nonregular Linux stdout produces explicit125 failure. Three new production Rust
tests check exact encoding rejection, repeated calls, transient stack limits and
injected short/zero/BrokenPipe/Interrupted/WriteZero outcomes with no retry.
The prior63 production comparisons and decoder mutation corpus remain intact.
The isolated evaluation suite inherits the three new production tests; do not count
them again as independent tests. Separate SUB-511 probes remain supplemental.

Assumptions remain: preferred image base, valid native stack, initialized legacy
CRT byte text/binary mode, isolated writable regular stdout and full-write success.
Printable bytes avoid LF/CTRL-Z conversion, not Unicode-mode differences. errno,
_doserrno, CRT streams/handlers and other volatile registers are unobservable in
this subset. Failure behavior is a converter rejection outside equivalence domain;
Windows error semantics and durability are not emulated. Windows Server2025 evidence
is not XP7/application compatibility. No general APIs/memory/handles, Wine or AI.

Next medium review should independently audit metadata range/alias handling,
hypothetical shared/nested contexts and state-budget rejection, production emitter
payload binding and error paths. Keep PR draft/unmerged; no release.
