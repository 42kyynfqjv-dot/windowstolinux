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

Evidence harness scripts/check_imported_output.py constructs seven authored programs:
Hello, changed World payload, one byte,64 bytes, untaken output helper output and alternate caller contexts sharing an output helper.
Linux performs actual PE-to-Rust-to-ELF translation, repeated-source equality and
exact stdout/stderr/exit assertions; Windows executes the identical fixture builder
against independently specified expected bytes. It also checks2048 truncations and
40 malformed metadata/address/argument/flag/cleanup cases through the real CLI.
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

## Medium review

The former harness printed36 malformed cases but executed35. It now counts actual
rejections and adds five table/name-end and alias cases, yielding40. A seventh
Windows/Linux fixture checks two hypothetical callers sharing one helper (one
selected by native control flow). Production write failure tests now assert retained
partial bytes as well as failure/no retry. No production acceptance defect was
reproduced. Metadata reads are checked against raw and virtual section extents,
then file bounds; disjoint spans prevent thunk/descriptor/name aliasing. The buffer
resolver is an internal trusted callback bound by Pe::translate to this image;
there is no public provenance type proof. The old byte-only decoder oracle does
not independently cover imported call recognition.

M0 foundation and narrow M1 translation/equivalence acceptance have reproducible
CI evidence. That does not complete the original broad compiler/compatibility
roadmap. The next highest-value step is an independently specified deterministic
corpus within existing semantics, rather than another API: separate generation
and expected observations from fixture helpers, compare Windows to generated ELF,
exercise metadata relocation and shared/nested/untaken contexts, retain rejected
cases and minimize failures. No Windows XP7 or real-application claim follows.
Medium effort suffices for corpus design/evidence plumbing; Astra High is warranted
only if a reproduced state-analysis or semantic defect requires redesign.
