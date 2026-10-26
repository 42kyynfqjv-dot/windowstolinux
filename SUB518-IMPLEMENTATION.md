# SUB-518 bounded compiler-program translation

The exact linker profile now passes through a private typed validator before Rust
emission. Structural validity alone remains insufficient. All HIGHLOW sites must
match complete reachable 68 immediate or FF15 displacement fields, including both
branch successors and call continuations; unmatched and overlapping fields reject.
The existing authored-image profile and its decoder policy are unchanged.

`src/linker/translate.rs` uses an exact byte whitelist plus iced length/validity
checking for the observed SUB517 forms. The linker profile supports JNZ only;
existing authored profiles retain their previous branch families. Instructions
are emitted as fixed Rust match arms; no PE bytes or decoder dependency are shipped.
`state.rs` shares checked typed stack/register transitions between validation and
native execution. Scalar/Pointer/opaque Unknown remain distinct. ImportSlot is
represented only by a validated Write operation, never as guest register data.

Image ownership is lexical: private Op/Value/State constructors and graphs exist
only inside one Candidate translation, with no API for importing state from another
image. Pointer values are immutable RVAs resolved solely against that Candidate.
Generated code owns only its validated literal output buffers. A numeric VA cannot
be used as a pointer. Copies preserve tags; pointer arithmetic/comparison/EAX returns
reject. Unknown incoming ESI has a distinct identity from unknown EAX. Call frames
snapshot ESI and RET verifies restoration; it does not restore automatically.

Every conditional successor is validated in its own complete state context; states
are never merged or stripped of provenance to accept a join. In addition to existing
1024 decoded/executed instruction, 128 extra word and 32 call limits, validation
caps total explored transitions at4096. This may reject otherwise valid programs.
Both return epilogues require balanced ownership and original ESI. ADD ESP,20 drops
exactly five caller Data words, rejecting saved/return words, and makes tracked
flags unknown until overwritten. Only caller Data under the immediate callee Return
can supply the first two arguments. Arithmetic uses the existing independently
verified CF/ZF/SF/OF implementation. Runtime output retains full-write regular-file
requirements and exit125 on unsupported output environment/failure.

The prior unconditional emission barrier is replaced by complete structural,
decoder-field, all-context ownership/type/output and terminal validation. A failure
at any stage preserves existing output files. The old scalar emitter is never used
for a linker Candidate. No general register/memory/CRT or extra API support.

## Evidence gates

- 48 root Rust test functions (two new ownership/typed-return tests), plus existing
  evaluation suite (43 functions,27 inherited) and model suites.
- `tools/check_compiler_subset.py`: six deterministic native executions of authored
  literal compiler-shaped code, including both error epilogues and signed immediate
  boundaries;20 independent malformed/unsupported mutations preserve output.
- All2612 former linker CLI rejection cases remain rejected; only their semantic
  diagnostics change where the old unconditional barrier was reached.
- Existing102 Windows/Linux comparisons remain required, separately counted.
- `compiler/measure.py` uses the unchanged source and single documented MSVC build
  configuration, executes original Windows PE, converts twice and checks deterministic
  Rust. It records exact PE SHA and compiler flags and verifies PE bytes unchanged.
  The `compiler-native-linux` CI job downloads generated source/report, compiles with
  rustc -D warnings and requires Hello/empty stderr/exit0 against the Windows report.
  It never patches the PE or searches compilation flags. Ordinary CRT must reject.

Successful CI is required before claiming the compiler comparison passed. Reports
and source are artifacts; official compiler/CRT binaries are not distributed. The
separate debug-event load-base observation remains limited to that instrumented
launch; ordinary baseline base and actual relocated operand bytes are unmeasured.
No all-base/XP7/general-application claim. Valid flat stack/no-fault/no-asynchronous-
mutation and legacy CRT output assumptions from SUB517/SUB512 remain conditional.
Historical unexplained corpus timeout is not declared solved.

Next medium review should focus on decoded relocation coverage, per-Candidate
ownership isolation, hypothetical branch states, saved ESI and cleanup boundaries,
generated transition equivalence, and provenance of the actual CI compiler artifact.

## Medium production/provenance review

The first CI checkpoint converted PE on Windows and compiled its Rust on Linux;
it did not establish independent Linux conversion of that PE. The revised gate
transfers only the authored freestanding PE, its generated Rust and reports.
Linux verifies PE SHA256, authored C source SHA256 and Windows-generated Rust SHA256,
then runs the Linux converter twice on that exact PE. Both generated sources must
match the recorded Windows Rust digest before native compilation/execution. PE bytes
must remain unchanged. Full stdout/stderr/exit are checked against the original
Windows report. No CRT/compiler binary is transferred. This strengthens provenance
without changing compiler flags, input bytes or production semantics.

Reviewed private per-Candidate state isolation, complete relocation binding and
separate branch/call contexts; no production semantic defect reproduced. Added a
21st production mutation: replace the success epilogue POP ESI with supported PUSH
ESI. This must reject through ESI/terminal ownership validation, rather than merely
an unsupported-opcode check. Root counts remain48; typed models remain16 functions
and24 parameter variations of one layout. The six authored native cases remain
separate from the one real compiler-program Windows/Linux comparison.

Next bounded validation should compile a small fixed set of independently authored
C source variations with the same documented toolchain/options, without PE edits
or flag searches. Record every acceptance/rejection, independent expected outputs
and first unsupported feature. Require accepted variants to pass this same hashed
PE Windows/Linux conversion/execution chain. Rejection is a measured result, not
permission to broaden semantics. Medium effort is sufficient for that measurement;
any new semantic implementation requires a concrete Astra High handoff.

The first strengthened run40274654723 failed at the source-hash comparison because
Windows checked out CRLF C source. Rust include_str source also needs identical
checkout bytes for deterministic cross-host emission. .gitattributes now requires
LF for C and Rust source; hashes still compare exact bytes without normalization.
This changes checkout policy, not compiler options or compiled PE bytes after build.
The failed run is retained as provenance evidence, not retried as unexplained flakiness.
