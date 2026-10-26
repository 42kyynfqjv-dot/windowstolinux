# SUB-559 private helper integration

The input decoder now starts at the validated actual entry, discovers internal
CALL targets and continuations, and accounts for every byte. Uncovered bytes must
be0xCC; targeting them attempts decoding and rejects. Bound relocations must still
match every recorded pointer field. An independent structural traversal tracks
call targets/returns and explores both branch edges, rejecting cycles, missing
or overlapping targets and state/depth exhaustion. Calls may point backward;
conditional branches remain forward-only.

The state proof adds protected internal-return tags and immutable frame snapshots
of stack, saved ESI, argument count and borrow authority. Exact argument reads
require the call-entry stack shape and valid argument offsets. Caller arguments
are never callee cleanup authority: cleanup can remove only argument words above
the current frame floor. Local cleanup requires the root allocation's exact stack
shape. Internal RET checks the original stack and ESI, pops its protected tag and
continues at the recorded return; only entry RET checks portable process exit.
Volatile registers and flags are conservatively unknown after internal return.

This profile has exactly one allocation lifetime and one acquisition, no admitted
memory writes or later external effects, and no pointer arithmetic. Its private
Buffer tag therefore denotes that unique allocation; it cannot be forged by a
scalar or another file. A borrow requires passed Buffer authority, live root local
tags and initialized bytes. Root cleanup clears initialization, and reallocation
is forbidden. Distinct arbitrary owners, writable borrows and allocation reuse
are excluded rather than modeled with synthetic addresses. A future extension
must introduce explicit owner/generation identities before adding those features.
WORD reads validate both bytes and bind the physical offset on every path; shared
PCs require identical bindings. API result1 carries second-unit zero, while result2
has two unknown UTF16 units. The EDX capability is captured before a WORD load
replaces EDX with its scalar. No scalar-to-capability conversion exists.

Native Rust uses direct block functions and direct internal calls. A bounded,
proof-validated stack vector carries numeric scalar arguments and internal offsets;
zero represents the unique buffer offset only where the private proof establishes
that type. It never acts as an unchecked host pointer. Internal calls retain the
runtime argument values, source-before-write behavior and call continuation.
Protected tags exist only during analysis. No instruction interpreter/AI fallback
or hand-written decimal answer replaces decoded application instructions.

92 root functions include two new helper tests: exact decoded call/read forms,
8 native input expectations and negative call/argument/read/cleanup/cycle paths;
plus isolated protected argument and pointer/scalar boundaries. Nested calls without
explicit arguments and a repeated call without valid arguments reject. General
nested/shared behavior is not claimed solely from the model: every context must
pass complete production proof. Existing model8tests are inherited evidence.
Limits remain4internal frames,16stack words,128instructions,512code bytes,4096
structural/symbolic states, and scalar63occurrences/depth12.

The frozen source/flags/PE remain unmodified. CI now requires all3variants to have
17 Windows/ELF matches each, identical Rust across hosts/converter environments,
105 extra native inputs and9 separate unsafe image rejections each. The helper
inventory checker is provenance evidence; actual execution comparison is separate.
Local experiments used copied reports and are not final cross-host evidence.

Medium review must audit frame-floor cleanup, unique-owner assumptions, full WORD
and terminator facts, borrowed argument ranges, address-before-destination capture,
structural call/padding proof, native stack simulation and final artifact hashes.
OrdinaryCRT/general pointers/writes/recursion and broad ABI support remain excluded.
Procfs/stable environment, no-fault stack and unobserved actual load-base premises
persist. Four historical timeout causes remain unexplained. Modern Windows CI is
not XP/7 validation. Review gates precede standing-authorized merge.
