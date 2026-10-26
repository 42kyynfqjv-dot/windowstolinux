# SUB-535 initialized image reads

Implements the reviewed SUB534-IMAGE-READ-DESIGN.md conditional domain. The owned PE
envelope selects a private data-read proof when importless input has writable sections.
It validates metadata closure, only relocation/debug directories, one initialized RW
section, no zero-fill, exact full code extent/entry and complete HIGHLOW operand binding.
Every other form, including branches/calls/stores, rejects. Inspection reports never
confer emission authority. Existing strict non-data profiles retain their checks.

Only 8B0D va32, A1 va32, 03C8, 03C1 and terminal C3 are decoded, with iced length checks.
Targets must be complete initialized four-byte words in this same owned image's RW
section, outside all metadata. The established relocation parser rejects non-code
sites, duplicates/overlap and unsupported records. Every remaining code relocation
must bind a read field. Scalar values cannot become pointers. The entire program
proves no writes or escapes before a private Proven wrapper emits source.

read_state.rs supplies identical checked scalar transitions to proof and emitted Rust.
ADD wraps32 bits and computes CF/ZF/SF/OF; reads preserve flags. Unknown operands,
exit outside0..255, missing/early return and instruction limits reject. Proven read
values become native constants under the documented no-external-mutation/no-fault
normal-loader/valid-stack domain. This does not preserve excluded hardware volatile
access events/timing. Generated ELF has no Wine, decoder or AI runtime.

Independent production harness: seven deterministic native cases (array9, wrap0,
signed overflow0, max255, different-image6, one-read2, unaligned1),62 CLI rejections.
The unbound-loader-write case deliberately uses a high preferred base and a larger
initialized section so an extra relocation over ADD bytes passes structural target
checks and reaches exact operand accounting. Another case relocates an unused data
word and reaches the code-site restriction. Unknown ECX, unsupported effects/prefixes,
truncations, partial ranges, aliases, startup directories and preserved output files
are checked. One new Rust test function checks independent flag boundary tables and
unknown/return gates;77 root functions total. Nine prior model functions are inherited.

CI changes only held_array acceptance. The frozen source/options and compiler-produced
PE remain untouched; Windows/Linux independently convert the same hashed artifact to
identical Rust and compare actual stdout/stderr/exit9. Ten earlier compiler comparisons,
102 authored pairs and18 launch diagnostics remain; five other held-out programs reject.
Model artifact checks label accepted array execution as a separate pipeline check.

Actual Windows array load base remains unobserved; model base arithmetic does not prove
multiple observed rebases. Windows Server2025 evidence does not establish XP/7 or general
applications. Loops/general writes/heap/CRT/PE32+ remain unsupported. Three historical
Windows timeout causes remain unresolved. Next medium review: private selection/proof
isolation, exact operand accounting and full-width bounds, shared transitions, fixture
provenance and rejection evidence. No merge/release.
