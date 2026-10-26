# SUB-502: bounded comparison and signed branches

Primary instruction contract reviewed: Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2, order 325383-081US (September 2023), entries CMP (3-179/180), Jcc (3-547 onward), ADD, XOR and MOV. Source: https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf . The implementation and fixtures are independently authored; no external implementation code was copied.

Only CMP EAX,imm32 (3D id), short JL (7C cb) and short JGE (7D cb) are added. CMP computes flags from EAX minus the unsigned 32-bit immediate bit pattern, without changing EAX. CF means unsigned borrow; ZF means the result is zero; SF is result bit 31; OF means the signed mathematical difference is outside the i32 range. JL tests SF != OF; JGE tests SF == OF. The immediate is already the operand width: no narrower-immediate sign extension occurs in this encoding.

ADD updates CF/ZF/SF/OF from the 32-bit sum, with OF indicating signed overflow. XOR EAX,EAX clears CF/SF/OF and sets ZF. MOV preserves all modeled flags. AF and PF remain unmodeled and have no supported consumers. There are no new memory operations, APIs, register forms, prefixes, near branches, backward branches, JLE/JG or other conditions.

Both successors are decoded and must respect the existing instruction-boundary and executable-byte rules. Entry EAX and flags start unknown; the deterministic path must initialize each before use. The 1024 decoded/executed instruction bounds and return range 0–255 are unchanged.

The validator and emitted standalone Rust use the same independently authored Flags helper source. This prevents validator/emitter drift; independent tests use widened signed/unsigned arithmetic rather than the bit formulas used by that helper. The 49-pair boundary matrix covers 0, 1, 2, INT_MAX, INT_MIN, -2 and -1. Authored executable cases additionally test overflow predicates, CMP preserving EAX, MOV preserving signed flags, XOR resetting signed flags, and existing CF/ZF consumers after CMP. Existing deterministic-generation and rejection checks remain in CI.

The complete current matrix has 32 Windows/ELF cases. Windows Server 2025 evidence is distinct from the unvalidated XP–7 target. Runtime code contains statically decoded Rust operations and fixed successors; the generated binary has no Wine or original-instruction decoder dependency.
