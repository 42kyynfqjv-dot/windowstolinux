# Roadmap

- M0 foundation and M1 narrow modern-Windows PE32-to-native-ELF slice are in draft review.
- M2 has bounded EAX arithmetic, four flags, forward conditions, direct calls/returns and one-word stack arguments;
  the strict iced adapter is integrated. General stack/data memory is still open.
- M3 now has bounded code plus read-only-data mapping; general executable structure, imports, relocations and indirect calls remain open.
- M4–M7 Windows APIs, advanced execution, instrumentation and desktop behavior remain open.
- M8–M10 x64, representative corpus, optimization and reproducible releases remain open.

Current production evidence:53 authored Windows Server2025/Linux cases. This is
not XP/7 validation or application compatibility; the99% objective is aspirational.
No milestone is complete merely because generated Rust compiles.

## Next native program gate

SUB-508 implements the reviewed [SUB507-DESIGN.md](SUB507-DESIGN.md) contract:
exact PUSH imm32, MOV EAX,[ESP+4] and flags-preserving LEA cleanup over one tagged
stack. Ten new authored programs exercise arguments, shared/nested helpers, joins
and flags. The independent design prototype remains test-only. See
[SUB508-IMPLEMENTATION.md](SUB508-IMPLEMENTATION.md) for implementation evidence
and conditional native-stack assumptions.

Medium SUB-508 review found no production defect. Added a production-path
regression for multiple caller words: only the nearest word is readable, and
both words must be cleaned before entry RET. Existing fixture arithmetic and
intermediate-result branches were inspected against the actual emitted paths.

SUB-509 implements the bounded two-section profile in [SUB509-MAPPING.md](SUB509-MAPPING.md).
The new authored image retains helper exit12; read-only bytes remain unobservable.
Next is medium review of checked file/RVA extents, alignment, permissions, entry
slicing and independent fixture evidence. Then define bounded immutable-data access
as a separate design gate toward a later console-output program. General memory,
imports/APIs, writable data, relocations and application compatibility remain open.
