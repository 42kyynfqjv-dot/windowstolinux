# Roadmap

- M0 foundation and M1 narrow modern-Windows PE32-to-native-ELF slice are in draft review.
- M2 has bounded EAX arithmetic, four flags, forward conditions, direct calls/returns and one-word stack arguments;
  the strict iced adapter is integrated. General stack/data memory is still open.
- M3 executable structure, imports, relocations and indirect calls remain open.
- M4–M7 Windows APIs, advanced execution, instrumentation and desktop behavior remain open.
- M8–M10 x64, representative corpus, optimization and reproducible releases remain open.

Current production evidence:52 authored Windows Server2025/Linux cases. This is
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

Next: SUB-509 bounded code plus read-only-data PE mapping, using Astra High for
range/address design and implementation, then medium review. Specify the exact
two-section profile from primary PE/COFF documentation, preserve the one-section
baseline, and reject ambiguous/overlapping/truncated mappings, non-file-backed
entry and entry in data. Keep code decoding confined to its executable extent.
Add a genuine Windows/Linux two-section helper case and independent range tables.
This supplies an M3 prerequisite for later immutable-data access and a separately
designed output API; it adds no data reads or console output by itself. Imports,
relocations, writable/general memory, general ABI and application compatibility
remain open. See the existing Linear SUB-509 issue for measurable acceptance gates.
