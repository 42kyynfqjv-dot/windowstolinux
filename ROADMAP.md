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

Next is focused medium review of owner/return integrity, caller cleanup, shared
and nested contexts, production-versus-prototype independence and exact CI results.
Resolve any confirmed gap before widening support. Then select a separately scoped
program-level gate from the original roadmap; this slice does not establish a
general ABI or permit arbitrary compiler-generated code.
This advances original M2 stack-state prerequisites more than another arithmetic
opcode. Native stack storage and exception assumptions remain explicit. General
memory, PE sections/imports and a small independently implemented API contract are
later separate gates toward an observable console application. General ABI support
must not be inferred from a single argument-passing convention.
