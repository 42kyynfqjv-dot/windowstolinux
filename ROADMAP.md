# Roadmap

- M0 foundation and M1 narrow modern-Windows PE32-to-native-ELF slice are in draft review.
- M2 has bounded EAX arithmetic, four flags, forward conditions and direct calls/returns;
  the strict iced adapter is integrated. General stack/data memory is still open.
- M3 executable structure, imports, relocations and indirect calls remain open.
- M4–M7 Windows APIs, advanced execution, instrumentation and desktop behavior remain open.
- M8–M10 x64, representative corpus, optimization and reproducible releases remain open.

Current production evidence:42 authored Windows Server2025/Linux cases. This is
not XP/7 validation or application compatibility; the99% objective is aspirational.
No milestone is complete merely because generated Rust compiles.

## Next native program gate

SUB-507 defines bounded stack arguments so an authored helper can consume caller
supplied data. [SUB507-DESIGN.md](SUB507-DESIGN.md) proposes exact PUSH imm32,
MOV EAX,[ESP+4] and flags-preserving LEA cleanup over one tagged stack containing
data and return words. The five test-only prototype functions do not add production
support. Review the address/ownership/flags contract at medium, then use Astra High
for the bounded validator/emitter integration and genuine Windows/Linux evidence.

This advances original M2 stack-state prerequisites more than another arithmetic
opcode. Native stack storage and exception assumptions remain explicit. General
memory, PE sections/imports and a small independently implemented API contract are
later separate gates toward an observable console application. General ABI support
must not be inferred from a single argument-passing convention.
