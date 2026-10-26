# SUB-553 frozen runtime-input composition measurement

Historical SUB-553 measurement. SUB-555 [scalar integration](../scalar/IMPLEMENTATION.md)
now requires guard_join acceptance; squares/helper retain their rejection gates.
The original frozen sources, flags and51expected Windows outcomes are unchanged.

Sources, 51 literal expected outcomes and compiler configuration were committed in
076661c before any compiler/converter evaluation. `frozen.json` hashes the source
bytes and expectations. No production code was changed. All three source programs
remain unchanged after measurement, including rejected programs.

| Program | Structural difference | Windows baseline | Converter outcome |
| --- | --- | --- | --- |
| guard_join | Reordered size/digit guards, second digit first, joined result | 17/17 expected outcomes | Rejected: `input: unsupported instruction at 1014` |
| squares | Sum of squared input digits (42 -> 20; 99 -> 162) | 17/17 expected outcomes | Rejected: `input: unsupported instruction at 104e` |
| helper | Noinline function receiving owned buffer pointer and runtime length | 17/17 expected outcomes | Rejected: `input: complete code extent` |

These are 51 original-only runtime scenarios, zero new translated programs and
zero new Windows/Linux execution pairs. Linux must reproduce the exact converter
rejections on the same hashed Windows PEs. If a future accepted case appears,
the harness requires identical generated Rust across hosts/converter environments
and actual native stdout/stderr/exit agreement. Standalone prototypes do not enter
this measurement. Earlier 13 compiler programs (input with 17 scenarios), 102
authored pairs, 18 launch diagnostics and four older held-out rejections remain
required by CI.

## Concrete barriers from unmodified instruction listings

`guard_join` first uses `CMP EAX,65` rather than copying length to ECX. Later forms
include TEST EAX,EAX, local DWORD loads into ECX, word zero extension from CX/DX,
scaled arithmetic in ECX/EAX, ADD EAX and SUB EAX. The present proof has symbolic
values but its form policy remains register-specific. The first diagnostic is
only the first barrier; adding that one CMP alone would not translate this case.

`squares` first uses ADD EDX,-48 at 104E. Its later IMUL EDX,EDX / IMUL ECX,ECX
requires nonlinear value bounds beyond the current affine domain. It also uses
new register/load/arithmetic forms. Renaming ADD as SUB alone does not solve it.

`helper` places its entry at 1040 after a helper at 1000 and five INT3 alignment
bytes. It uses a backward direct call, caller-owned pointer argument, parameter
loads through that pointer, and two distinct ADD ESP,8 cleanups. The input profile
currently requires entry at the code section start and a completely covered
acyclic instruction graph. Inspection success or ignoring alignment bytes cannot
prove pointer lifetime, call/return ownership or cleanup. No binary padding or
entry bytes were edited to evade these restrictions.

## Highest-value next gate

Astra High: design/test-only validation of a bounded register-parametric scalar IR
for the unchanged `guard_join` program. Normalize exact EAX/ECX/EDX scalar forms
without weakening pointer separation, complete graph coverage, byte initialization,
per-width flags, interval refinement or affine modular arithmetic. Inventory every
required instruction and preserve rejection for other forms. Independent traces
must prove reordered guards and joins for all API classes, and digit range
boundaries for unknown UTF16 units, before production implementation is reviewed.
The acceptance target is the same unchanged program under all 17 frozen vectors,
plus independent unsafe-guard/unknown-register tests. This addresses compiler
register allocation/guard composition; IMUL, helper-pointer calls, arbitrary stack,
CRT, general memory/loops and PE32+ stay separate.

## Reproduction and provenance

On an existing MSVC x86 developer environment:

```
cargo build --locked
python research/input/diversity/measure.py EVIDENCE
```

The evidence directory must exist. Compile configuration is exactly `/nologo /Bv
/O2 /W4 /GS- /Zl /c`; linking uses `/machine:x86 /subsystem:console /nodefaultlib
/entry:entry@0` and kernel32.lib. These are explicitly freestanding custom-entry
programs, not ordinary CRT applications. Versioned compiler listings, full commands,
source hashes, PE hashes and every original observation are written to
`input-diversity.json`, `div_*-compile.txt` and disassembly/import reports. Final
PE hashes may vary between independent builds (linker timestamps); the Linux job
consumes each run's exact Windows artifact without changing it.

On Linux after downloading that same artifact:

```
cargo build --locked
python3 research/input/diversity/measure.py EVIDENCE --compare
```

First measurement run: 40394569155, MSVC 19.51.36260.0, modern Windows Server2025.
The three PE SHA256 values in that run were respectively:

- guard_join: f0e6615d9481089dbd6a2932af109ff23ab8cc14bb8cea02babd0825a2a7e59b
- squares: ef38324067251ad2bdbccb2ddad0ddf242af10057e43714a96e84ba78ab8fe11
- helper: 437fabbc8573c13603a8c32c98744d331cf8a188c10aa6ef33fe6f02edfb8d4f

Final-commit CI artifacts are the authority for that run's exact hashes and
comparison records. A successful rerun never erases a failure; launches have a
30-second limit and no retry, persist case/command/platform/hash before launch,
and retain timeout output if one occurs. Existing historical diagnostics remain.

This does not establish general environment API, ordinary CRT or XP/7 compatibility.
The inherited genuine-procfs/stable-initial-environment/encoding/resource/valid-stack
premises still bound any accepted native input program. Four historical Windows
fixture timeout causes remain unresolved.
