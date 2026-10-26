# SUB-514 measured compiler gaps

Observed Actions run40267760683, commit14b66c76e794458bc0c31586482b31653b807e5b:
MSVC19.51.36260.0, LINK/dumpbin14.51.36260.0, Windows Server2025 NT10.0.26100.0.
Exact structured observations are in observed-report.json; full logs/reports are in
the compiler-measurement-reports Actions artifact. Toolchain is version-recorded,
not immutable-pinned. PE timestamps cause binary hashes to differ across rebuilds;
the requirement here is reproducible source/settings/observations, not identical
PE hashes. No attempt was made to alter compiler/linker output or hunt for flags
that make conversion pass. An initial recipe failed symbol decoration; corrected
/ENTRY:entry@0 and original _write declaration resolved it without code patching.

| Build | Windows stdout / stderr / exit | Converter result |
| --- | --- | --- |
| Minimal custom-entry legacy import | Hello / empty /0 | rejected: unsupported nonempty PE data directory5 |
| Ordinary /MD main/CRT startup | Hello / empty /0 | rejected: only code with optional read-only data is supported |

Neither produced a translated Linux ELF. These are two Windows-only observations,
not two additional native equivalence pairs; the102 existing comparisons remain.
The current converter is built on Windows for this measurement; its rejection
paths are the same Rust source, not a separate emulation implementation.

## Minimal compiler image: blockers beyond the first rejection

- .text/.rdata/.reloc sections, headers0x400 rather than authored0x200.
  Import descriptor is atRVA0x2100, IAT0x2000 and lookup0x2128, all inside .rdata.
  Our profile instead requires a separate loader-owned third import section.
- Base relocations directoryRVA0x3000 size12 and debug directory0x2010 size28.
  DLL characteristics0x8540 include dynamic base/NX/no-SEH/terminal-server-aware.
  Clearing these without modeling them would hide loader/address assumptions.
- Exact existing msvcrt.dll!_write import; no new external API is needed for this
  minimal image. Ordinary /MD imports UCRT/VCRUNTIME/kernel32 functions instead.
- Reachable instructions outside current subset: PUSH ESI(56), PUSH imm8(6A),
  MOV ESI,EAX(8BF0), ADD ESP,20(83C414), CMP EAX,imm8(83F80C), CMP ESI,imm8
  (83FE05), XOR EAX,EAX alternate encoding33C0, POP ESI(5E), and helper
  ADD EAX,[ESP+8](03442408). Current MOV EAX,[ESP+4], CALL rel32/FF15,
  JNE short and RET forms also occur. Padding INT3s are not claimed reachable.
- Compiler reorders pure helper computation after _write and keeps the return in
  callee-saved ESI. Correct conversion needs explicit register/ABI state, saved
  register tags, two argument locations and flags-changing ADD ESP cleanup;
  existing flags-preserving LEA cleanup is not a substitute.

The tiny helper has real machine code at0x401040; entry at0x401000. Observed text
virtual size0x49. Raw disassembly is limited to the independently authored minimal
program. No linked CRT startup disassembly or executable is committed.

## Ordinary CRT image: deliberately separate scope

Four sections including writable .data, DLLchars0x8140, directories1/5/6/10/12.
Imports include KERNEL32, VCRUNTIME140 and UCRT stdio/runtime/math/locale/heap API
sets. Load configuration, exception handlers, process initialization and exit APIs
are substantially broader than one output function. Ordinary main is not equivalent
to selecting a custom entry and omitting CRT. No ordinary application support claim.

## Prioritized next engineering gate

First define and implement a bounded **linker-produced image intake profile** for
this unchanged minimal image: checked generic section mapping, directory-bound
import ranges independent of section position, exactly specified debug handling,
DLL characteristics and HIGHLOW relocation/address provenance. Fail closed for
TLS/load-config/unrelated directories and import aliases. Reproduce the same image
with existing CI; add independent adversarial mappings and relocation tests.
Parsing/intake success must remain distinct from translation: unsupported ESI/stack
forms must still reject. This architecture/contract work merits Astra High.

Then separately design the observed register-save/two-word-argument/ESP cleanup
semantics and exact encodings needed for the unchanged minimal C program, with
Windows/Linux end-to-end output/exit as the acceptance gate. Do not add random
opcodes or broaden the CRT-linked build simultaneously. No new resources or user
decision is required for this next authorized engineering step; model handoff only.
