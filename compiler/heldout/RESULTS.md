# SUB-527 held-out results

Source/configuration/input/expectation freeze cf042295303dccedb8506564f1e466ef9d353acd
preceded measurement implementation8eb5f5991d41bd23eb4f544e64afc4f8ff9b81e4.
First complete run40288844509, compiler-measurement-reports artifact12634409438.
Windows Server2025 NT10.0.26100.0, available MSVC19.51.36260.0 and LINK14.51.36260.0
for x86/x64; configuration frozen, toolchain version observed rather than pinned.
Seven original C sources, eight build configurations. No source/flag/PE alteration.
See cases.json and PLAN.md for exact expectations and commands; results.json retains
full PE/source hashes, flags, section metadata and actual diagnostics for this run.
PE timestamps change hashes across rebuilds; each run checks identity across hosts.

| Case | Original stdout / stderr / exit | Conversion on Windows AND Linux |
| --- | --- | --- |
| runtime argc/argv A B | Args / empty /68 | reject: only code with optional read-only data is supported |
| volatile runtime-bound loop | empty / empty /10 | reject: linker COFF profile |
| volatile global array reads | empty / empty /9 | reject: linker COFF profile |
| writable local byte buffer | empty / empty /132 | reject: linker COFF profile |
| local structure/frame | empty / empty /12 | reject: linker COFF profile |
| ordinary CRT main | CRT / empty /0 | reject: only code with optional read-only data is supported |
| binary file roundtrip | Data / empty /0; held.txt=Data | reject: only code with optional read-only data is supported |
| x64 PE32+ CRT counterpart | CRT / empty /0 | reject: only x86 PE32 is supported |

All eight originals met literal expectations before conversion. All eight
rejections preserve output and match independently on Linux for the same hashed
PE. The Linux checker repeats conversion twice. Zero new accepted/translated pairs. This is eight
configurations, not eight distinct source programs or a compatibility percentage.
No reproduced converter defect, tool failure, baseline timeout or hidden retry.
Existing eight accepted compiler programs,102 authored comparisons and18 launch
samples remain mandatory. Historical unrelated timeout causes are still unresolved.

## What the first diagnostics do and do not establish

The custom COFF diagnostic is a profile restriction, not malformed COFF. Source
inspection finds src/linker.rs requires EXACTLY three sections in that combined
check; all four controls have machine14C, optional-header sizeE0 and COFF102.
Loop/array have four sections (.text/.rdata/writable .data/.reloc); buffer/structure
have two (.text/.rdata) and no import/relocation directories. They are well-formed
Windows programs outside the accepted three-section/mandatory-output-import model.
Ordinary CRT images use four sections, DLL characteristics8140, load configuration
and multiple VCRUNTIME/UCRT imports. x64 magic20B has machine8664 and .pdata/unwind.
The converter stops at these barriers; it did NOT validate subsequent instructions.

Independent dumpbin inventory of authored custom-entry code exposes later needs:
- Loop: XOR ECX, memory CMP at403000, JBE, NOP, INC ECX and backward JB.
- Array: MOV ECX,[403004], A1 reads of writable .data and ADD ECX,EAX.
- Buffer: PUSH/POP ECX, byte local stores, MOVZX and INC AL.
- Structure: SUB ESP,8, local word stores/reads and ADD EAX,[ESP].
These are disassembly findings, not claims of decoder or execution support. Do not
relax only section counts and call these cases translated: writable permissions,
relocation pointer provenance, imports/startup and actual instruction semantics
remain separate acceptance gates. Volatile/global state has explicit valid-memory,
no-asynchronous-interference assumptions; no cross-environment equivalence claimed.

## Single next architecture gate

Prioritize an Astra High design/test-only contract for a normalized, permissioned
PE32 image intake, separating structural validity from the current exact-section/
mandatory-_write fingerprint. This shared first barrier blocks all seven x86
configurations before instruction measurement. Bound design to measured two-/four-
section layouts, optional absent import/relocation directories, metadata exclusions
and typed provenance. Writable .data may be modeled as metadata but must retain an
emission barrier until writable-memory semantics are separately verified. No generic
CRT, TLS, writable-memory execution, loop or PE32+ support is implied by intake.

Acceptance: primary PE contracts; independent malformed/overflow/overlap/permission/
metadata tests; explicit rejection of startup effects outside scope; preserve strict
old profiles and all prior evidence; unchanged held-out PEs either remain explicitly
blocked at a truthful execution prerequisite or are proven end-to-end in a later
implementation. Plan production stages only after medium design review. Merely
moving a rejection later is diagnostic progress, not compatibility success.

Loop termination/resource proof, byte-addressed local/global memory, broader x86
register/flag effects and ordinary CRT are still major later gates. PE32+ adds a
separate64-bit state/address/calling-convention/unwind scope and should not expand
this PE32 design. No evidence yet ranks a particular ordinary application workload
or supports99%/XP7/general-app claims. No paid resources, merge or release.
