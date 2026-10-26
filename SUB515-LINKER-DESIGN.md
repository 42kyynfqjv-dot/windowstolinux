# SUB-515: linker-image and relocation design

Design/test-only validation, **not production support**. The coordinating request
narrowed SUB-515 to this review gate. Compiler source, flags and PE bytes remain
unchanged. tools/linker_intake.py is not imported by Rust and never emits code.
Its success means structural candidate, not instruction or program acceptance.

## Evidence and primary contracts

compiler/RESULTS.md records two real MSVC builds. Minimal custom-entry output has
three sections, one legacy _write import, relocation/debug directories and DLL
characteristics 0x8540. Ordinary /MD additionally needs writable data, load config,
many APIs and CRT startup. Those are separate work. Proposed first production
intake should reach unsupported PUSH ESI (56) at entry RVA 0x1000, not full conversion.
The observed ESI/save/restore, two-argument helper, ADD ESP flags and instruction
forms still need a separate design and implementation.

Primary sources read 2026-10-26:

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format):
  optional headers/DLL characteristics, sections, imports, debug directory and
  base relocation blocks/types. [Maintained source](https://github.com/MicrosoftDocs/win32/blob/docs/desktop-src/Debug/pe-format.md).
- [Microsoft SDK header mirror](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/winnt.h):
  IMAGE_DEBUG_TYPE_POGO is 13; type 20 carries extended DLL characteristics.
  The Learn table does not document type-13 payload schema. Do not invent it.
- Startup/flags and CRT contracts: compiler/README.md and SUB511-OUTPUT-DESIGN.md.

Independent MIT OR Apache-2.0 implementation from documented contracts and literal
byte expectations. No Wine/loader source copy. Same-project testing, not an external
audit or claimed clean-room work. Extra restrictions are our subset, not assertions
that other PE images are invalid on Windows.

## Structural profile

Preserve the existing authored-image profile separately. Never retry malformed
input under weaker rules. Proposed linker profile:

- PE32 I386 console; executable COFF 0x0102; 0xe0 optional header; 16 directories;
  no COFF symbols/line records/section relocations. Exactly one RX code section
  0x60000020, one R initialized data 0x40000040, one R discardable relocation
  section 0x42000040. Roles derive from permissions and directories, not names or
  ordinals. General writable data is outside scope.
- SectionAlignment 0x1000; FileAlignment 0x200; nonzero preferred base aligned to
  0x10000; file <=4 MiB, image <=1 MiB. Check all arithmetic before narrowing,
  allocation or slicing. Reject empty ranges and exclusive endpoints greater than
  u32::MAX; base+image must not wrap. This endpoint rule is conservative.
- Headers cover the entire bounded table and fit the file; allow 0x400 headers.
  RVAs ascend adjacently after checked page rounding, starting at rounded headers.
  Raw spans may have different order but are aligned, disjoint, outside headers
  and in-file. Nonzero VirtualSize <= aligned SizeOfRawData; no zero-fill tail.
  Allocation/overlap uses rounded max(virtual,raw); access requires full width in
  min(virtual,raw). Raw padding is never program content. Check SizeOfImage,
  SizeOfCode, SizeOfInitializedData, zero uninitialized size and BaseOfCode/Data.
- Entry, complete instructions and targets must be in file-backed executable code.
  Preserve graph/overlap/depth/stack/instruction/terminal limits, reserved loader
  fields and stack/heap reserve/commit checks. Valid storage/no faults/no async
  interference remain execution preconditions.

Only directories 1/import, 5/relocations, 6/debug, 12/IAT may be nonzero; require
all four initially. Reject TLS, load config, exports, resources, exceptions,
bound/delay imports, certificates and all others. Certificates use file offsets,
not RVAs: reject rather than misuse an RVA resolver.

DLL characteristics exactly 0x8540: DYNAMIC_BASE, NX_COMPAT, NO_SEH,
TERMINAL_SERVER_AWARE. Dynamic base requires the provenance contract below, not
preferred-base loading. NX agrees with no data execution, NO_SEH with no exception
machinery/faults; no Terminal Server environment/API is observable in this subset.
These bits do not establish equivalent Linux security policy. CFG, AppContainer,
integrity enforcement and all other bits reject until separately specified.

## Import/debug ownership

Use one image-scoped checked RVA resolver, independent of section ordinal. Exactly
one 20-byte import descriptor plus zero terminator, zero timestamp/forwarder,
distinct 4-aligned ILT/IAT pairs (one matching name RVA plus zero), no ordinals/bound
addresses, exact msvcrt.dll / hint-zero _write, exact eight-byte IAT directory.
Complete names/tables must fit the R data section.

Reserve disjoint descriptor/terminator, ILT/terminator, IAT/terminator, DLL name,
hint/name, debug directory/payload and relocation directory spans. **IAT is mutable
loader-owned state despite R permissions.** Exclude all metadata from immutable
reads/output, including crossing ranges that start outside. Only the exact imported
call may reference the first IAT slot. No reading numeric IAT values/terminators.
Other R bytes are eligible after full-width and permitted-byte checks.

Debug: exactly one 4-aligned 28-byte entry; zero Characteristics/major/minor;
Type 13 POGO; nonzero payload <=4096 bytes. Payload RVA and file pointer must
resolve to identical complete R-data bytes. Reject file-only/unmapped payloads,
aliases and every other kind/version. Timestamps do not affect generated behavior.
The opaque payload supplies no trusted code ranges, symbols or startup actions;
neither it nor its directory may affect execution, values or output. This exclusion
and instruction whitelist bound the assumption that this known packaging is debug
metadata only. No general assertion about arbitrary debug kinds: type 20 must not
be silently ignored. Undocumented type-13 payload semantics remain a review limit.

## Relocation records and typed provenance

Directory wholly in R discardable section, 4-aligned, nonzero, <=4096 bytes. Each
block has eight-byte header, size >=12, multiple of four, fits in the directory;
blocks consume it exactly, with no guessed terminator beyond its extent. Pages
are 4-KiB-aligned, strictly increasing, inside image; at most 128 live records.

Permit type 3 HIGHLOW plus at most one last zero WORD/type 0 ABSOLUTE padding per
block. Require a live record per block. Reject HIGH/LOW/HIGHADJ/DIR64/unknown or
machine-specific types, repeated pages and malformed sizes/padding. ABSOLUTE is
no patch. HIGHLOW site = checked page RVA + 12-bit offset. Complete four-byte field
must be in file-backed code; unaligned fields allowed. Reject duplicate/overlapping
sites across all blocks, header/metadata/IAT/data/gap/tail/self patches. Relocated
data/pointer tables are separate scope.

Read the original little-endian word. Require a nonwrapping preferred-base VA into
eligible R data or the exact IAT slot. Normalize to image-owned RVA. This is only
candidate provenance: a record/address-looking word does not identify its use.

Before emission, checked decoding supplies instruction start/end and exact four-byte
absolute operand offsets. Require a bijection between every live record and supported
fields in the reachable graph, including both branch successors. Reject unconsumed
records even in unreachable code, opcode/operand/instruction straddles, missing
records on pointer uses and relocated fields consumed as integers. Never infer
pointer identity from value equality. Unsupported entry code can reject before this
join; structural success must not authorize emission.

Future values: ImagePointer(RVA) and ImportSlot(RVA), scoped to one image. Preserve
tags through allowed register/stack copies and joins. Reject pointer arithmetic,
CMP/XOR/integer return/output, forged integer-to-pointer conversion, unknown tags
and unsupported consumption. Minimal MSVC pushes its relocated buffer using imm32.
**Existing u32 stack data cannot preserve provenance: typed value/stack propagation
is prerequisite to accepting the compiled program.** Return addresses stay opaque
and protected. No general memory or image introspection.

## Preferred/rebased image assumptions

HIGHLOW adds actual_base - preferred_base modulo 2^32. For nonzero 64-KiB-aligned
actual base and a complete nonwrapping image, admitted internal pointers satisfy:

`(preferred_base + RVA + delta) mod 2^32 == actual_base + RVA`.

Retained RVA selects identical bytes at each such base. Relative control flow is
unchanged; IAT resolution is separate and numeric function addresses never escape.
ELF uses native data/support, need not map at the Windows base, and needs no PE
loader or address decoder at runtime. The argument requires complete record binding
and preserved tags through every allowed path. Preferred-base evaluation alone
cannot establish it. General wrapping pointers/rebasing other image types reject.

Arithmetic tests cover zero/positive/negative deltas and upper limits, not actual
Windows rebasing. Current Windows baseline measures stdout/stderr/exit, **not module
load base**. Before broad ASLR-equivalence claims, record actual bases through a
documented external process/module observer without altering PE bytes, flags or
security settings. Multiple bases are evidence, not proof of all bases. Lack of
observed rebasing must remain an explicit gap.

## Evidence and implementation gates

Run `python3 -m unittest discover -s tools -p test_linker_intake.py -v`: 14 distinct
test functions, including all 2560 truncations of one independently laid-out image,
literal upward/downward relocation results, metadata endpoints/exclusions, aliases,
dual debug addresses, malformed imports/blocks/types, duplicate pages/patches and
typed field coverage. Truncations are not independent semantic programs. No old
fixture generator/production code is imported; bytes are not claimed to form a
Windows-loadable app. Model bind takes test-supplied field descriptions, so tests
the join rule, not decoder correctness or pointer flow.

Actual Windows compiler measurement additionally records model mapping/relocation
reports and dumpbin /relocations. No PE patching or decoder bypass; no extra Linux
comparison for the rejected compiler programs. Reports only, no binary redistribution.

Observed CI [40269206888](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40269206888)
at 46e8af9c3390b91127db5d274bdf6bce24e76545: all four jobs passed. MSVC
19.51.36260.0 / LINK 14.51.36260.0, Windows Server 2025 NT10.0.26100.0. Independent
model and dumpbin agree on one page-0x1000 relocation block of size 12, records
0x3004 and 0x300c (two HIGHLOWs, no padding). Original field at RVA 0x1004 is
0x402008, the PUSH buffer operand; field at RVA 0x100c is 0x402000, the FF15 IAT
operand. These correspond to normalized RVAs 0x2008 and 0x2000. This observed
disassembly correspondence is not a production decoder-binding proof.

Debug type 13 has payload RVA 0x2044, file offset 0x644, size 0xbc, ending exactly
at import descriptor RVA 0x2100. IAT occupies [0x2000,0x2008); Hello occupies
[0x2008,0x200d). These adjacent ranges are disjoint. The model accepts the unchanged
image structurally; production still rejects directory 5. Ordinary CRT output
still rejects its four-section layout. Both Windows originals emit Hello, empty
stderr, exit 0; neither produces a translated ELF. The 102 existing comparisons,
46 root tests, 43 evaluation functions (27 inherited) and 14 new prototype tests
passed. [Text/JSON artifact](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40269206888/artifacts/12627179619).
This is a historical measured commit; the PR/Linear checkpoint records final-head CI.

After medium review, bounded production integration requires:

1. Rust image-scoped range/role/ownership types; exact policies/diagnostics and
   preserved authored profile. Independent production-path tests for last-byte/
   one-too-far accesses, overflow before allocation, cross-alias, unsupported dirs,
   duplicate/missing/wrong-field relocations and deterministic failures.
2. Parsed candidates cannot emit until binding and typed pointer flow are proven.
   Unchanged minimal MSVC output must reach the actual unsupported PUSH ESI error.
   If typed integration is deferred, linker-profile emission stays unconditionally
   gated off, even for crafted simpler programs. Intake is not conversion.
3. Final-commit CI rebuilds both unchanged C configurations, records MSVC/OS and
   verifies Hello/empty stderr/exit 0 originals and exact converter outcomes;
   compare toolchain/model relocation facts. Preserve 102 Windows/generated Linux
   pairs, 46 root tests, 43 evaluation functions (27 inherited), corpus negatives
   and deterministic source. Structural acceptance is not an extra native pair.
4. Separate bounded ABI/instruction milestone must translate that same unchanged
   minimal PE to Rust, compile Linux ELF and compare actual stdout/stderr/exit to
   Windows. Include independent pointer-flow/negative relocation cases, successful
   regular-file CRT/valid-stack assumptions and actual-base evidence limits. No
   ordinary /MD, general loader/ASLR or XP/7 compatibility claim.

No new resource/user decision is needed. Medium review should challenge opaque
POGO handling, metadata ownership, actual-base evidence and typed stack prerequisites
before another Astra High production integration turn.


## Medium contract review

Range/role checks, duplicate/overlap rejection and metadata exclusions were reviewed
against the observed MSVC fields. No production change was justified. The model
still cannot prove instruction boundaries or pointer flow; its test-supplied bind
fields are not that proof. Pointer identity belongs to the Candidate resolver;
production must use image-owned types and cannot trust caller-supplied RVA tags.
Actual load bases remain unmeasured. Opaque POGO handling is conditional on excluding
all metadata consumption and all unsupported startup directories, not a general
claim about debug records. These conditions remain mandatory production gates.

The relocation listing comparison is now enforced against the same unmodified PE
in Windows CI (rather than only manually inspecting two reports). One added test
checks independently specified dumpbin records and missing/unrecognized listings:
15 prototype functions now, with the original 14 retained.

Timeout investigation: run40269378607 first Windows job121398673975 completed case13
then timed out waiting15 seconds for case14; retry job121398912221 passed case14
(stdout433134, empty stderr, exit0) and all other cases. Logs supply no process
trace, actual load address, Windows event or verified cause. A successful retry
cannot establish that this reliability issue is fixed. Corpus launch/timeout logs
now flush case ID, platform and exact PE SHA256; the15-second limit and failure
remain unchanged. Final CI provides another ordinary execution attempt, with no
stress test, security change or acceptance relaxation. If it recurs, retain the
exact failing image identity and collect documented process/module diagnostics
before guessing whether scheduling, loading or program behavior caused the wait.

Ready for a bounded Astra High production-intake implementation after this review:
strict parsed-candidate types and independent Rust loader tests, with linker-profile
emission unconditionally blocked pending separately reviewed typed pointer flow.
Require unchanged compiler intake to reach unsupported PUSH ESI, preserve all prior
comparisons, and keep actual-base observation separate from arithmetic reasoning.
