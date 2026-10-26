# SUB-509 bounded code and read-only-data profile

Primary contract: Microsoft PE/COFF specification, read 2026-10-26:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
Sections consulted: optional header standard/Windows fields, section table, section
flags and section data. It specifies ascending adjacent aligned section RVAs,
aligned raw sizes/pointers, VirtualSize versus raw padding/zero fill, and the
separate execute/read/write flags. The restrictions below are this converter's
accepted subset; they do not describe every image Windows can load.

## Mapping decision

Preserve the existing one-section code profile. Additionally accept exactly two
section-table entries in order: code with characteristics60000020, then initialized
read-only data with40000040. Names do not grant permissions. All section relocation
and line-number pointers/counts must be zero (also enforced for one-section files).
All existing PE directory, DLL, machine, subsystem and alignment checks remain.
No writable/discardable/shared section or alternative permission combination.

For each section, compute checked half-open file range [PointerToRawData,
PointerToRawData+SizeOfRawData) and conservative virtual extent [VirtualAddress,
VirtualAddress+max(VirtualSize,SizeOfRawData)). Both sizes must be nonzero;
RVA aligned4096, raw pointer/size aligned512. File ranges must fit the input and
start beyond SizeOfHeaders; virtual extents must fit SizeOfImage and avoid headers.
The data raw pointer must be at least the code raw end, and its RVA must equal the
code extent end rounded up to4096. Thus section padding also cannot overlap data.
Raw file gaps are allowed; reordered/overlapping file ranges and RVA gaps fail.
Checked round-up rejects overflow. Data VirtualSize may not exceed raw size;
zero-filled data is outside this slice. Code retains prior virtual-tail behavior,
but its zero-filled tail and raw padding are never supplied to the decoder.

For two sections, code starts at SizeOfHeaders rounded up to4096. SizeOfImage
must equal the rounded end of data's raw extent; SizeOfCode/InitializedData must
match the two raw sizes, UninitializedData must be zero, and BaseOfCode/Data must
match their RVAs. This intentionally narrow consistency policy does not retroactively
require those aggregate fields in the historical one-section profile.

Entry mapping is unchanged: only executable code, delta strictly less than both
VirtualSize and raw size, bounded slice length min(raw,virtual)-delta. The lifter
receives only that slice; a branch/call/fallthrough cannot enter data or padding.
The Pe object retains validated section descriptors and original bytes; this does
not allocate a general process image or translate data access. Data cannot be read
by any newly authorized instruction: the instruction and stack contracts are unchanged.
Imports, relocations, TLS, APIs and all other directories remain rejected.

## Evidence and reproducibility

Three production-loader test functions add literal mapping/entry tables, data-byte
independence, all1536 proper fixture truncations, malformed fields, permissions,
raw/virtual/header overlaps, extents/overflow and unsupported directory/entry/
control-flow/memory cases. Root suite38 functions; isolated suite36 functions
(24 inherited control/stack,6 comparisons,6 design-model functions). Counts must
not be summed as unique coverage. Independent literals use a separately authored
Rust PE fixture; the Python Windows fixture is not imported into those tests.

The new Python two_section_helper PE places stack_argument code at RVA1000/file200
and16 authored data bytes at RVA2000/file400. It pushes7, calls the existing helper
that adds5, cleans its argument and returns12 with empty stdout/stderr. All52 prior
fixtures remain. CI runs53 original Windows programs and generated native Linux
ELFs, translates twice for deterministic source, and compiles with rustc -D warnings.
The extra decoder stream repeats existing instructions; it is new image-layout
coverage, not new instruction-semantic coverage. Final commit/run and actual OS
are recorded in PR/Linear after CI. Modern Windows evidence does not validate XP/7.

Run root fmt/Clippy/tests with --locked, scripts/export_decoder_cases.py, isolated
fmt/Clippy/tests with --locked and scripts/check_fixture_manifest.py. Full native
execution commands and literal expected exit statuses are in .github/workflows/ci.yml.
No dependency or license change. Original implementation derives from documented
contracts, without Wine source or runtime dependency.

## Support and next review

Supported: one code section, or code plus exactly one read-only initialized-data
section under the constraints above. Data bytes remain unobservable to accepted
programs. General loader/memory/API/application compatibility is unimplemented.
Stack equivalence remains conditional on the documented valid-stack/no-fault domain.

Return to medium for production range/rounding/permission review, entry slicing,
aggregate-header consistency, fixture independence and final CI verification.
Then separately design bounded immutable-data access as the next prerequisite
for an authored console-output program; do not infer permission for API/import
support from this mapping milestone. No architecture blocker identified in scope.
