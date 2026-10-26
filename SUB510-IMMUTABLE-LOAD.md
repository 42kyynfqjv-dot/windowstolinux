# SUB-510 exact immutable-data EAX load

Primary instruction contract: Intel SDM volume2, order325383-081US Sept2023,
MOV pages4-35 through4-38, https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf.
A1 in32-bit operand/address mode loads a doubleword from DS:moffs32 into EAX;
no flags are changed. Unaligned loads are valid when alignment checking is disabled;
#AC/#PF/segment exceptions are excluded by the execution assumptions below.
PE address provenance follows Microsoft PE/COFF's image base, RVA and section
contracts: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format.
Implementation and fixtures are independently authored, with no source import.

## Accepted contract and provenance

Accept exactly unprefixed `A1 address32`, five bytes, EAX destination, memory source,
no base/index, four-byte displacement, default DS. Iced code/length/operand metadata
and first-byte whitelist enforce this. Equivalent ModRM forms, other registers,
widths, prefixes, writes and computed addresses remain unsupported.

Pe retains the parsed preferred ImageBase. A read first checks that address+3 does
not wrap, then checked subtraction gives RVA=address-ImageBase. Only section1 of
the existing validated two-section profile can supply data, with exact40000040
permissions. Checked delta=RVA-dataRVA and end=delta+4 must fit both VirtualSize and
SizeOfRawData. Checked file offset=rawPointer+delta supplies exactly four bytes,
decoded little-endian without a host pointer cast. No read may touch code, headers,
gaps, raw padding, virtual tails or another section. One-section reads fail.

Native execution preconditions: image actually loaded at its preferred base;
flat zero-base DS covering the data; readable initialized section bytes as in the
file with no external mutation; no page/segment fault or asynchronous interference.
Unaligned loads additionally require alignment checking disabled. Header parsing
does not prove the actual load base or OS execution state. Existing no-relocation,
no-import/DLL-feature policy remains; this does not model rebasing or exceptions.
Existing valid-stack assumptions also remain. Windows fixtures provide observations
for their runs, not a universal environment guarantee or XP/7 compatibility claim.

## Production path and lowering

The CLI calls Pe::translate. `control::decode` builds typed LoadAbsolute(address)
IR; decoding alone never authorizes executing a read. `translate_with_reads` receives
an explicit resolver closure over that validated Pe, resolves every decoded load
(including untaken paths), then lowers the immutable u32 to existing Mov(value) IR.
This preserves EAX/flag semantics and generates a native Rust constant assignment.
No original address, host pointer, byte decoder or PE loader is used at runtime.
There is no writable data/instruction in the accepted subset that could invalidate
constant lowering. Future writable data or external calls require a new contract.

`emit` rejects any unresolved load before path validation, including an unresolved
instruction on an untaken branch. Byte-only translate therefore rejects these
programs without context. The resolver entry is internal to the crate; production
uses only Pe's checked resolver. This is not a public arbitrary-memory interface.
Existing53 streams have identical IR/emission behavior; no new dependencies.

## Tests and observation gates

Root42 test functions include three new production-loader/translation tests:
literal little-endian and first/last/unaligned boundaries, moved preferred base,
changed-data/source observations, complete-width rejections, unknown/known flags,
shared helper/branch join and invalid untaken reads. Prefix/alternate-operand and
one-section/header/code/gap/padding/wrap rejection use production paths.

Isolated36 functions comprise24 inherited control/stack,6 decoder comparisons and
6 independent design-model tests. The harness compares typed A1 IR to both the
handwritten decoder and literal expectations; metadata cross-checks iced/yaxpeax.
For the nine `data_` streams, source-result parity explicitly expects rejection
without image context. It is not a successful-emission or independent image-read
oracle. Root Pe tests and genuine original/translated execution cover resolution.
Mutation totals include duplicate/shared logic and are not exhaustive semantics.

CI runs62 authored programs: all53 prior cases and nine immutable-data cases.
Expected exits: data_sum12, data_unaligned12, data_last255, data_wrap2,
data_zero22, data_carry22, data_overflow11, data_negative_overflow22, data_call12.
Flags are established before loading7; the loaded value must not change prior
ZF/CF/SF/OF branch observations. Each original Windows program and generated Linux
ELF must match the literal expected exit and empty stdout/stderr; repeat translation
must produce identical source, compiled standalone with rustc -D warnings.
Final head/run and observed Windows OS are recorded in PR/Linear after CI.

Run root fmt/Clippy/tests with --locked; export_decoder_cases.py, isolated locked
fmt/Clippy/tests; check_fixture_manifest.py and native execution commands in CI.
Modern Windows Server2025 evidence does not validate XP/7 or applications.

## Next review

Return to Sol medium to audit preferred-base assumptions, whole-width provenance,
all-path resolution, unaligned fault preconditions, flags, fixture independence and
unchanged prior emission. Resolve confirmed gaps within this slice before designing
an output/import/API gate. General memory, writes, dynamic pointers and APIs remain
unsupported. No remaining architecture blocker identified within this contract.

## Medium review

No production defect reproduced in the CLI Pe-bound resolver or whole-width bounds.
The internal resolver closure is an explicit trusted boundary, not a type-level
proof against arbitrary future callers. Current production captures the same Pe
for its code and data and caches no resolved values between images. A new test
alternates two PEs with identical code but different data and raw offsets, placing
a decoy at the old file offset; generated source must match each independent
literal EAX value. The new data_sum_alt fixture keeps data_sum code identical but
changes the word7 to9, requiring exit14 versus12 on Windows and Linux.

Current43 root functions; isolated36 =24 inherited control/stack+6 comparisons+6
design tests. Native fixture count63. Preferred-base/flat-DS/immutability/no-fault
and disabled alignment-check assumptions remain explicit and conditional.

Next SUB-511 is an Astra High design gate for one imported output function and
exact observable bytes. Compare documented CRT _write with Win32 output contracts,
choose the smallest truthful boundary, and specify imports/IAT, calling convention,
buffer provenance, clobbers and error/short-write behavior before implementation.
Return to medium contract review; no API or general-memory support is added here.
