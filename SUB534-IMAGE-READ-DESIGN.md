# SUB-534: initialized image reads under a complete no-write proof

Design/model only. Production still rejects the frozen array and loop images at
`importless: only code and immutable sections`. Ten other compiler programs remain
accepted; six held-out conversions remain rejected. This proposal targets the
unchanged array program's empty stdout/stderr and exit9. It does not enable loops.

## Evidence and primary contracts

The source/configuration freeze is cf042295303dccedb8506564f1e466ef9d353acd.
From CI40304355511, MSVC19.51.36260.0/LINK14.51.36260.0, Windows Server2025:

| Artifact | SHA256 | Original result |
| --- | --- | --- |
| held_array.exe | 007ccc51350a5c6854296bd192e58f7a7983225ac8362e6deed3b6bcf9980a86 | empty stdout/stderr, exit9 |
| held_loop.exe | e014b182487c205570ca22efbf9b5d97e1366297faba95eec949f3692ee2a3bc | empty stdout/stderr, exit10 |

Timestamps can change future PE hashes. CI checks each run's unchanged PE and source
hashes, literal code/data/relocation bytes, original recorded output, and production
rejection. It does not edit binaries or frozen compiler flags. Array code is21 bytes:
`8b0d04304000 a108304000 03c8 a100304000 03c1 c3`.
All three operand relocations are HIGHLOW: RVA1002->3004,1007->3008,100e->3000.
Initialized data words at RVA3000/3004/3008 are2/3/4. Literal trace: ECX3,EAX4,
ECX7,EAX2,EAX9,RET9. No value comes from the converter's expected result.

Loop code is28 bytes, including `CMP [absolute],EAX`, `CMP ECX,[absolute]`, JBE,
INC ECX, NOP and a JB at+25 targeting+16. Its two HIGHLOW fields are1006/1015->3000
(initial5). The new model rejects at the first XOR, before the independently checked
back edge. Do not claim it diagnoses loop termination or executes the loop.

Independent authored implementation/specification, MIT OR Apache-2.0. Primary
references read for this decision:

- Microsoft PE specification, section data/VirtualSize/SizeOfRawData, permission flags,
  base relocations and TLS callbacks: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- Intel SDM093 Vol2B MOV/RET: https://cdrdv2.intel.com/v1/dl/getContent/671241
- Intel SDM093 Vol2A ADD: https://cdrdv2.intel.com/v1/dl/getContent/671199

Previously downloaded primary PE text and Intel PDF text were read in the workspace.
HIGHLOW adds the actual-minus-preferred base delta to the complete32-bit field.
MOV reads the source into its destination and preserves arithmetic flags; ADD sets
CF/ZF/SF/OF (also AF/PF, whose consumers remain unsupported). A writable section is
permission to write, not evidence of a write, nor evidence that its contents stay
constant. Virtual tails beyond file-backed initialized bytes must not be read here.
No Wine source or tests are imported; no clean-room-process claim.

## Smallest language with a complete effect proof

Use a separately checked, private initialized-data candidate. It must never emerge
from an inspection JSON report or from fallback after another profile fails. Select
this proposed profile explicitly from checked importless PE intake with initialized
writable data and a relocation directory. Preserve existing strict profiles. Profile
selection is not authorization to emit; all following gates must succeed first.

| Exact bytes | Effect admitted in this candidate |
| --- | --- |
|8B0D va32|MOV ECX,dword[absolute VA], bind field at instruction+2|
|A1 va32|MOV EAX,dword[absolute VA], bind field at instruction+1|
|03C8|ADD ECX,EAX, both full known scalars|
|03C1|ADD EAX,ECX, both full known scalars|
|C3|Terminal entry return with known EAX0..255|

This is five forms, six instructions in the array. No prefixes, alternative encodings,
register-indirect access, immediate address materialization, pointer arithmetic, calls,
branches, stores, stack operations or system instructions in this candidate. Entry
must equal the sole code section's RVA. Decode its entire virtual code range into
this language, with exactly one RET at its end and at most1024 instructions. Reject
truncation, extra bytes after RET, unexplained code, and every unsupported effect.
Raw section padding outside VirtualSize is neither code nor data. There is no branch
sampling, guessed unreachable path, caller, callee or join to ignore. This intentionally
restricts composition with existing call/stack features; widening requires another
proof review. The loop continues to reject even if its initialized data passes intake.

The no-write proof is syntactic over the complete entry program: allowed reads target
only initialized data; ADD writes only volatile scalar registers; RET consumes the
protected incoming return address under the existing entry convention. No instruction
can write image bytes, generate/escape a pointer, call external code, jump into padding
or start another thread. ESI/EDI/EBX/EBP and ESP are untouched until the terminal RET.
No concrete observed run is used to infer absence of writes. Dynamic execution fallback
is unnecessary. Bounds, cap, initialized register and exit proofs precede emission.

## Owned image, initialized ranges and typed operand authority

Keep the owned PE snapshot and section mappings together. Retain checked file/RVA/
virtual arithmetic, maximum4MiB file/1MiB image, one code section, up to8 sections,
disjoint raw and mapped ranges including padding, valid permissions/alignment, and
closed metadata. Allow exactly one private initialized RW section (C0000040), with
nonzero VirtualSize <= SizeOfRawData; reject shared, executable-writable, BSS and
zero-filled tails. Immutable/debug and discardable-relocation sections may accompany
it under the established parsers. Names/order are not proof. No writable heap/global
store support is implied by a section's admission.

Each read needs a private bound address containing this image's ownership, exact
instruction/operand-field RVA, target section and target RVA, width4, and relocation
identity. Construct it only by matching a unique HIGHLOW at the entire decoded
four-byte field and computing VA - preferred image base with checked subtraction.
Check target+4 in a single initialized virtual AND file-backed range, outside every
metadata byte. Reject headers, code, gaps, immutable/debug bytes, relocation tables,
zero-fill, raw padding, boundary crossings and overflow. Unaligned full reads may be
accepted under the explicit no-fault domain; no concurrent atomicity is promised.
A public digest, raw numeric VA/RVA, or bound address from another image cannot grant
access. Private constructors/lifetimes or a single owned candidate must enforce this
in Rust; the Python model's mutable test objects are not a security boundary.

Metadata closure allows only directories5(base relocation) and6(the already validated
debug form), all others absent. Preserve transitive debug payload ranges and pointer/
file agreement. Imports/IAT, TLS (callbacks/index writes), load config, resources,
exports and other startup facilities reject, including superficially unused ones.
Enforce the existing sorted relocation blocks, exact HIGHLOW/terminal-zero ABSOLUTE
padding rules, <=128 live records, no duplicates/overlaps and complete four-byte sites.
Every live relocation must bind to exactly one admitted read field; no unbound loader
write anywhere in the image is allowed. In particular, reject all relocation sites in
data, even outside the three accessed words. This prevents initial data from changing
under loader relocation and avoids treating a relocated pointer word as a scalar.
Other relocation kinds reject, not ignore. Full-width exclusions apply to sites AND
read targets; checking their first byte is insufficient.

Loaded four-byte contents are scalars even if their numbers resemble addresses.
This language provides no scalar-to-address operation, indirect read or pointer escape.
The decoded operand carries address authority; the loaded register does not. Repeated
or overlapping reads are safe under the stable-byte domain and read their actual
little-endian bytes; they never create write aliases. Aliased sections/file mappings
still reject. Both ADD operands must be initialized full scalars; wrap modulo2^32 and
track flags correctly. MOV preserves each flag's knowledge. No flags are consumed in
this first candidate, but future state reuse must not inherit invented flags.

## Conditional execution domain and relocation evidence

Assume normal successful PE loading, flat32-bit addressing, mapped readable pages,
valid incoming stack/return convention, and no faults/asynchronous callbacks/threads
or external agent changing program data/code while it runs. No shared section or
external call is admitted. The static proof excludes program-originated writes and
escapes; it cannot prove that a debugger, injected thread, external process, unusual
loader or hardware will never alter memory. These are explicit domain conditions.

The frozen C objects are volatile. The observation contract here is process stdout,
stderr, exit and specified files, under the domain above. It does not promise physical
volatile-read event counts, debugger/hardware tracing, timing or MMIO behavior. The
model records every source read in order. Constant values in native generated code
are justified only after the no-write/no-external-mutation proof; compiler folding
must not be represented as preserving those excluded access-event observations.

For any successful non-wrapping actual load base B, HIGHLOW yields B+targetRVA from
preferredBase+targetRVA. Native translation resolves the RVA in the owned image and
has no dependency on B. Literal tests cover preferred, higher and lower bases; these
are arithmetic/model tests, not observed Windows rebasing. Current array/loop baseline
records do not report their actual load bases. Future same-PE execution can establish
output agreement at whatever successful base Windows selected, but cannot establish
distinct rebasing coverage without observer evidence. Do not reuse another program's
observed base as proof for these artifacts. No forced rebasing or security changes.

## Prototype, review and implementation gates

`tools/image_read_model.py` independently binds exact bytes/relocations and evaluates
this restricted language. Nine test functions use literal traces/flag tables, complete
word boundaries, mapping/metadata aliases, loader writes into data, missing/duplicate/
overlapping fields, unknown initial registers, unsupported stores/calls/branches,
prefixes, truncated code, instruction caps and independent relocation arithmetic.
No production imports. The test model receives checked-layout descriptors; it is not
a second full PE parser. Existing independent `permissioned_intake.py` supplies layout
extraction only for the artifact checker; its15 inherited tests are not new counts.
`check_image_read_contract.py` checks exact frozen array/loop evidence on both hosts.
No model result confers emission eligibility. Production source/acceptance unchanged.

Medium review should challenge the complete-effect-language restriction, loader-write
exclusion, full-width metadata/data separation, own-image binding and volatile/domain
claims. Then a separate Astra High implementation can add this private candidate,
exact read forms and scalar ADD ECX,EAX, reusing existing checked state/emission where
safe without broadening other profiles. Required gates:

1. Independent malformed production tests for all intake/relocation/target/unknown/
   unsupported-effect cases, including failures before any output source is written.
2. Exact whitelist and instruction-length checks, a complete terminal body, all
   relocation fields accounted for, no capability constructed from inspection output.
3. Independent native arithmetic/read/flag boundary tests and stable deterministic
   Rust. No decoder, Wine or AI runtime dependency in generated ELF.
4. Same untouched array PE separately converted on Windows/Linux to identical Rust;
   actual ELF empty stdout/stderr and exit9 compared to Windows with source/PE hashes.
   Update only conversion acceptance, never frozen source/compiler options to fit.
5. Ten existing compiler comparisons,102 authored comparisons,18 launch diagnostics
   and all other five held-out rejection gates preserved. Loop support remains separate.

No known tool/resource blocker. Linear context-notes tool advertised but returned
`Tool get_agent_context not found`; issue/repository guidance was available. Three
historical original-Windows timeout causes remain unresolved; failures retain diagnostics
and are not retried silently. Server2025 evidence is not XP/7 or general-app compatibility.
No merge/release. This design is ready for bounded medium review, not production use.

## Medium contract review

Reviewed the complete decoder/evaluator and independently literal expectations. The
proof covers this candidate's entire code body, not all previously supported opcode
families: branches/calls are forbidden even if an apparent branch would be untaken.
The existing graph/call machinery does not authorize composing those operations with
this new data authority. Model inputs assume checked PE metadata closure; the model's
directory-number allowlist alone cannot prove debug/relocation transitive closure.
Production must obtain that property from the owned checked envelope and must never
accept caller-supplied descriptors or report JSON as evidence.

Closed two isolated regression gaps within the existing nine test functions: a complete
non-overlapping HIGHLOW over valid ADD bytes now explicitly reaches `unbound loader
write`; a loader write to a fourth initialized data word, unused by every read, reaches
`loader write outside code`. Earlier malformed-site cases could reject at bounds or
missing-field checks and did not establish these particular gates. No model behavior
change or production defect was reproduced. Full-width metadata overlap and partial
read bounds, exact artifact bytes, independent arithmetic/flags and own-snapshot reads
were verified. Python mutable test objects do not establish Rust capability isolation.

Ready for bounded SUB-535 Astra implementation: private checked candidate, exact five
forms, unified checked semantics/emission, full relocation accounting including unused
data and code sites, independent negative CLI tests proving each gate is reached, and
actual unchanged-array Windows/Linux exit9 agreement. Retain all ten existing compiler
comparisons and six rejections until the array implementation passes; then only array
changes acceptance. No loop execution, general memory or external-call composition.
Valid stack/no-fault/no-external-mutation conditions and unobserved actual array load
base remain explicit. Three historical Windows timeout causes remain unresolved.
