# SUB-528: permissioned PE32 intake (design only)

## Decision and scope

Replace section fingerprints **in a proposed image model**, not in production in
this issue. The test-only Python model describes ranges, permissions, metadata and
outstanding proof obligations. It never emits Rust or reports execution eligibility.
`src/`, the production CLI, decoder, state machine and dependency lock stay unchanged.
The existing strict profiles remain regression oracles and continue rejecting all
eight SUB-527 held-out configurations. Parsing progress adds zero translated pairs.

The experiment covers the measured two-section importless images and four-section
images containing writable data. It also bounds the outer layout of ordinary CRT
PE32 images, but explicitly leaves their import/startup metadata unvalidated.
PE32+ is rejected before PE32 field interpretation. These are scoped policy checks,
not a complete Windows-loader validator or a claim that every rejected image is
malformed. A bounded inspection model must distinguish those statements.

## Primary contract provenance

Independent implementation under MIT OR Apache-2.0; no Wine source or runtime.
Consulted Microsoft [PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
on 2026-10-26: COFF and optional headers; section table/flags; directories; debug
records; base relocations. Relevant format facts: directory count and optional-header
size bound directory access; sections distinguish raw and virtual extents; raw
alignment can produce padding, while a larger virtual size introduces zero-fill;
certificate addresses are file offsets; HIGHLOW adjusts a 32-bit relocation field.
An RVA is relative to an image base, whose preferred header value need not be the
actual loaded address. The specification itself is not a complete loader contract.
The narrower restrictions below are project decisions and are not presented as
universal PE validity rules. Existing SUB-515/516 and SUB-517/518 remain the sources
for typed relocation and executable ABI proof, respectively.

## Separate result types and authority

1. **Header/layout rejection**: report the exact first structural, policy, architecture
   or resource error. Do not retry through a more permissive parser after rejection.
2. **Envelope checked**: immutable input snapshot, SHA-256 identity, PE32 bounds,
   section permissions and directory root spans have passed this subset. This does
   not establish correctness of an import descriptor, TLS callback or load config.
3. **Metadata closure checked**: every supported directory's transitively referenced
   byte range is validated and excluded from program reads. An unparsed directory
   makes closure incomplete, even when its outer range is in bounds.
4. **Execution proof** (future, separate): exact instruction graph, supported ABI,
   typed operand/relocation bijection, ownership, flags, return, output, resource and
   environment obligations must all pass before a private emit-capable object exists.

The prototype's report always has `emission_allowed: false`. `metadata_closed: true`
only applies to the supported importless directory subset. A relocation candidate
has `bound: false` and cannot authorize a load, output buffer or indirect call.
There is no API accepting an arbitrary caller-created report as an emission token.
Production implementation must use private types and constructors for these stages;
JSON diagnostic data is never authority to execute. Keep identity and section context
attached to ranges/pointers throughout conversion; no reuse between input files.

A future inspection command may successfully produce a diagnostic report while
`conversion_eligible` is false, but the conversion command must fail and preserve an
existing output file. No conversion success status for merely reading a PE. Keep
historical first-failure diagnostics and distinguish later prerequisites observed in
independent disassembly from instructions actually checked by a converter.

## Header constraints: necessary checks and deliberate limits

| Field/property | Proposed treatment | Rationale/limit |
| --- | --- | --- |
| MZ/PE signature, complete headers | Required with checked ranges | Prevent probing truncated/untrusted bytes |
| Machine/magic | I386 + PE32 only | PE32+ needs separate width/ABI/unwind design |
| Optional header and directory count | At least 96 bytes, 0..16 directories fitting the declared size; remaining extension bytes zero | Stop assuming E0/16; opaque extensions stay unsupported |
| Section count | 1..8 resource cap, one code region | Two/three/four is incidental; eight is a project bound, not a Windows maximum |
| COFF execution flags | Require executable; allow 32-bit and stripped legacy/debug flags, optional RELOCS_STRIPPED; reject DLL/system/large-address-aware/other flags | Machine establishes architecture; exact0102 is incidental; altered address/loader models remain out of scope |
| COFF symbol/section relocation records | Zero | Object/debug symbol handling is unimplemented |
| DLL characteristics | Only DYNAMIC_BASE, NX_COMPAT, NO_SEH and TERMINAL_SERVER_AWARE bits may occur | Presence/absence is recorded; exact8540 is incidental; no SEH or ASLR validation inferred |
| Subsystem | Console3 | GUI/native/driver startup is a separate gate |
| Section/File alignment | 4096/512 | Retained measured-profile policy; low-alignment images need separate permission analysis |
| Preferred base/image | Nonzero64KiB-aligned base, nonwrapping32-bit extent, image <=1MiB, file <=4MiB | Retain resource and pointer assumptions |
| Stack/heap fields | Positive commit <= reserve; loader/Win32Version fields zero | Retained policy, not proof of valid stack or available memory |
| Aggregate sizes/BaseOfCode/BaseOfData | Diagnostic information only | Never override section-table ranges or confer access permissions |
| Timestamps, names, raw file order | Do not decide roles/eligibility | Permissions, ranges and directories carry authority |

No weakening of the existing production parser is implied by the changed treatment
of aggregate fields or COFF flags. Compare both acceptance boundaries explicitly
before migration. A newly accepted *envelope* still has no emission capability.

## Mapping and permissions

Use checked half-open ranges for every file offset, RVA and VA calculation. Empty
accesses are invalid. Keep the existing conservative nonwrapping32-bit endpoint
rule: the exclusive endpoint must fit u32 (a range ending exactly at2^32 rejects).
Check products/counts before allocation or indexing in a Rust implementation.

Each section records virtual data `[rva, rva+VirtualSize)`, complete raw file span,
file-backed program bytes limited by `min(VirtualSize, SizeOfRawData)`, and rounded
reservation using `max(VirtualSize, SizeOfRawData)`. Raw padding and alignment padding
are never code/data accesses. Entry must be inside a file-backed executable byte;
later decoding must validate the full instruction width, not only its first byte.
Headers, inter-region gaps and a request crossing any section boundary reject.

Retain ordered adjacent section-aligned virtual reservations and exact final image
extent in this bounded contract; gaps/reordered virtual tables remain unsupported.
Raw spans may appear in a different file order but cannot overlap each other or
headers. Full raw spans must exist, including padding. Check reservation overlap,
raw/virtual arithmetic and rounded extents independently, including virtual tails.
Overlays carry no program mapping; certificates receive separate file-range checks.

Supported role combinations are RX code60000020, R initialized data40000040,
RW initialized dataC0000040, RW uninitialized dataC0000080, and R discardable metadata
42000040. Names have no authority. These are explicit semantic permission/content
combinations, not arbitrary acceptance of other shared/cache/execute/write flags.
Reject WX, unreadable sections, mixed/unknown content bits and unmodeled attributes.
One RX region is a current policy boundary; multiple code regions are future work.

Only writable roles may have zero-fill in this experiment. Pure BSS requires
raw size/pointer zero; a partially initialized RW region may extend past raw bytes.
Zero-fill is recorded, never silently read from raw padding or treated as immutable.
Writable storage, including initialized-only .data, is a global emission barrier
until a separate memory model proves initialization, access width, mutation and
aliasing. The prototype can describe a pointer to writable or zero-fill storage,
but cannot perform a program read/write there. Nonwritable zero-fill is deliberately
unsupported. Valid-memory/no-fault assumptions must remain explicit in future work.

## Directories, aliases and startup

Every nonempty directory needs both address and size and a complete containing
file-backed section range. Absent entries are optional; there is no mandatory import,
relocation, debug or IAT merely to match a linker fingerprint. Root metadata ranges
must not alias. Certificate entry4 is special: validate its **file** range/alignment,
exclude headers/raw sections, then retain an unsupported-certificate obligation.
The prototype does not authenticate or parse its records.

Only existing bounded debug13/POGO and HIGHLOW relocation substructures are parsed.
Debug13 has one28-byte descriptor, reserved/version fields checked, <=4096-byte opaque
payload, matching RVA/file pointer, and disjoint descriptor/payload ranges in R data.
Opaque bytes remain metadata; no claim about POGO semantics or other debug kinds.

Imports/IAT in the prototype are deliberately **unvalidated** obligations, including
the old exact `_write` case. No new partial import parser grants access while missing
thunks, strings or termination. Production integration must compose the existing exact
import validator, reserve all transitive ranges, maintain IAT/ILT distinction and
reject aliases/unsupported descriptors before closing metadata. General imports,
bound/delay imports, exports, resources, TLS, load configuration, exception tables,
CLR, reserved/unknown directories all block execution. Directory root bounds alone
never imply these structures are valid. In particular, unsupported startup effects
are blocked even if the entry instruction stream looks supported.

If any import or unsupported directory is present, metadata closure stays false and
**all** program immutable-data access is denied. Relocation record analysis is marked
not-run in that case; do not report an empty result as proof that no relocations exist.
Known debug fields are still checked, but do not complete unknown metadata closure.
The ordinary CRT controls exercise exactly this incomplete-closure result.

## Relocation and base provenance

Absent relocations are permitted at the envelope stage, even if DYNAMIC_BASE is set.
Do not infer successful rebasing or absolute-address safety from absence. With
RELOCS_STRIPPED plus a nonempty relocation directory, reject the inconsistency.
Preferred-header evidence and observed Windows load-base evidence are separate;
SUB-527 provides no new observed base. Record `preferred-header-only` for this model.

For a closed metadata set, retain the bounded block grammar: <=4096-byte directory,
strictly increasing4KiB pages, complete4-byte-aligned blocks, HIGHLOW3 records, canonical
final zero ABSOLUTE padding, <=128 live nonoverlapping four-byte sites. Each site must
be wholly file-backed code and outside metadata. Other record types, metadata/data
patch sites, partial fields, duplicate/overlapping sites and empty pages reject.

Read the preferred VA at each site using this image snapshot. Checked subtraction
produces a candidate destination RVA; it must be inside R/RW/BSS virtual data and
outside metadata. Pointer records retain image identity, site, destination, permission
and **unbound** status. A candidate into a zero-fill tail is descriptive only.
A one-byte destination check grants no multi-byte operation: future binding must
check the full width, byte backing and required permissions for each exact operand.

The four-section controls produce five independent observed relocation candidates:
loop1006->3000,1015->3000; array1002->3004,1007->3008,100E->3000. All target writable
data, so all retain the writable-memory barrier. No reinterpretation as immutable
constants, no integer/pointer laundering and no arithmetic on address values.

Future emission needs the existing bijection between reachable decoded absolute
operand fields and supported relocation records, with exact operand roles and
complete destination widths. No omitted or extra relocation, interior instruction
site, guessed address immediate or unavailable actual-base proof may be silently
accepted. Importless nonrelocatable candidates still require ABI/return/flags/stack
proof and explicit treatment of every absolute address form. Existing authored
preferred-base profiles remain distinct from rebasing-normalized compiler profiles.

## Evidence and reproducibility

`tools/permissioned_intake.py` imports no production code, old prototype or fixture
generator. `tools/test_permissioned_intake.py` constructs literal two-/four-section
byte layouts and asserts independently chosen offsets/roles/bytes and failures.
Fifteen new test functions include2048 complete file-truncation cases, metadata alias
and incomplete closure, partial words, BSS/zero-fill, padding/entry edges, header and
arithmetic boundaries, permissions, certificate coordinates, relocation grammar,
stripped contradiction, snapshot identity and deterministic reports. These are design
model checks, not additional native programs or unique tests inherited from older models.

`tools/check_permissioned_corpus.py` reads all eight unchanged SUB-527 PE artifacts,
checks original baseline outcomes against the frozen manifest, source/PE hashes and
production rejection reports, then compares literal expected roles/directories and
observed relocation sites against the model. It writes
`permissioned-intake-report.json`; Linux recomputes the report from the same hashed
PE and requires exact JSON equality with Windows. Existing Windows/Linux converter
checks still independently require the actual rejection diagnostic and preserved
output sentinel. Model parsing cannot replace those checks.

Initial local experiment used the original frozen-source measurement artifact
12634409438 from CI40288844509 (hashes in compiler/heldout/results.json). New CI rebuilds
with the same frozen source/configuration; PE timestamps may change hashes between
runs, while each cross-host comparison requires byte identity within its run.
Available MSVC version is recorded, not falsely called permanently pinned.

| Held-out group | Prototype result | Execution obligations still blocked |
| --- | --- | --- |
| buffer, structure | Two-section envelope and supported debug closure | Instruction/ABI proof not run; existing local-memory forms unsupported |
| loop, array | Four-section envelope, debug/relocation closure, five unbound writable targets | Writable-memory barrier; instructions/ABI not run; loops additionally need termination/state semantics |
| argc/argv, ordinary CRT, file roundtrip | Four-section envelope only | Load config10, import closure, writable memory; relocation/instruction proof not run |
| PE32+ CRT | Architecture rejection | No64-bit intake/state/ABI/unwind support |

No new accepted PE->Rust->ELF comparison. Prior eight compiler programs,102 authored
comparisons and18 original launch samples remain mandatory; eight held-out baseline
outcomes/rejections are separate counts. Windows Server2025 is the execution evidence;
XP/7, ordinary application compatibility and99% remain unvalidated. Historical two
Windows timeout causes remain unresolved; no retries/timeouts are relaxed here.

Run design tests:

```
python3 -m unittest discover -s tools -p test_permissioned_intake.py -v
python3 tools/check_permissioned_corpus.py <downloaded-evidence-directory>
python3 tools/check_permissioned_corpus.py <downloaded-evidence-directory> --compare
```

## Bounded implementation gates and handoff

**Medium contract review first**: audit whole-range/zero-fill boundaries, incomplete
metadata closure, certificate coordinates, aggregate-field treatment, candidate
versus typed pointer authority, and literal expectations against frozen artifacts.
Check all15 functions and exact Windows/Linux reports; do not treat an envelope as
valid startup semantics or import parsing. Review retained restrictions as deliberate
policy, including one RX region, eight-section cap and alignment/permission classes.

**Next Astra High production step**: implement a private normalized envelope and
non-emitting inspection diagnostics under these reviewed gates. Preserve the current
conversion profiles and rejection results. Add independent Rust malformed/range tests,
read-only inspection of all eight held-out PEs with identical cross-host reports,
exact snapshot/hash identity, explicit unvalidated-directory status and sentinel
preservation for conversion. No emitter access from an envelope or unbound pointer.
This is a concrete structural prerequisite, not a new application compatibility claim.

**Later, separately scoped integration**: close exact existing `_write` metadata or
no-import metadata; bind only reviewed operand forms; connect the existing execution
proof to importless immutable images. The fixed buffer/structure artifacts will
still reject unsupported local-memory instructions. Their eventual translation
requires a bounded byte/word local-storage design; loop/array require writable/global
memory, and loops require cycle/termination/resource semantics. CRT/runtime inputs,
files and PE32+ are independent larger projects. Do not widen all of them as part of
loader work or remove a barrier merely to move a success counter.

No tool/resource blocker was found for this design. The remaining uncertainty is
Windows behavior beyond the measured layout/base/no-fault domain, not availability
of the existing CI. No merge, release, new credentials or paid resources.
