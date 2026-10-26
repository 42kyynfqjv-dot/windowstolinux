# SUB-529: production PE32 inspection without emission

`w2l --inspect-image INPUT.exe` reads a bounded immutable snapshot and prints one
JSON report. Exit0 means the inspection report was produced. Every successful
report says `emission_allowed: false`; no Rust/ELF output is produced. Structural,
architecture, policy or resource rejection exits1 with a diagnostic on stderr.
The existing `w2l INPUT.exe OUTPUT.rs` conversion interface and its strict profiles
retain their acceptance/rejection behavior. No fallback from conversion to inspection.

Implementation: private `Envelope`, section and unbound-pointer types in
src/inspection.rs. Only a diagnostic string crosses that module boundary; there is
no emission constructor, program-data reader or pointer export. One owned Vec binds
all locations/candidates to the same image. File input is capped at4MiB+1 before
parse, image ranges at1MiB; checked32-bit endpoints and bounded table counts precede
indexing. Whole file-backed widths and raw/virtual padding are distinct. Zero-fill
lookups return no file coordinate. Writable/BSS ranges remain metadata descriptions
with an execution barrier. Names/section count fingerprints do not confer authority.
The reviewed permission classes, one-code-region, alignment, section-order and
resource policies remain explicit limits; this is not an unrestricted Windows loader.

SUB528-PE32-DESIGN.md supplies the independently implemented primary PE contract.
Optional directory count and optional-header size control access; certificate
addresses use file offsets. Unknown/import/startup directories prevent metadata
closure. Supported debug13 payloads are excluded from program data. Only the bounded
HIGHLOW relocation grammar is analyzed when metadata closure is established; candidates
retain unbound status and complete field/alias/provenance checks. The preferred base
is header evidence only. Relocation analysis is explicitly not-run for incomplete
metadata; zero candidate records in that case do not assert absence of relocations.

## Validation

Six new Rust test functions directly construct literal PE layouts, without importing
the prototype or fixture generators. They exercise2048 truncated prefixes, explicit
header/range/permissions/architecture negatives, incomplete startup/import metadata,
zero-fill file coordinates, full widths, snapshot isolation, relocation block/type/
overlap/target/stripped contradictions and deterministic output. Total root Rust
functions:66 (60 prior+6 new). An initial local test incorrectly expected a valid
512-byte header extent to reject; corrected the malformed input to256 bytes after
checking that the complete table fits within512. Parser policy was not weakened.

The frozen held-out checker now invokes the real CLI twice per image, requires byte
identical output/diagnostics and compares parsed reports with the reviewed independent
model and literal role/relocation expectations. Production JSON omits the prototype's
SHA field: the checker binds every report to the exact source/PE hash in a separate
`production-inspection-report.json` artifact. JSON is diagnostic data, never an
execution capability. Windows produces that report; Linux independently inspects
the same PE bytes and compares it exactly. Conversion still runs separately and
must reject all eight, retaining output sentinels and matching diagnostics.

| Inputs | Inspection | Conversion |
| --- | --- | --- |
| buffer/structure | Envelope and supported debug metadata checked; instructions/ABI unproven | Both reject |
| loop/array | Envelope/metadata checked; five unbound writable relocation targets | Both reject |
| args/CRT/file | Envelope only; load-config10/import closure and writable memory blocked | All three reject |
| PE32+ | Architecture rejected | Reject |

No new translated pair. Existing eight compiler-program comparisons,102 authored
comparisons and18 launch samples remain separate mandatory gates. Persistent corpus
launch evidence and15/5-second timeout/termination limits remain intact, with no
silent retry. Three earlier original Windows timeouts remain unexplained. Windows
Server2025 evidence establishes neither XP/7 nor ordinary application compatibility.

## Medium review handoff

Audit private stage boundaries, whole-range arithmetic, zero-fill coordinates,
metadata aliases/closure, unbound relocation authority and exact source/PE/report
provenance. Review new Rust literal expectations independently of Python parity;
parity alone is not correctness proof. Inspect any newly retained timeout evidence
before expansion. No instruction/ABI proof runs through inspection, and the parser
cannot produce an emit-capable object.

Next architecture gate after review: separately integrate closed no-import metadata
with the existing instruction/ABI proof for a scoped immutable image. Keep conversion
strict for unsupported memory forms and writable layouts. The unchanged buffer and
structure compiler artifacts still require a bounded local-storage design; loops,
global memory, ordinary CRT and PE32+ remain separate larger gates. No merge/release.
