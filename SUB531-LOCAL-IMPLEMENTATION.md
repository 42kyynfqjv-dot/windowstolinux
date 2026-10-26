# SUB-531: two scalar locals and private importless execution

The frozen structure.c program needs eight bytes of local stack storage. Its unchanged
29-byte MSVC entry now passes full PE/intake, exact decoding, graph, ABI and local-state
proof before native Rust emission. The acceptance gate is the actual same-PE Windows
baseline versus Linux ELF empty stdout/stderr and exit12. Inspection and model traces
alone do not satisfy it. CI artifacts record source/PE/Rust hashes, compiler version,
fixed flags, original observations and independent Linux conversion.

## Implemented contract

Only the exact forms in SUB530-LOCAL-FRAME-DESIGN.md are added: 83EC08 allocation,
C70424 imm32/C7442404 imm32 scalar local stores, existing 8B442404 with local meaning,
030424 scalar local addition, existing 83C408 with local cleanup meaning, and RET.
Two full aligned words are tagged Local(owner,allocation,uninitialized-or-u32).
Both tags/token and protected boundary are validated before each access/cleanup.
Reads require initialization; numeric address-like bits never confer pointer authority.
Fresh allocations and separate hypothetical branch states cannot inherit initialization.

MOV EAX,[ESP+4], MOV [ESP+4],imm32 and ADD ESP8 overlap earlier argument operations.
Current invocation allocation state selects exactly one rule. With live locals the
full local window must validate; no failure falls back to Data. Without allocation,
old argument ownership applies; the earlier caller store remains restricted to12.
Data cleanup rejects untracked/mixed/protected/foreign slots. Existing pointer-valued
Data cleanup remains allowed without granting permission for pointer-valued locals.

SUB/ADD ESP invalidate CF/ZF/SF/OF because absolute ESP is unknown. MOV preserves flags;
ADD EAX,[ESP] uses actual wrapping scalar arithmetic and carry/sign/zero/overflow.
Push/save/tail/output and nonlocal cleanup cannot execute with live local allocation.
Parameterless internal calls suspend caller locals below a fresh protected Return;
callee ownership cannot expose those locals as arguments. Returns require balanced
cleanup, preserved ESI and scalar EAX; entry exit range stays0..255. Limits remain129
words,32 internal calls,1024 decoded/path instructions and4096 explored states.

The shared validator/runtime transition clones bounded state and commits only after
success, including PC/steps. Output errors can have external file effects under the
existing _write failure contract; state atomicity does not claim to undo I/O.
Independent bad-state tests check failed local operations atomically. Invalid PE inputs
fail before output-file writes. Native emitted code uses the same checked transitions.

## Intake and proof boundary

For DLL8540 inputs, checked optional-header/import-directory facts select the profile:
no import directory selects owned semantic Importless intake; a declared import selects
the old strict imported Candidate. There is no parser retry/fallback. Other authored
profiles retain their prior loader. The new profile requires only Code/Immutable
sections, complete file backing and no directory except validated optional debug13
with reserved payload. Imports/IAT, relocations, TLS, load config, certificates,
metadata-only/writable/zero-fill sections remain ineligible.

Only the executable code slice with its RVA/entry is exposed to a private compiler
view. It carries no data section, relocation or IAT authority. Absolute address forms
cannot validate; scalar immediate bits cannot be dereferenced. This proves image-base
independence within the accepted instruction set; it does not claim observed Windows
load base. Envelope inspection retains false emission eligibility. A private
ProvenProgram exists only after full graph and all-path state proof and is the only
emission entry. No report, JSON or supplied eligibility Boolean grants permission.

Valid aligned sufficient stack storage, no wrap/faults/asynchronous mutation and
unobservable absolute ESP/return addresses remain conditional execution assumptions.
This is no general heap/global/byte-memory, CRT, loop or PE32+ implementation. Primary
Intel/Microsoft instruction and ABI provenance is recorded in SUB530; implementation
and tests independently authored under MIT OR Apache-2.0. No Wine or AI runtime and
no decoder dependency in generated ELF.

## Evidence and reproduction

Run cargo fmt --check, rustfmt --check src/linker/state.rs, cargo clippy --all-targets
--locked -- -D warnings, cargo test --locked, cargo build --locked, then
python tools/check_local_production.py. The latter authors its own PE bytes and literal
expected results independently of production, earlier fixtures and the model:10
native deterministic cases and95 CLI rejections. Four added Rust functions check
layout/arithmetic, atomic tag/token/protected failures and both cleanup modes,
fresh/nested/shared frames, per-path initialization and resource/return obligations.
Two added intake functions check directory/permission/snapshot boundaries, debug
closure and2048 file truncations. Total root count73 (67 previous +6 new).
The ten prior Python model functions are separate design evidence, not extra native
comparisons. Decoder evaluation counts remain43 including27 inherited functions.

The output-free native cases exposed an empty-buffer emitter warning; the generated
output closure now explicitly rejects any unvalidated output, so rustc -D warnings
passes without suppressing the warning. The older nested test's IR-name assertion
now checks StoreFour(12), retaining its two native cases and50 rejections.

CI uses unchanged compiler/heldout/structure.c/cases.json and the fixed original
compiler configuration. conversion.json records the separate acceptance requirement:
structure succeeds; seven other held-out configurations reject and preserve outputs.
Windows measures original behavior before conversion. Linux checks PE/source hashes,
converts twice, requires byte-identical Rust from both hosts, compiles and executes
with exact stdout/stderr/exit checks. check_local_frame_contract.py independently
checks literal29 code bytes and model trace; it explicitly labels native execution
as a separate check. The eight earlier compiler programs,102 authored comparisons
and18 original launch probes remain required. No retry/timeout changes. Three
historical original-Windows timeout causes remain unresolved; Windows Server2025
results do not establish XP/7 or ordinary application compatibility.

Next medium review: audit production local/argument dispatch, protected words and
all-path initialization, importless capability and artifact identity/output evidence.
Keep the draft PR unmerged; future capability expansion needs a distinct bounded gate.

Medium review: the original uninitialized-branch regression took its invalid path.
Added opposite branch polarity so a concrete initialized execution still rejects
the hypothetical uninitialized successor. Both remain tested. No production defect
was reproduced. Reviewed same-artifact Windows/Linux empty output and exit12, local
tag/token/boundary checks, explicit cleanup dispatch, unknown ESP flags and private
code-only intake bridge. All seven other held-out conversions remain mandatory rejects.

Next proposed gate is design-only owned byte-local storage for frozen buffer.c:
actual observed PUSH ECX/POP ECX allocation, byte initialization, MOVZX, AL increment
and store. Resolve partial-register/INC flag semantics, unknown discarded ECX,
per-byte initialization and protected-word isolation with independent traces before
production changes. It advances the remaining importless stack-memory case without
adding loader rebasing, writable globals, loops or CRT startup at the same time.
Astra High is appropriate for that contract/model; medium review precedes implementation.
