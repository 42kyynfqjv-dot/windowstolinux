# Original image-name locale and conversion boundary

## Connected execution

Under the existing explicit native profiles, original entry now executes
`0x40ae79 -> 0x40ab89`, the existing locale-view constructor `0x40aabe`, and
the actual locale-info code-page read. The unchanged mapped program's value
is not 65001; it therefore executes `0x407fc0 -> 0x407d96`, the real shared
resolver `0x407e41`, and kernel32 provider acquisition. It reaches original
**GetProcAddress CALL `0x407efe`, IAT `0x415070`, for `AreFileApisANSI`**.
The implemented export registry rejects this name as unsupported. This is a
converter capability rejection, not an observed Windows missing-export result.

The function cache at `0x41e000` remains zero. No NULL export, absence sentinel,
LastError 127 or successful query is manufactured. Preceding module-reference,
stack, initialized locale/output record and onexit effects remain. The original
narrow converter at `0x40ae94 -> 0x40ad10` has not executed, and no argc/argv is
published. Default admission, whole startup and rcedit remain unsupported.

When file mode is ANSI the original helper returns **CP_ACP=0**; OEM mode
returns **CP_OEMCP=1**. It does not return GetACP's numeric value. Alias
resolution must use the declared target profile; direct Windows CP65001 probes
do not prove that the Windows host's ACP is UTF-8.

The original locale helper's independently tested 65001 branch returns 65001
without querying file mode. Its module-backed locale view preserves the actual
constructor's uninitialized PTD field and zero temporary flag. Heap-backed views,
non-default locale mutation helpers and their temporary-view cleanup remain
rejected; no numeric address is retagged into an arbitrary heap view.

## Evidence and requirements

[Frozen expectations](evidence/argv-locale-expectations.json),
[conversion vectors](evidence/argv-conversion-expectations.json), and
[results](evidence/argv-locale-conversion.json) separate original instructions,
modeled inputs, API observations and translation evidence.

Eleven native original-instruction scenarios cover the successful 65001 branch,
expired mapping, unknown code-page bits, unbound constructor mutation, changed
helper/constructor bytes, unproved absence sentinel, numeric function guesses,
wrong typed cached function, genuine cold lookup, and unproved heap locale view.
Success and failure assertions are explicit; a generic error cannot count as the
successful branch. The actual entry regression checks the live module/name
arguments and unchanged function cache, rather than accepting any later error.

The predecessor's six raw Windows GetModuleFileNameW records were downloaded
from run **41320551684**, artifact **13089177276**, validated against the raw
hash in its report, and retained as
[immutable JSONL](evidence/argv-image-name-windows-8327b31.jsonl). Its trace SHA256
is `61b357e54abac6247e899e7808fa5dd228e05c69564d4a944770de447bf43abb`.
These are direct Windows API component observations, not six translated PEs.
All three predecessor workflows passed; earlier launch timeouts remain unresolved.

The added isolated authored Windows child records raw process file-mode BOOLs,
restores the initial mode before file I/O/assertions, identifies the actual
resolved export-owner module and records ACP/OEMCP without assuming UTF-8.
Fifteen frozen UTF-8 input cases (14 within the documented flags domain and one
outside it) record every return, LastError and output
byte before comparison. Guard bytes beyond capacity must be untouched. Bytes
**inside** a failed conversion's capacity are retained without an invented
unchanged-buffer rule. Local metadata typechecking is not Windows execution;
actual observations require the Windows CI artifact and validated JSONL hash.

Primary contracts:

- [AreFileApisANSI](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-arefileapisansi): process-wide ANSI/OEM mode, nonzero versus zero result; raw TRUE need not equal 1.
- [WideCharToMultiByte](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-widechartomultibyte): UTF-16 input units versus output bytes; -1 includes NUL, positive counts do not add one, zero capacity queries, modern invalid-surrogate behavior, flags and failure effects. XP behavior remains unsupported.

## Preserved Windows probe contradiction

Checkpoint 458490a startup run **41323334916**, job **124897997677**, failed:
flag 0x10 returned 2 rather than the frozen documentation-derived0/error1004
expectation. This is a new API-observation mismatch, not a historical launch
timeout or proof of a converter defect. That aggregate step had no evidence
folder configured, so its failure log retains the return comparison but **no
raw file-mode/conversion trace was uploaded** in artifact13090501814. This
missing data is explicit; it cannot be reconstructed from the assertion.

The correction collects all 15 rows before assertions, retains aggregate API
JSONL even before the reproduction gate, and treats flags outside 0/128 as
observations only. The original frozen expectation remains in the repository
so the contradiction is auditable. Unsupported flags remain outside the
converter contract. Within-domain return/error/output/guard checks remain
strict. A separate protocol regression accepts the observed return 2 but still
rejects writing past capacity. Fresh Windows execution must establish the full
trace; a rerun does not erase the original failure.

## Local verification

182 root, 330 CRT (two artifact gates separately executed), 185 unwind tests;
96 startup Python tests (one skip), 106 tools and 18 corpus tests (one skip),
Clippy and formatting passed. Full runtime replay passed with five retained
recorded Windows wrapper comparisons and zero whole-PE pairs. Fresh emission
from the current source is byte-identical:
7017962af3c1c24b1018af6d0da9686975a8d63b909067e31a3afa94cc06d562.
The later probe/protocol repair does not change emitted runtime semantics.
Fresh Windows observation retention and exact final-head CI remain a separate
pending gate; the original flag mismatch is preserved above.

## Next connected gate and review scope

Implement shared process file-mode ownership and a justified callable export
with BOOL knowledge sufficient for the original TEST, without inventing raw
result bits. Then connect the already inventoried original `0x40ad10`, query and
copy wrapper `0x40ab65`, `0x40b8c5`/flags helper `0x40b835` and actual
WideCharToMultiByte IAT `0x4150e0`. CP_ACP=0 needs checked resolution through
the explicit UTF-8 profile; CP_OEMCP=1 requires a distinct supported policy.
Preserve source lifetime across query/copy,
byte counts, NUL handling, invalid UTF-16 and failure-buffer effects. Output
capacity/allocation/length stores and the image wrapper's cookie return must
execute before claiming conversion completion. Argv parsing follows separately.

Sol can independently review this diff, raw observation provenance and helper
bounds. A bounded Astra pass is warranted only if partial BOOL knowledge or
query/copy memory effects require new proof/runtime semantics. Do not substitute
GetACP, assume ANSI mode or treat the known unimplemented export as absent to
advance the entry. Existing free/exception, nonempty onexit, native close/EOF,
Windows path acquisition and broader equivalence gates remain explicit.
