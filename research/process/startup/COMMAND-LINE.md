# Process-owned command lines for callback 9

## Frozen native profile

GetCommandLineW is UTF-16. GetCommandLineA uses the process code page, which cannot
be inferred from PE machine type or Linux argv. This milestone admits only an
explicit code page 65001 (UTF-8) native launch profile. It does not claim a legacy
ACP, XP/7 support, or acquisition of a Windows parent's raw command line.

Native argv is captured once. The builder emits a canonical MSVC-style string:
argv0 is quoted using the distinct program-name rules; later arguments are always
quoted, with runs of backslashes doubled before a closing quote and doubled plus
one before a literal quote. Spaces/tabs, empty arguments and Unicode are preserved.
Empty/quoted argv0, NUL, invalid native UTF-8 and more than 32766 UTF-16 code units
excluding the terminator reject. No lossy code-page best fit or replacement occurs.

A and W buffers are distinct, initialized, read-only process-owned mappings. They
include terminators, retain stable pointers through repeated calls and cannot be
freed as temporary input or heap allocations. Pair publication rolls back its own
first mapping if the second mapping fails; existing state is untouched. Each API
validates only its requested buffer so a later W failure preserves the actual A
store. Static import, original instructions, ABI and saved-state checks remain.

The original 25-byte callback at 0x407093 calls GetCommandLineA/IAT41508c, stores
41ce74, calls GetCommandLineW/IAT415090, stores41ce78, sets AL1 and returns. The next
table index is10/0x40b42a. Other bootstrap/thread/entropy inputs remain explicit;
this is component evidence, not whole-PE translation or full rcedit support.

Primary requirements: Microsoft GetCommandLineA/W (system-owned lifetime; A is an
8-bit process-code-page conversion; UTF-8 manifest support since Windows1903),
Microsoft MSVC parsing-C-command-line-arguments, and Windows UTF-8 process manifest
documentation. Frozen vectors and a separately authored Windows probe check raw
A/W values, process code page, pointer stability and actual CRT argv parsing.


## Implementation checkpoint and independent gates

Local gates passed: 299 CRT tests (two artifact-dependent tests omitted in the
ordinary suite), the artifact-backed original-entry/body test, 185 unwind-slice
checks, 84 Python tests (one existing skip), Clippy and formatting. Command-line
coverage includes ten frozen quoting/Unicode vectors, exact UTF-16 length limits,
12 process-storage scenarios, ten original-body scenarios and real Linux child
argv capture including invalid UTF-8 rejection. Later W, import or RET failure
retains original completed stores; stale/foreign/unknown/RW buffer facts reject.
Both A/W published globals are checked in the connected original-entry case.
A completed getter discards unproved LastError knowledge; errno is not synthesized.
The complete artifact replay is still running at this checkpoint.

All predecessor6fb39ce workflows passed (41256670340/41256665387/41256665420),
including native-unwind-slice job124704049836. The earlier5ce115c E0433 failure
and previous disk/linker failure remain historical evidence, separate from the
unresolved original-Windows case19 timeout.

The newly authored Windows probe uses actual GetCommandLineA/W, GetACP and MSVC
wmain parsing under an embedded UTF-8 manifest. It launches each frozen raw string
with an explicit executable path, validates exact bytes/terminators/argv and repeat
pointer stability, and records failures before raising. Its count increments only
after a real exit0 result matches every expected field. Compilation/execution use
the existing official MSVC14.44 family; actual compiler/linker hashes, tool and SDK
versions, configuration and PE/source hashes are recorded. There is no narrower
minor-version pin than that configured family. No fresh Windows observations or
new Windows/ELF pairs are claimed before this CI job executes successfully.

The observer's synthetic unit packets are decoder/count regressions only. They
are not Windows evidence. The ten vectors were authored independently before
converter evaluation; unknown outcomes must not be changed into passing goldens.

Primary references:
- https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinea
- https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew
- https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
- https://learn.microsoft.com/en-us/windows/apps/design/globalizing/use-utf8-code-page

No formal approval, merge, release, native close/EOF equivalence or full startup/
rcedit/default/XP7 support is established by this checkpoint. Sol can review the
codec, pair rollback, process lifetime, API/IR effects and evidence harness; routine
verification does not need escalation.

## First Windows conformance observation and input-byte repair

Job124710377429 in run41259747689 at5fd86eb succeeded. Artifact13064208599
(ZIP SHA2562c9ad131c85cb50603deb49556522fe2920f9b7ee5ecc7885d85f8769ff0169f)
contains ten matched original Windows observations. Each raw stdout was independently
redecoded locally against the frozen vectors, including UTF-8/UTF-16 terminators,
Unicode confusables/non-BMP characters, quoting, actual MSVC argv and stable A/W
pointers. Host Windows20348, MSVC14.44.35207, SDK10.0.26100.0; process ACP65001.
This is API/CRT conformance, not ten converted Windows/ELF programs.

Source C and vectors matched repository bytes exactly. Windows checkout converted
the manifest to CRLF: the observed hash was
4f636b71972d4814f1f5cb3935416e76f52a74866a13149c886b3d64007ac6a3,
while the repository LF hash is
76433dcefb453be86234dacbad769bfe31eaf94606213c27ea5a5ad5b3f138c3.
The exact LF-to-CRLF transformation reproduces the observed hash; it is retained
as a distinct input-byte variant, not falsely labeled byte-identical. Attributes
now enforce LF for startup manifests. The observer archives and compiles its copied
C/manifest inputs and reads the copied vectors, so a subsequent artifact contains
the exact compiled/compared inputs. Fresh final-head conformance remains a CI gate.


## Completed local and byte-frozen Windows verification

The complete local replay passed, as did a later explicit emission with a fresh
mtime and identical Rust SHA256
`d64a6dad254c580ee56db41ef4b34e8f5a144190599d49759e46f5b7fa19abfe`.
PE remains1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4.
The five recorded Windows wrapper comparisons remain component evidence; neither
the new native API cases nor the probe observations are whole-PE translation pairs.

Follow-up job124711930713/run41260275742 at1779a18 also matched all ten cases.
Artifact13064488864 has ZIP SHA256
a883e7abacd0f62e6befc2d6563dbf1c4ea8a59dffe0cab777f99c647adc252f.
Every stdout was independently redecoded and every archived compiled C/manifest/
vector byte matched the repository and its reported hash. The observed PE is
851f578ab7ab77904dd08f163f4d6cc70e6b50d4f7cd7dc3ebd0ca4a6f52b5f7,
unchanged throughout those ten executions. The previous run used a separate PE
and remains a repeated observation of the same ten cases, not ten additional
compatibility scenarios. Both were Windows20348/MSVC14.44.35207/SDK10.0.26100.0,
with actual ACP65001, stable A/W pointers and exact Unicode/quoting/argv outcomes.

[Source, PE/Rust/report/log hashes and both Windows provenance records](evidence/command-line.json).
No new resource failure occurred; older generated binaries were archived with
round-trip hash checks before replay, preserving source and Windows diagnostics.
Historical Windows case19 remains unresolved. Final-head whole CI must be checked
separately; successful probe jobs are not a full workflow pass or merge approval.

The next original callback is locale/multibyte initialization, not yet environment
construction:40b42a stores static pointers, calls required UCRT getter40a2ef, then
40b235. Its -3 code-page selection reaches GetACP via40afbc; it must agree with the
same declared process65001 profile. Disassembly also shows an eight-byte realigned
stack frame at40b235 and locale/reference effects. Those are implementation/proof
prerequisites, not an observed decoder rejection: execution still stops before the
callback. Inventory the whole scope before implementation and preserve borrowed
PTD ownership, saved ESP/EBX, initialization/reference updates and failure cleanup.
Sol can perform review/inventory; a genuinely new aligned-frame ownership problem
may warrant bounded Astra reasoning. No Ultra, formal approval, merge or release.
