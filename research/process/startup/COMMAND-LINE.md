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
