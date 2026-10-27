# Source-built rcedit measurement

Frozen utility source/fixture/case definitions:9017c307c666a624b58de11c730b3b9eb4182277,
before any evaluation. Upstream source remains commit
e95698dd8d79b1da648ef70771a709d1bab0ba51, with original MIT/Rescle notices and
CMake static-runtime/optimization policy. No converter code changed.

## Build outcomes, without hidden failures

| Cohort | Actual result |
|---|---|
| Default MSVC2026 on Windows2025 | Source build failed: std::locale::empty absent. No PE/cases/converter run. |
| Preinstalled MSVC14.44 on Windows2025 | Source build failed: matching ATL header absent. No PE/cases/converter run. |
| Complete VS2022 toolkit on Windows2022 | Unchanged source builds; original utility and fixtures measured. |

BUILD-HISTORY.md preserves exact commits, CI/artifacts and primary-source reasons
for separate build-prerequisite cohorts. Source, optimization and all workload
expectations were unchanged; no successful binary was selected by converter
coverage. One independent observer link omission (user32.lib for LoadStringW) was
fixed without changing upstream code or fixture byte/semantic expectations.

First complete observations at e316f36/CI40527753526:
Windows artifact12744877078, Linux12744543490.
Windows Server2022 10.0.20348, MSVC14.44.35207, SDK10.0.26100.0.
Original utility SHA2563c74f74318a7280127751bff415d7dc4906beece61b59c8046f51ae9a5088b11;
authored fixture28b842386d4d11d79f9fcb4c4fdc33b30a25abd84b3eac6896b7173205222274.
These identify that exact build, not reproducibility of PE timestamps/debug data
across independent builds. Actual tool paths and five tool executable hashes,
source file hashes, commands and untouched per-run binary hashes are retained.

## Original Windows semantic results

All eleven frozen cases passed: seven success cases exit0 and four error cases
exit1. Original exact stdout/stderr, input/output hashes, Win32 observations and
resource snapshots are in report.json; no generated expected values were fitted.

| Case | Observed invariant |
|---|---|
| ProductName query | Original Product; complete input file unchanged |
| String42 query | Original Resource; complete input file unchanged |
| ProductName edit | Edited Product; all other observed values retained |
| Unicode ProductName edit | UTF16 code units for Café Ω retained exactly |
| FileVersion edit | Fixed and string value9.10.11.12; ProductVersion retained |
| String42 edit | Replaced Resource; version/RCDATA retained |
| RCDATA77 edit | Exact bytesff000102fe807f, including embedded zero |
| Missing version key | Exit1; complete file unchanged |
| Invalid version syntax | Exit1; complete file unchanged |
| Unknown option | Exit1; complete file unchanged |
| Malformed PE data | Exit1; complete malformed byte sequence unchanged |

All valid outputs retained original machine, entry and executable code bytes.
Privilege-manifest payload bytes were unchanged. The queried fixture was never
executed: upstream loads resources with DONT_RESOLVE_DLL_REFERENCES and
LOAD_LIBRARY_AS_DATAFILE; the independent observer also maps only data/resources.
Linux artifact checks verify actual original/edited fixture hashes and snapshots;
those checks are provenance/invariant verification, not native utility executions.

## Actual support boundary

The original source-built utility has nine sections:
.text/.rdata/.data/.idata/.tls/.00cfg/.fptable/.rsrc/.reloc.
Static imports include VERSION.dll, KERNEL32.dll and USER32.dll. Nonempty directory
metadata includes import/resource/relocation/debug/TLS/load-config/IAT. DLL flags
are0x8140. Static directory/import references do not prove which effects execute.

Production conversion exits1, preserves the output sentinel and reports
`only code with optional read-only data is supported`. Inspection separately
rejects at `limit: section count`. Both hosts consume the same original utility
hash. There are ZERO third-party Windows/ELF execution pairs. Raising an inspection
section cap would not establish CRT, heap, TLS, C++ exception, argument, Unicode,
resource-mapping or resource-update execution support.

## Reusable priorities and holdouts

Compared with ISCC's Delphi/ISCmplr graph, this is an unchanged native C++/MSVC
source build using existing public hosted tools. It provides a genuinely different
project/build-family baseline, not a Wine-failure claim. Feasibility is established
for the measured build/cases only. Per-component runtime rights remain separate
from the upstream MIT license when considering transformed-binary distribution.

The next capability gate should inventory shared user-mode startup/memory/ABI and
file/resource effects across independent families before selecting one cohesive
implementation slice. Do not fit nine-section admission to one binary, skip CRT
startup, substitute an implementation of rcedit, or use application names/hashes/
result stencils. Once this measured failure guides code, classify the case as
development/regression and retain a fresh whole family for acceptance. WinSCP's
Embarcadero lineage overlaps ISCC; it alone is not an independent runtime holdout.

Final-head full CI and substantive review are required before merge. All existing
streaming, source-compiler, authored and ISCC gates remain required. Eight historical
original-Windows timeouts remain unexplained; no retry or threshold change is made.
No privilege-manifest edit, user executable, driver/storage/network workload,
release/deploy or kernel/driver/general-app/XP7 support claim is part of this work.
