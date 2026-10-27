# Source-built independent resource utility measurement (SUB-574)

Pinned upstream: https://github.com/electron/rcedit/tree/e95698dd8d79b1da648ef70771a709d1bab0ba51 .
`source-pins.json` records exact Git blobs for the build inputs and license;
`frozen.json` fixes source, configuration, fixtures and independent expectations
before evaluation. The source remains unchanged. No converter support is added.

## License and original build

Upstream LICENSE is MIT, Copyright2013 GitHub Inc., requiring preservation of
copyright and permission notices. main.cc, rescle.h and rescle.cc explicitly refer
to that license and credit the Rescle origin where applicable. The original source
and notices are retained; LICENSE accompanies the original compiled artifact.
This is an upstream build, not a port of its implementation into the translator.
MSVC runtime/SDK components retain their separate distribution terms; the original
application license does not relicense every runtime component.

README requires CMake3.15+ and VS2015+. Upstream CMakeLists.txt sets static
`CMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded`, `/Ox /Os`, two C++ files, its RC file and
version.lib. These settings are preserved, including ATL/standard C++ dependencies.
We use the existing x86 MSVC environment with NMake and RelWithDebInfo. No source
patch, compiler-policy override or post-rejection tuning is permitted. Installed
cl/link/rc/nmake/CMake paths and hashes, compiler versions, SDK identity, exact
commands, raw source file hashes and utility PE hash are recorded before conversion.
The architecture is explicitly checked as x86. Missing build prerequisites fail
and remain reported rather than prompting a replacement toolchain or account.

## Safe frozen workloads

Eleven observations use a separate fresh copy of one independently authored
resource container per case:

- Read the known product-version string and resource string42.
- Set ProductName, a Unicode ProductName, fixed FileVersion and its string,
  resource string42, and RCDATA77.
- Missing version key, invalid version syntax, unknown option and malformed input.

The resource container is built from the supplied C/RC files; it is NEVER executed.
It contains known fixed/string versions, resource string42 and arbitrary binary
RCDATA77. Fixture paths and replacements are temporary and isolated. No user
executables, privilege-manifest options, signing, credentials, installers, drivers,
network use by the tested application or storage benchmarks are involved.

A separately authored Win32 observer uses GetFileVersionInfo/VerQueryValue,
LoadString and FindResource/LoadResource to report resource values. Its mapping uses
LOAD_LIBRARY_AS_DATAFILE plus LOAD_LIBRARY_AS_IMAGE_RESOURCE, never executing the
queried image. Expected values are literal fixture specifications, not outputs
copied from rcedit's parser. Unicode is observed as UTF16 code units to avoid host
console/codepage assumptions.

A separate bounded PE/resource snapshot records code and resource payload hashes.
Entry point, machine and executable code remain unchanged. Read/error cases must
preserve the complete file. All observed resource semantics must remain identical
except the requested field; privilege-manifest bytes must remain identical.
Resource serializers may normalize other metadata bytes; raw snapshots record
those differences without calling them semantic changes. Version/string/data
expected values and exit classes are fixed before evaluation. Original stdout/
stderr and complete resulting hashes are retained honestly.

## Measurement and interpretation

All original Windows utility observations precede converter invocation. Full
headers/imports/disassembly then accompany the unchanged source-built utility.
`w2l` conversion and `--inspect-image` are measured separately. Unexpected admission
requires review of the complete runtime/resource-effect contract, not an automatic
ELF compatibility claim. Current unsupported intake is expected to reject with an
unchanged output sentinel. Linux consumes that same original PE hash and must
agree on the conversion/inspection rejection. Zero third-party ELF execution pairs
are claimed by this measurement harness.

Reproduce in the existing Windows x86 MSVC/CMake environment:

    cargo build --locked
    python research/utilities/rcedit/measure.py RUNNER_TEMP/rcedit-corpus

Then verify the same artifact on Linux:

    cargo build --locked
    python research/utilities/rcedit/check_native.py rcedit-evidence

No genuine Windows baseline or converter outcome is claimed until these steps run.
Timed-out commands persist partial evidence and fail; there is no retry or raised
threshold. All existing authored, MSVC, LLVM and ISCC regression jobs remain required.
Eight historical original-Windows fixture timeout causes remain unresolved.

## Suite role and next capability gate

rcedit is a Windows PE-resource utility from an independent project and native
MSVC/CMake build family. It complements the Delphi/ISCmplr dependency graph measured
for ISCC and the Embarcadero-lineage WinSCP control. This is not a current Wine
failure claim, and no lack-of-Linux-port inference establishes Wine failure.
CrystalDiskMark/DiskSpd and VirtualDub remain separate reserved families.
Once a measured failure guides implementation, classify that case as development/
regression; preserve another project/runtime/dependency family for acceptance.

The complete actual build/runtime/import/control inventory must determine the next
cohesive shared capability gate. Do not convert an early section-count or header
rejection into a promise that later CRT/heap/C++/resource semantics are supported.
No app-name/hash/answer stencils, startup bypass, ordinary-CRT/general-app/PE32+
claim or kernel/driver implementation is part of this measurement.
