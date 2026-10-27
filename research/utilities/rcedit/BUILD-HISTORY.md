# Preserved compiler compatibility experiment

The preregistered initial build at9017c307c666a624b58de11c730b3b9eb4182277,
CI40525008904, failed BEFORE producing rcedit.exe or running any workload/converter.
Artifact12742948966 retains the report and complete command outputs. Upstream
rescle.cc line88 calls std::locale::empty(); the existing default MSVC2026 STL
reports C2039/C3861 because that member is absent. This is neither an application
execution failure nor a converter rejection, and no semantic expectation was fitted.

The exact runner image's published primary-source software inventory lists an
already installed older x86/x64 toolset:
https://github.com/actions/runner-images/blob/win25-vs2026/20261021.278/images/windows/Windows2025-VS2026-Readme.md
component Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64.
Microsoft's STL vs-2022-17.14 xlocale blob77c8d1b4c9b075e660c2b8f2a1d19d458114361a
still declares the nonstandard locale::empty function (deprecated, ABI-compatible):
https://github.com/microsoft/STL/blob/vs-2022-17.14/stl/inc/xlocale .

A separately registered compatibility build selects existing MSVC14.44 through
vcvarsall.bat x86 -vcvars_ver=14.44. It records actual tool directory/hash/version
and rejects another toolset. The upstream README permits VS2015 and above.
Upstream commit, all source bytes, original CMake static-runtime/optimization
policy, configuration, fixture hashes, eleven cases and independent expectations
remain unchanged. Nothing is installed, no source is patched and no compiler flag
is introduced to hide unsupported converter behavior. The converter has not yet
been evaluated for either build at this registration point.

The first failed cohort remains part of the results even if this build succeeds.
A missing older component or another compiler incompatibility must be reported;
there is no automatic source edit, alternate compiler or success fallback.

The separately registered14.44 cohort at397ebd2/CI40526142134 selected the expected
compiler14.44.35207, but failed BEFORE a PE or observations because its matching
ATL headers were absent: rescle.cc:11, C1083 atlstr.h. Artifact12744446792 records
that failure. The source was not changed, and no utility or converter ran.
Actual installed tool directories were14.29.30133,14.44.35207 and14.51.36231.
The older compiler alone was not a complete compatible SDK environment.

The existing GitHub Windows2022 image publishes a complete VS2022 17.14 toolkit,
including VC.Tools.x86.x64, VC.ATL and VC.ATLMFC components17.14.36510.44:
https://github.com/actions/runner-images/blob/main/images/windows/Windows2022-Readme.md
(read as image20261022.344.1). A third cohort is registered using that normal hosted
image and the same14.44 compiler family, without installing any component. Source,
CMake policy, optimization, configuration and eleven expectations remain unchanged.
The actual image/tool binaries and SDK versions are recorded before building;
hosted image labels are maintained by the provider, not immutable version selectors.
This is a build-prerequisite comparison, not selection based on converter results:
neither earlier cohort produced a binary for converter evaluation. Both failures
remain outcomes, even if the complete toolkit works. No automatic fallback is used.
