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
