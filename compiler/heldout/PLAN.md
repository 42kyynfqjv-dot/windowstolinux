# SUB-527 preregistered held-out measurement

Freeze this plan, sources and cases.json in Git BEFORE adding/running converter
measurement. Eight configurations, seven original sources; x64 repeats ordinary
CRT source. Original sources MIT OR Apache-2.0. No converter imports or code changes.

Use existing GitHub windows-latest MSVC with vcvarsall x86/x64. Available compiler
version is recorded by /Bv, not falsely claimed pinned. Configuration is fixed:
cl /nologo /Bv /O2 /W4 /c SOURCE /FoNAME.obj; custom entries append /GS- /Zl;
ordinary entries append /MD. Link /nologo /machine:ARCH /subsystem:console NAME.obj
/out:NAME.exe; custom append /nodefaultlib /entry:entry@0. No import library is
needed for the four custom programs. Ordinary programs use default CRT libraries.
No flags/source/PE changes after observing rejection. Toolchain unavailable means
tooling failure, not unsupported conversion. CRT-linked binaries are authored
compiler outputs, not third-party application fixtures; toolchain runtime/startup
licenses remain applicable. No toolchain binaries/source are imported.

cases.json contains literal expected original stdout bytes, stderr, exit, argv
and side-effect files. Run each in a fresh temporary directory, regular stdout/
stderr files,15-second bound, no retries. The loop uses a volatile bound read at
runtime; arrays use volatile storage, and local buffer/structure use volatile to
retain memory effects under the frozen optimizer. They are freestanding controls
that expose instruction/data barriers apart from CRT startup. They are not ordinary
applications. args.c uses actual CRT-provided argc/argv; file.c performs a real
binary file roundtrip. No undefined arithmetic or CRLF-dependent output.

Record source, configuration, original PE SHA256, headers/imports/disassembly,
actual Windows observations before invoking converter. Rejection must preserve
output and record exact diagnostic. Linux must independently convert the same
hashed PE twice: identical rejection or identical Windows-generated Rust and
actual ELF observation/files for accepted cases. Keep original PE unchanged.
No support expansion or assumed acceptance/rejection. First rejection is not a
claim that later disassembled operations were validated/executed by the converter.

Preserve eight previous compiler programs,102 authored pairs and18 launch samples.
Modern Windows evidence does not establish XP/7 compatibility; historical timeout
causes remain unresolved. Rank next architecture work after actual measurement.
No paid toolchain/resources, security changes, merge or release.
