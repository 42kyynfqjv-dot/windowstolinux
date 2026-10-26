# SUB-514 real compiler measurement

Independently authored program.c computes helper(7,5), writes Hello (no newline),
and returns0 iff both results match. Expected raw stdout48656c6c6f, stderr empty,
exit0 is specified independently of compiler/converter output. No binary rewriting.

Two experiments use existing official Microsoft MSVC tools on windows-latest:

- Freestanding/custom-entry: /O2 /W4 /DFREESTANDING /GS- /Zl, with /NODEFAULTLIB,
  /ENTRY:_entry@0 and an import library generated from our msvcrt.def. /GS- avoids
  a CRT cookie initialization dependency in this tiny custom-entry experiment;
  /Zl and /NODEFAULTLIB explicitly exclude ordinary CRT startup. The C identifier
  write uses x86 COFF decoration to reference the DLL's _write export. This is a
  controlled legacy-import experiment, not a normal CRT-linked application.
- Ordinary CRT main: same program /O2 /W4 /MD, default CRT startup and defaults
  for security settings. It measures the much larger real startup/import surface.

/O2 is one ordinary optimized build configuration, not a search across flags for
acceptance. noinline keeps a real helper. No naked/inline assembly, hand-edited PE,
reordered instructions or disabled ASLR/relocations to fit the converter. Record
/Bv compiler versions and linker banner/options. windows-latest is an available
rolling image, not an immutable pinned toolchain: exact observed version is in
reports. Tools supplied with the existing Microsoft runner, no new download or
paid account. MSVC tools/Windows SDK are proprietary Microsoft components used
under runner terms; no toolchain/runtime DLL or binary fixture is committed.
Original fixture source/import definition/measurement scripts: MIT OR Apache-2.0.
Artifacts include JSON/text reports only, no linked CRT executable or DLL.

Primary contracts consulted:
https://learn.microsoft.com/en-us/cpp/build/reference/entry-entry-point-symbol?view=msvc-170
(stdcall entry, recommended CRT initialization),
https://learn.microsoft.com/en-us/cpp/build/reference/gs-buffer-security-check?view=msvc-170
(cookie startup requirement),
https://learn.microsoft.com/en-us/cpp/build/reference/zl-omit-default-library-name?view=msvc-170
(default-library omission). CRT semantics/restrictions are in SUB511-OUTPUT-DESIGN.md.

CI compiler-produced-windows builds both, executes each original with stdout/stderr
redirected to regular files, invokes unmodified production CLI and records its exact
acceptance or failure. dumpbin headers/imports plus freestanding authored disassembly
provide a gap inventory beyond first loader rejection. No disassembly of linked
proprietary CRT startup is redistributed. Reports are an Actions artifact and logs.
The converter is built/run on Windows here (same Rust source); if rejected, there
is no generated ELF comparison for these programs. Existing102 true native pairs
remain separate. If unexpectedly accepted, report that rather than claim native
Linux equivalence without compilation/execution there.

Reproduction: cargo build --locked on Windows; enter an MSVC x86 tools environment;
python compiler/measure.py. RUNNER_TEMP must name a writable temporary directory.
Do not interpret failure as a request to relax checks. Use observed PE metadata and
instruction/ABI gaps to choose a separately designed bounded next implementation.
