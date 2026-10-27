# Independent utility families (SUB-573)

This phase freezes independent project families before implementation and measures
an unchanged third-party Windows compiler. It adds no converter semantics.
`frozen.json` reserves whole development/control/acceptance families. Source and
binary hashes are harness provenance only; application names/hashes/results must
never influence translator admission or emitted program behavior.

## Development: Inno Setup ISCC

Official release 7.1.0 x86, tag is-7_1_0, source commit
7d634620f1d1caca6c76e8398da7133153db9e7b. `package.json` pins the official GitHub
release asset and published SHA256. The downloaded package is an installer,
not ISCC.exe itself. Local inspection confirmed PE32/x86 and its digest; it was
not executed locally. The Windows job runs only this recognized official setup
in current-user portable mode, in a fresh RUNNER_TEMP directory. It disables
icons, tasks/file associations and restart. Upstream `isportable.iss` makes it
non-uninstallable in portable mode; `setup.iss` gates file associations and GUI
launch on tasks/postinstall skipifsilent. No generated installer is executed.

Primary license: https://github.com/jrsoftware/issrc/blob/7d634620f1d1caca6c76e8398da7133153db9e7b/license.txt
permits use, modification and redistribution for any purpose, retaining source
notices/conditions and binary copyright/site notices, crediting original origin
and labeling modifications. Original package and compiler resources are untouched;
its license accompanies the compiler artifact. This does not relicense the
converter. Upstream notes exceptions/components; no third-party implementation
source is imported. The artifact contains ISCC.exe and notices, not the entire
set of third-party libraries; the full portable payload is inventoried by hash.

A source rebuild requires licensed Delphi (upstream documents 12.3 Athens with
May Patch and GetIt dependencies). Community Edition lacks command-line builds.
No licensed build environment exists locally. This experiment uses the official
prebuilt distribution; it must not be called independently source-rebuilt.

ISCC is a console front end, not a standalone compiler implementation: the normal
source loads ISCmplr.dll; compiler/preprocessor and compression dependencies are
separate. Delphi runtime initialization, UTF16 strings, managed memory, exception
handling, dynamic loading, filesystem/path and output formatting are potential
shared capability surfaces. These source references are not measured imports
or runtime closure. Headers/imports and full ISCC/ISCmplr/ISPP disassembly are
retained from the actual original package before converter evaluation.

## Frozen workload and observations

The fixtures compile an empty harmless installer description and one containing
all 256 byte values as payload, twice each. Neither installer is launched. Invalid
script and unknown option cases fix expected exit classes 2 and 1 respectively.
All fixture byte hashes and argument forms are frozen before Windows execution.
Success requires a generated PE artifact; failure must produce none. Exact
stdout/stderr/output hashes are recorded, not invented. Repeated output hashes
are compared to expose timestamps or other nondeterminism without stripping bytes.
If outputs differ, future equivalence requires an explicit observation/time
contract; no silent normalization is introduced here.

All six original observations complete before conversion. Then `w2l` intake and
`inspect-image` are measured separately; neither compilation nor inspection is
translation. Admission is deliberately expected to reject this currently
unsupported dependency graph. Unexpected admission fails for review. Linux must
consume the same original compiler hash, agree on the rejection diagnostic and
preserve its output sentinel. There are zero ISCC Windows/ELF execution pairs.

Reproduce in the existing Windows hosted-runner/MSVC environment:

    cargo build --locked
    python research/utilities/prepare.py RUNNER_TEMP/utility-corpus
    python research/utilities/measure.py RUNNER_TEMP/utility-corpus

On Linux, download that exact artifact and run:

    cargo build --locked
    python research/utilities/check_native.py utility-evidence

Preparation is limited to temporary tool storage. No credentials, signing,
network transfers, storage benchmarks, driver installers, system security changes,
startup skipping, source edits or support expansion are part of this measurement.
Timeouts retain stage/command and partial output and fail without automatic retry.

## Control and reserved families

WinSCP source pin 246bbd42342c4443bd9ff806e91dc0bca9f83869; its license.txt
contains GPL v3 and separate icon terms. Its readme identifies C++Builder 11
Professional, VS2022 tools, NASM and objconv build requirements, and PuTTY/FileZilla/
other library components. These are genuine dependency/license review gates.
Official Wine support makes WinSCP a control, not a Wine-failure claim. No network
credentials or transfers are exercised in this phase; no WinSCP binary is run.
Do not treat its Inno Setup deployment scripts as an independent Inno family.

CrystalDiskMark's official license page states MIT; DiskSpd and CrystalDiskMark
are related and reserved together. The direct/synchronous-I/O Wine MR9809 lead
is not a current pinned-version reproduction. No storage test is authorized:
eventual benchmarking requires an explicitly authorized disposable scratch target
and a caching/durability contract, never user disks. VirtualDub is a reserved
GUI/media family; exact source/version and per-file licenses must be pinned before
activation. No native Linux port is not proof of Wine failure. xxd already has a
Linux port and remains only a possible portability control.

Reserved families are not used to design application-specific fixes. Once a
reserved failure guides code, reclassify that case as development/regression and
retain a fresh family for acceptance. First measure actual feasibility; select
one cohesive reusable loader/runtime/memory/API prerequisite from the complete
inventory. No kernel/driver, ordinary CRT, PE32+, general-app or XP/7 support claim.

## Initial CI findings (preserved history)

Run40518168120 at frozen commit622f07e prepared the official portable payload,
then stopped before compiler observations because Git's Windows checkout changed
`.iss` LF bytes to CRLF. Explicit eol=lf preserves the original preregistered bytes;
fixture contents, hashes, command configurations and converter support are unchanged.
No baseline is claimed from this failed preflight. Original ISCC.exe from that
artifact has SHA256 f87212f64f08e0b57b53829c7441719cda73dffbfcfdcf851031b74ee0f9f2f8.
Local intake of the untouched compiler rejects with `only code with optional
read-only data is supported`; the output sentinel remains intact. This is a layout
profile rejection, not evidence that subsequent Delphi/DLL/runtime semantics work.

The same run preserved an eighth original-Windows timeout in authored corpus case2:
PE31f21dbf8b0d49740b2f7379d84775eeb4cb457b298aae5f2e5fa8b6fe18b797,
full expected stdout433032, empty stderr, poll=None after15.0085seconds;
spawn0.00876seconds, killed exit1. Server2025 image20261021.278.1/Python3.12.10.
Artifact12739229930 retains program/launch/stdout/stderr. The varying fixture and
full-output/live-process pattern does not prove a common cause. Loader-thread or
entry-return hypotheses remain unverified. Earlier seven causes remain unresolved.
The launch harness now attempts a bounded, read-only owned-child process/thread
snapshot BEFORE kill on future failures; diagnostic failure is recorded. This
keeps the15second failure threshold and introduces no retries or timeout suppression.
