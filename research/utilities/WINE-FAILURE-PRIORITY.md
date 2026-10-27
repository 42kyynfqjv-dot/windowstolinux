# Wine failure priority and SUB-575 handoff

Planning checkpoint: 2026-10-27; base main
`91f8eca89a5e6dbfd009745726e85fe1b7eadb27` (reviewed PR35).
This document freezes selection and evidence rules, not application behavior or
new converter support. No Wine or candidate executable was run for this note.

## Objective and current evidence

Prioritize independently developed utilities with reproducible Wine failures to
expose shared Windows API semantics early. Retain unrelated project/dependency
families as holdouts. Do not select only utilities that already fit the converter.
No application-name/hash/result stencils, guessed main entry, or source changes to
manufacture acceptance. A useful feature failure is distinct from an application
that cannot launch, and both are distinct from incorrect benchmark measurements.

PR35 establishes an untouched MIT rcedit source build and eleven independent
original-Windows resource workloads. Its conversion still rejects; there are zero
third-party Windows/ELF execution pairs. ISCC and rcedit have not been shown to fail
under Wine. WinSCP's documented Wine support makes it a control. ISCC and WinSCP
share Embarcadero lineage and do not constitute independent runtime holdouts.

## Candidate evidence, without promoting reports to reproductions

| Candidate | Primary evidence | Current classification and next check |
| --- | --- | --- |
| WinMerge | Wine bug52350 report dated 2025-08-31: Wine10.13, fresh64-bit prefix configured as win7; compare two text files and use ShellMenu/Delete. Report lists versions including2.16.41 and a regression boundary around2.16.33. | Concrete user-mode Shell/COM feature-failure lead, not startup failure. No current Wine status, exact asset/hash/architecture, or fresh reproduction verified here. |
| CrystalDiskMark | Wine MR9809 discussion dated2025-12-21 proposes direct-I/O changes to distinguish disk from cache measurements. Reviewers dispute validation and synchronous-I/O interpretation. | Semantic-correctness lead only; not demonstrated unrunnable. No version-pinned app/Wine reproduction. No storage workload is authorized by this planning note. |
| Notepad3/grepwinNP3 | Wine bug54927 later records a fix atcdc4af0c266ce3f001f51edbaf2c6e3af2029ee7 on2025-11-15. StrFormatByteSizeEx startup failure is listed fixed in Wine8.0.2. | Exclude these stale reports as evidence of current failure. |
| Python/PyInstaller crealf failure | Upstream pywine issue73 records missing UCRT function and later says Wine10.1 implements it. | Exclude this known-fixed report; do not deliberately choose old Wine solely to claim superiority. |
| Driver/Windows-internal tools | Reports involving NDIS/kernel drivers, Windows-bundled calculator internals, or proprietary runtimes without redistribution provenance. | Outside the present user-mode/open-source candidate gate; failure is not evidence a portable API implementation is missing. |

No eligible, currently verified, completely unrunnable utility has been established
by this bounded search. That gap remains explicit. It must not idle the shared
prerequisite work supported by the unchanged utility artifacts.

WinMerge's repository contains GPLv2 license text. Before selecting an exact
artifact, pin source/release, check applicable file and dependency notices and
corresponding-source obligations. Benchmarking it does not import its source into
the MIT OR Apache-2.0 compiler; transformed-program distribution needs separate
license accounting. CrystalDiskMark's top-level MIT does not settle every component.

## Reproduction gate

1. Pin official source/release asset, architecture, SHA256 and source/license
   provenance before execution. Record exact Wine release/build/packages and host
   architecture, kernel, display backend, locale and fresh-prefix configuration.
   Historical reported Wine is a comparison; a pinned current supported Wine build
   is required for a current-failure claim. Record later fixes/status if found.
2. Use isolated disposable fixture copies and a prefix with no user files,
   credentials, broad host-drive mappings, elevated services or driver installers.
   Do not turn off host security or substitute arbitrary Windows DLLs. GUI actions
   and COM state must be recorded, not inferred from an error string alone.
3. Freeze observable Windows expectations independently before testing Wine or the
   converter. For the WinMerge lead: two tiny authored files, exact input/output
   hashes, operation selected, cancellation/aborted status and resulting filesystem
   state. A read-only query or successfully launched window is not the failed test.
4. Capture original Windows and Wine stdout/stderr/exit, application diagnostics,
   exact actions and before/after state with bounded timeouts and no hidden retries.
   Record separately: packaging/dependency failure, environment limitation,
   reproduced API/semantic defect, and inability to reproduce the historical issue.
5. Minimize a confirmed user-mode failure into an independently authored API
   contract test; retain the untouched full application as the integration target.
   A reduced test is not full application translation or a general Wine comparison.
6. Storage experiments require a separately reviewed bounded disposable-file target,
   explicit applicable authorization, alignment/filesystem/error contracts, and an
   oracle for semantics. No real disk/device/privilege benchmark follows from MR9809.

Wine is absent in this local environment. No local reproduction is claimed.
Selecting an official Wine build and isolated reproduction environment is work to
perform, not a reason to install an arbitrary image or claim the API failure proven.

## Shared capability plan and Astra High scope

SUB-575 remains one cohesive architecture decision. Incorporate the failure-oriented
track without postponing all engineering until a candidate reproduces:

- Inventory complete entry/startup, memory and external-effect dependencies of the
  exact retained rcedit/MSVC and ISCC/Delphi artifacts. Distinguish decoded/static
  references, observed execution and unproved branches. rcedit's entry reaches
  wmainCRTStartup/security_init_cookie; wmain installs an FS:[0] exception frame.
  An empty static TLS callback list does not close TLS/process-context behavior.
- Audit reusable normalized CFG, frame/ownership, solver and emitter paths. Existing
 4096-byte/32-object checked storage has no guest-VA/PE-admission authority; do not
  silently treat it as a general process address space.
- Decide checked32-bit VA mappings, stack/global/heap/TLS ownership and lifetime,
  initialization/aliases, relocations, ABI/return protection and explicit exception
  barriers. Compile faithful runtime branches and checks where justified; static
  proof of every application result/termination is not automatically required.
- Map candidate complicated APIs onto these same capabilities. For Shell/COM,
  account for interface/vtable provenance, reference-count lifetime, HRESULTs,
  deferred operation queues, flags, callback/error/cancellation effects and paths.
  Do not replace IFileOperation::DeleteItem with immediate unlink: Microsoft's
  contract says it declares work; PerformOperations executes it, and even S_OK can
  accompany cancellation, requiring GetAnyOperationsAborted.
- Define independent invalid-range/alias/uninitialized/realloc/return/exception
  traces and one bounded production prerequisite. Preserve rejection at unresolved
  startup/API effects. Do not attempt full COM/UI/CRT or kernel support in this pass.
- Keep a failure-oriented development case and untouched whole-family acceptance
  holdouts; once a failure guides code it is development/regression evidence.

Deliver a reviewable decision, concrete minimal implementation gates and objective
original-Windows/native acceptance. State remaining application blockers honestly.
Do not repeat isolated accessor probes or per-opcode PRs. Astra High is warranted
for this memory/process/effect composition; routine provenance/reproduction remains
medium. No new production implementation was performed in this planning pass.

## Sources and search limits

Exa: seven targeted searches,47 result slots (duplicates included), followed by
primary-page reads; this is bounded candidate discovery, not exhaustive coverage.
Current status and every candidate/version still require direct verification.

- [WinMerge bug52350 reported Wine10.13 reproduction](https://list.winehq.org/hyperkitty/list/wine-bugs@list.winehq.org/message/7VIJQX2RZOAOGJU3IF7XXJCQPEJXNA4D/)
- [WinMerge license text, unpinned discovery reference](https://github.com/WinMerge/winmerge/blob/master/LICENSE.md)
- [Wine MR9809 discussion, including disputed semantics](https://list.winehq.org/hyperkitty/list/wine-gitlab@list.winehq.org/thread/I2WYUECF7XHG3ZLZJWXCHEEEMTEWMBES/)
- [Microsoft DeleteItem contract](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-deleteitem)
- [Microsoft PerformOperations contract](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ifileoperation-performoperations)
- [grepwinNP3 fix report](https://list.winehq.org/hyperkitty/list/wine-bugs@list.winehq.org/message/7QHZCNOUCSHYRQHD45V7W7JBXCBNMTKQ/)
- [pywine issue73, later implementation noted](https://github.com/webcomics/pywine/issues/73)

No Wine code or test was copied. Studying patch discussions is not a clean-room
process. Any later implementation uses independently written code and tests from
documented contracts with explicit provenance. Eight historical original-Windows
timeouts remain unexplained; no threshold or retry change is made.
