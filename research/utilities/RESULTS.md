# Initial independent utility measurement

Frozen source/configuration/expectations: commit622f07e, before evaluation.
Reviewed official Inno Setup 7.1.0 x86 package SHA256:
f9671174e0d15ba9b4f6b56564c6aed32ea8db9c3cb9bf6f2af0850fe7894f60.
Source release commit7d634620f1d1caca6c76e8398da7133153db9e7b.
Original compiler SHA256 f87212f64f08e0b57b53829c7441719cda73dffbfcfdcf851031b74ee0f9f2f8.
It was obtained through official current-user portable setup in runner temporary
storage. No generated installer was executed; no compiler binary was edited.
This is an official prebuilt-release baseline, not an independent Delphi rebuild.

Observed at67cd57c in CI40519227673, Windows artifact12740428222:

| Workload | Runs | Exit | stdout/stderr bytes | Output |
|---|---:|---:|---|---|
| minimal script | 2 | 0 | 0 / 0 | 2,097,143-byte PE, stable hash |
| all-byte payload script | 2 | 0 | 0 / 0 | 2,097,482-byte PE, stable hash |
| invalid script | 1 | 2 | 0 / 162 | none |
| invalid option | 1 | 1 | 276 / 35 | none |

Minimal output SHA2569c5fcdae0a6bc7b87c70ac5b9b2dc6f008f9dead61139efc1e54de9d882544b3;
payload output84af93f97f066910f9dd19317333787b46727b02ee1322f6095cecd41abbe946.
Repeat stability is an observation for these cases, not proof that all scripts or
compiler builds are deterministic. Exact original commands, stdout/stderr and
artifact manifests are retained in report.json. No normalized output was used.

## Actual converter and metadata boundary

Original ISCC is PE32/x86 console, 11 sections:
.text, .itext, .data, .bss, .idata, .didata, .edata, .tls, .rdata, .reloc, .rsrc.
DLL characteristics are0x8140. Imported modules include kernel32.dll, user32.dll,
oleaut32.dll, msvcrt.dll and advapi32.dll. Concrete import names include dynamic
loading, command-line access, heap allocation, exceptions and console output.
These are actual static references, not evidence all paths execute or effects close.
Section names alone do not prove an active callback or directory; use retained
headers/directories and separate startup analysis for that determination.

Current production conversion exits1 with `only code with optional read-only
data is supported` and preserves the output sentinel. Both hosts consume the same
compiler hash. This early profile rejection does not establish support for any
later instruction, initialization, heap, exception or DLL effect. Zero third-party
Windows/ELF execution comparisons have been demonstrated.

The first inspection record used the wrong CLI spelling and therefore reported
an OS file-not-found error. That record is retained as a harness failure, not a
metadata result. Correct `--inspect-image` rejects at `limit: section count`.
Final-head CI must verify the corrected invocation and same-PE result before merge.

## Complete dependency family, not a one-opcode patch

Upstream ISCC normally calls into ISCmplr.dll; ISPP and compression components
are additional dependencies. Source and actual PE inventories are complementary.
The compiler/runtime initialization, managed strings/heap, exception handling,
filesystem, dynamic loading and console/stdio surfaces exceed current execution
contracts. An unavailable licensed Delphi build environment is a reproducibility
gap. Component/Delphi runtime redistribution and translation permissions require
separate review before distributing transformed binaries; the top-level open
source application license must not be described as relicensing every runtime.

A useful next gate is one cohesive user-mode module/startup/runtime capability
inventory across development ISCC and an unrelated control, preserving whole
families for acceptance. Establish safe loader/initialization ownership and a
sound argument/file/exit observation contract before implementing any shared
subset. Raising a section limit alone cannot count as application progress.
No app-name/hash/result admission shortcuts, startup bypass or wholesale native
replacement of the compiler is authorized by this measurement.

WinSCP remains an independent Wine-working control; CrystalDiskMark/DiskSpd and
VirtualDub remain reserved families, not templates for the current implementation.
No current pinned Wine failure is claimed and no storage workload is run.
Eight historical original-Windows timeout causes remain unresolved; the newest
case and bounded pre-kill diagnostic improvement are recorded in README.md.
