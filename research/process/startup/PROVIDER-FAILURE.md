# Original provider initialization failure boundary

Review of3b91f65 found the inline slots/lease limits are checked before writes,
and the typed-load iterator preserves the former single-exact-tag rule and
lifetime validation. The allocation-denial test requires successful calls and
zero attempts, with partial/displaced/multiple-tag and stale-object negatives.
The12 focused provider tests passed again. No runtime correction was indicated.

The next missing fact is failed provider initialization, independently of native
bookkeeping capacity. The authored `provider_attach.c` is compiled twice with
identical MSVC14.44 x86 /O2 /MT /LD configuration except ACCEPT_ATTACH=0/1. The
loader observer uses absolute disposable output paths and flags0x900. The DLL
exports a simple value7 control function using its compiler-generated C export;
its DllMain returns FALSE or TRUE at DLL_PROCESS_ATTACH. No third-party DLL or
user executable is modified.

Before Windows execution, `provider-failure-frozen.json` fixes source hashes,
configurations and independent expectations: two rejected loads return null and
error1114, neither leaves an acquirable module, and the control loads twice,
executes value7, survives one owned release and disappears after the final release.
The observer saves LastError immediately after each failed load, before module
queries can change it. It reports no arbitrary success LastError guarantee.

The [LoadLibraryExW primary contract](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw)
states that a FALSE initialization return causes load failure and unloading.
The [system error list](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-)
defines1114 as ERROR_DLL_INIT_FAILED. The exact1114 observation is a pinned-host
expectation, not a general mapping for every loader failure. Validation rejects
wrong errors, truthy non-Boolean lifetime fields and missing/incorrect results.

The approved existing startup workflow runs the two DLL builds and observer in
an isolated Windows2022 job, preserving source/compiler/artifact hashes, complete
commands, raw output and partial timeout diagnostics. Limits remain60s per build
and15s per process; no retry or threshold relaxation. These are original Windows
API observations, zero Windows/ELF pairs. Until CI completes they are pending,
not measurements. This change adds no callable native provider or API-set admission.

The expected failed-load namespace rollback does not imply all prior DllMain
writes, external effects or dependency loads are undone. This minimal DLL has no
such authored writes; generalized cleanup would need actual effect tracking.
Successful release observations apply only to this initially absent authored DLL,
not the resident KernelBase/ntdll hosts in the API-set probes. They cannot close
Ex allocation failure, API-set mapping/version effects, arbitrary TLS/DllMain,
concurrent initialization or actual startup failure composition.

The executable entry boundary remains LoadLibraryExW CALL0x402b00 / IAT0x415074.
Next: use the fresh result to constrain supported failed-initialization publication
and rollback, then establish the system-provider initial-state contract and
implemented exports. An uninitialized/failed provider must expose no acquisition
or callable export. Binding the real startup call still requires those effects
and its actual mapped object/index. Full startup/rcedit and historical timeout
causes remain unresolved. PR45 stays draft.

## Retained first build failure

Commit6aa46e1 run41051575029/job124048652319 failed before executing the
observer: the redundant explicit internal-name alias produced LNK2001 for
_independent_value. Artifact12974104509 is retained; its downloaded ZIP SHA256
17cd449e111b623c767d80f9587fe63adc829e489cc697f1c8ba04e9f0d14550
matched the upload report. The actual x86 COFF object independently contains
_independent_value and _DllMain@12. The correction removes the redundant alias
and uses __declspec(dllexport)'s compiler-generated directive. Original C sources
and semantic expectations are unchanged. Build failures now also print the saved
compiler/linker diagnostics to the job log. This is a build correction, not an
observed Windows initialization failure, retry success or timeout diagnosis.
