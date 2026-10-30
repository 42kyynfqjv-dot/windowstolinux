# Checked acquisition of an established resident DLL

The original load helper at 0x402af3 can now call a checked native Rust loader
for an explicitly established resident ordinary DLL. The code acquires another
owned reference through the existing module generation/reference table. It
executes no host library and accepts no per-call success Boolean. GetProcAddress
and FreeLibrary remain their existing separate contracts.

The environment binding is an explicit component premise: ordinary resident
DLLs whose initialization is already established, with no package, SxS or .local
redirection. It does not prove that original startup loaded or initialized them.
It accepts bounded ASCII basenames, case-insensitive identity and the documented
implicit .dll extension, reserved argument zero, and flags zero or
LOAD_LIBRARY_SEARCH_SYSTEM32. Paths, executable images, other flags, API-set
names and missing resident authority reject. A missing binding does not prove
ERROR_MOD_NOT_FOUND: search or first-load effects remain unknown. Ambiguous
basenames reject both at binding and after later module-table changes.

Every acquisition checks the runtime, initialization and original module
lifetime. Unloading and reusing the same numeric handle cannot revive the
binding or an old export. Successful acquisition invalidates LastError knowledge;
failed validation changes neither reference counts nor LastError. Acquired
references remain live until the existing release contract consumes them.
The original mapped helper and loader adapter retain protected calls, live code
checks and the reviewed post-effect image-lifetime check.

Four original-helper cases execute the unchanged helper with a canonical
kernel32 name pointer: established resident acquisition, missing environment,
stale resident module and changed original code. The independent lifecycle test
uses an unrelated DLL and export and checks case/extension handling, reference
increments, stale exports, duplicate basenames, changed module tables, foreign
runtime identity and unsupported paths/flags/API sets. These are native
component tests, not new Windows observations or whole-PE conversion.

The first actual entry boundary remains LoadLibraryExW at CALL 0x402b00,
IAT 0x415074. Its first request names api-ms-win-core-synch-l1-2-0. No existing
resident ordinary-DLL binding establishes API-set mapping, host-module selection
or its initialization effects, so the default entry keeps rejecting there.
Actual FLS publication and full startup/rcedit remain unsupported. The next
semantic gate is a justified process system-module/API-set namespace backed by
implemented native API contracts and lifecycle effects; arbitrary .so lookup or
invented successful module tokens cannot close it. A bounded Astra High design
pass is warranted for that gate. Sol can review this implementation and CI.

Review of 8edb01a retained its strict stale-code regression and process-index
versus stationary-fiber ownership tests. Its three CI workflows were still
running at the initial review. The new tests initially had a Rust temporary
borrow error, then an ambiguous short code-prefix locator; the locator now
binds the complete original helper bytes. Logs are preserved. Historical
original-Windows timeout causes remain unresolved.

Validation and hashes are in
[evidence/resident-loader-review.json](evidence/resident-loader-review.json).
The replay retains five recorded Windows component comparisons and adds zero
Windows pairs. No general loader, CRT, XP/7 or application support is claimed.

Primary contract: [LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw), retrieved 2026-10-30. The documented loaded-module basename rule, ambiguity, default extension, flags and search behavior motivate the bounded resident domain. The environment's already-completed initialization remains an explicit premise, not a fact inferred from that documentation.

[LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw), retrieved 2026-10-30, explicitly limits DLL_PROCESS_ATTACH to a DLL not already loaded. The supported component environment must establish that resident/initialized condition; this code cannot infer it from a handle alone.
