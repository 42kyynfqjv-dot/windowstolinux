# Cold resolver: measured ownership and publication gate

The cached path remains implemented; cold resolution and dynamic FLS invocation
remain rejected. This document records a code-level integration boundary, not a
claim of module loading or new application compatibility.

## New reproducible evidence

The artifact checker binds the entire160-byte original resolver402a53..402af3,
75-byte load helper402af3..402b3e, and module API import identities. A Rust test
independently decodes their calls and memory exchanges. The current shared IR
rejects all four memory XCHG instructions; the test preserves that barrier:

| Address | Original effect |
| --- | --- |
| 402ab7 | publish failed module lookup (-1), receive old module-cache value |
| 402ac4 | publish failed function lookup (-1), receive old function-cache value |
| 402acf | publish loaded module, receive old cache value |
| 402aef | publish resolved function, receive old function-cache value |

The resolver calls FreeLibrary41506c and GetProcAddress415070. The load helper
calls LoadLibraryExW415074 with flags800, then GetLastError415044 on failure.
Error87 enters original prefix comparison4078e0 before a possible flags0 retry.
That comparison and loader effects must be closed, not guessed from sample names.
The module-name table415c80 references api-ms-win-core-fibers-l1-1-1,
api-ms-win-core-synch-l1-2-0 and kernel32. The actual dynamic function request is
FlsGetValue; the static fallback remains TlsGetValue. This is not UCRT slot state.

A successful module publication racing with an already populated cache has a
FreeLibrary path. Numeric HMODULE equality alone does not prove ownership of the
same acquired reference. Nor does a function-address scalar prove that its module
remains loaded. The current CrtValue domain has no module/function lifetime
capabilities, and CrtStreamRuntime Module storage is not a module-loader object.
Adding a call target or a plain scalar XCHG would leave these obligations open.

## Reviewed defect fixed before this integration

An explicit backend callback could mutate captured ESP to a scalar/foreign stack,
or retire the Context object, after its initial validation. The original tested
normal-disposition path then returned despite stale capture state. A pre-fix
native regression failed. The dispatcher now rechecks the captured context after
PTD/backend return and before continuing its branches. All three cases reject
while retaining prior writes. The retirement case also reconstructs a new object
at the same guest address, preserving the distinction between address and lifetime.
This is protection around the component's explicit API-effect cut; it is not
proof of original Windows delivery or arbitrary DLL callback effects.

## Cohesive next implementation scope (bounded Astra High)

1. Define shared process/module acquisition references and exported-function
   capabilities, including runtime identity, module generation, symbol/backend,
   live acquired references and invalidation. Map guest numeric values to checked
   authority; never invoke host addresses or treat arbitrary integers as functions.
2. Bind a documented built-in module/API subset. LoadLibraryExW, GetProcAddress,
   FreeLibrary and dynamic FlsGetValue require exact success/error and lifecycle
   contracts. Unknown modules/exports reject. Real DLL initialization/TLS callbacks
   cannot be assumed harmless or removed from observable effects. Retain the
   original flags800/error87/prefix/retry decision and compare helper instructions.
3. Add full-word memory XCHG semantics under a reviewed atomic or explicit
   exclusive-initialization contract. Preserve read-before-write, old value,
   unchanged flags, ownership, publication ordering and earlier effects on later
   failure. A single-thread component is not evidence that shared cache writes
   can ignore concurrency or module-reference cleanup.
4. Execute the original cold resolver/load helper and lookup wrapper through the
   new contracts into the existing PTD/dispatcher path. Prove cache ownership on
   reuse and reject stale functions after unload/reload, wrong runtime, alias or
   incomplete initialization. Keep TLS and FLS index/thread/fiber lifetimes distinct.
5. Test fresh cache, module/lookup failures, unknown errors, fallback decisions,
   duplicate acquisition/publication, losing-reference cleanup, stale function
   reuse, foreign runtime, changed code and callback mutation/failure. Couple tests
   to original instructions. New Windows observations remain necessary for new
   differential claims; existing recorded boundaries are not cold-loader evidence.

Primary contracts to apply during implementation are Microsoft Learn
[LoadLibraryExW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw),
[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress),
[FreeLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-freelibrary),
and [FlsGetValue](https://learn.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsgetvalue),
plus the x86 instruction contract for implicitly locked memory XCHG. These links
are contract requirements, not a claim that every loader behavior is closed.

Astra is justified for the connected module/function lifetime and publication
contract; Sol can review and run routine evidence afterward. This does not call
for another sequence of isolated accessor models. Unwind/termination, original
startup, rcedit, ordinary CRT and historical Windows timeouts remain unresolved.
