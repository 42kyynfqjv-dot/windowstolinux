# Allocator/error gate after indexed global-lock integration

This inventory concerns the unchanged authored PE used by the startup component
checks, SHA256 `1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
It is not evidence that the full CRT, rcedit, or a zero-default runtime is admitted.

## Actual code and independently required effects

| Region | Observed instructions | Remaining binding |
| --- | --- | --- |
| 40c8f0..40c901 | CALL IAT4150f8, TEST EAX, store EAX in 41d2c8, SETNE AL, RET | Actual heap acquisition/import identity and lifetime; do not turn any integer into a heap token |
| 407cf0..407d50 | count/size overflow check against ffffffe0, product, minimum physical size 1, HeapAlloc IAT415094 with flags8 and heap from41d2c8 | Full integer forms and typed heap argument/result; failure effects remain distinct from returned bits |
| 407d17..407d2b | call4071c0; if nonzero call40c9c0 with requested bytes; if nonzero retry allocation | Mutable new-mode state and arbitrary handler effects; reject unknown handler behavior, not assume mode0 |
| 4071c0..4071c7 | MOV EAX,[41ce80]; NOP; RET | Live initialized mode cell and writer/alias contract; setter4071d0 has XCHG through this cell |
| 407d40..407d4d | call407ccd; MOV [EAX],12; XOR EAX,EAX | errno accessor's thread/runtime ownership, initialization and side effects; preserve prior API/handler effects |
| 407d50..407d8a | null free skips API; otherwise HeapFree IAT415098; failure GetLastError IAT415044 then mapping407c12 and errno accessor | Exact lifetime on failed free and error mapping; do not retire allocation merely because call happened |

The descriptor constructor's current effect callback selects a typed, zeroed
allocation or null. It still replaces the calloc helper and does not prove the
listed mode, handler, errno or heap-producer paths. Indexed Enter/Leave helper
instructions now execute; OS synchronization/exception behavior is still an
explicit component effect contract. The live manager EH4 registry path does not
close exceptional delivery or collided unwind.

## Primary API requirements

- [Microsoft calloc](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/calloc?view=msvc-170)
  specifies zero initialization, ENOMEM on allocation failure/oversized request,
  and configurable new-handler behavior. A zero count or size returns nonzero-size
  storage in this implementation, but dereferencing that zero-request result is
  outside the documented usable domain. Do not infer initialized readable bytes
  for a caller that requested zero from the physical minimum allocation alone.
- [Microsoft HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)
  specifies HEAP_ZERO_MEMORY=8, stable allocation addresses until free/reallocation,
  NULL failure where exception generation is disabled, and no SetLastError on
  failure. Heap-creation flags can affect exception behavior even if this call's
  flags omit HEAP_GENERATE_EXCEPTIONS: bind the heap configuration as well.

These pages were read for contract requirements; they are not proof of the exact
pinned CRT's hidden paths. The artifact instructions govern those paths.

## Next cohesive executable scope

Connect the actual heap producer, calloc arithmetic and initialized new-mode getter
to the same owned manager path. Bind heap identity/configuration explicitly. Prove
known-zero mode only from a live state source and its effects, not a sampled run.
Bind the errno accessor to an owned thread/runtime cell and execute the original
failure store. Reject nonzero/unknown handler mode until its callback/effects are
closed; preserve earlier allocation failures and handler effects on any rejection.
Execute the original free helper only with success/failure and error side effects
accounted for. Keep zero-request dereference and unknown exception behavior out of
admission. This is a shared allocation/error scope, not new application dispatch.

Independent acceptance must cover at least: successful64*56 zeroed bytes; failed
allocation with known-zero mode and errno12; product overflow before HeapAlloc;
zero requested bytes without readable-byte authority; unknown/nonzero mode; a
retrying handler's observable mutation; failed free preserving the allocation;
successful free invalidating all aliases; stale/foreign heap and errno cells; and
unknown heap exception policy. Windows conformance observations must be labeled
separately from native component cases and from whole-PE conversion evidence.
