# SUB-579 startup dependency decision — in progress

The first original entry dependency is security-cookie and thread exception-record
state, not a generic heap field. No startup effect is closed by this checkpoint.
Production remains unchanged and full rcedit conversion rejects.

## Exact retained evidence

Original rcedit source commit e95698dd8d79b1da648ef70771a709d1bab0ba51; PE SHA256
ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f; artifact 12767738629 from run 40577863473.
Corrected static inventory run 40581370393 succeeds at c35f650.
The first collector missed symbolized targets and included adjacent ILT stubs;
c35f650 resolves E8/E9 displacements from bytes and stops at terminal transfers.
Three literal synthetic tests cover identity, entry offset, ambiguous/missing
disassembly and this symbolized-thunk regression. These are evidence-tool tests,
not translated-program comparisons.

Observed static sequence (preferred base 0x400000):
- Entry RVA 0x688e jumps to 0x474d2c, which calls security initialization through
  0x40891d -> 0x475c79, then jumps to 0x474ad4.
- Cookie initialization reads global 0x51c140, compares the default and high bits,
  and may call 0x475c19. That helper references GetSystemTimeAsFileTime,
  GetCurrentThreadId, GetCurrentProcessId and QueryPerformanceCounter, mixes
  their results and a stack address. Its XMM zeroing/store is also unsupported.
- 0x474ad4 enters __SEH_prolog4 via 0x402a40 -> 0x475ba0 BEFORE
  __scrt_initialize_crt. The prolog reads FS:[0], saves registers/stack words,
  XORs cookie/frame state into metadata and writes a frame-relative record
  pointer to FS:[0]. A later cleanup excerpt at 0x474c33 restores FS:[0].
- Later references include startup locking, native startup state 0x51eb38,
  initializer tables and failure paths. None are established harmless.

These are bounded excerpts. Conditional targets, indirect calls, callbacks,
loader pre-entry effects, full code/data boundaries and path feasibility are not
closed. The 12-excerpt cap is explicit. Symbol names aid interpretation; actual
relative targets derive from bytes. No copied CRT implementation is introduced.

## Corrected cohesive acceptance boundary

A useful next implementation must handle shared per-thread state and protected
encoded records together with pointer-bearing storage, rather than claiming that
HeapAlloc plus four-byte pointer writes enables this entry.

1. Bind FS base/thread identity, initial exception-chain state and stack lifetime.
   Numeric guest pointers remain numeric; owner/generation proof metadata must
   not silently replace observable bits.
2. Represent encoded pointer/scalar relations (cookie XOR frame/scope values)
   without losing provenance or permitting arbitrary integer-to-pointer casts.
   Partial writes, overlapping aliases, external calls, free/resize and unknown
   values invalidate facts conservatively.
3. Specify nondeterministic cookie inputs and API success/failure/LastError
   effects from primary contracts. Demonstrate allowed observations are invariant
   to permitted environment/address differences, or reject address-dependent
   behavior. Do not hard-code recorded entropy, IDs or a cookie.
4. Prove registration, normal cleanup and exceptional/termination boundaries.
   Ignoring FS accesses, pretending no exceptions because samples succeeded,
   or jumping to guessed main is forbidden. A normal-flow-only domain needs
   explicit justified exclusion/fail-closed behavior for every other effect.
5. Freeze independent conformance expectations, including two thread/process
   identities, stale/partial/overlapping records and exceptional paths, before
   production widening. Reserve unrelated project families. Any newly admitted
   executable requires same-PE Windows/ELF outputs and deterministic emitted Rust.
   A component model does not count as original startup translation.

Primary contracts to review before implementation:
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/security-init-cookie
- https://learn.microsoft.com/en-us/windows/win32/debug/structured-exception-handling
- https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime
- https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter

## Current execution boundary

Local shell Git/curl cannot connect to the configured proxy:8080. Environment
status reports connected, running and enforced unrestricted HTTP; no policy or
credentials were changed. Existing authorized CI downloaded and inspected the
retained artifact successfully. The workflow uses read-only Actions/contents
permissions, never executes the utility, and publishes static evidence.

This PR is an implementation work-in-progress, not ready for medium acceptance
or merge. The complete shared thread/encoded-record contract and integration
remain open. Do not mark SUB-579 Done or claim new Windows/ELF pairs.
