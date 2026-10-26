# SUB-544: external commit-mode word ownership

Decision: model the returned word as an external CRT-instance resource. A numeric
address is never authority over image state. The isolated sentinel component cannot
be composed with the actual startup callback until the accessor call's external
frame and the subsequent store's ownership are proved. Production remains blocked.

## Primary contract and exact image

Microsoft documentation, read 2026-10-26:

- https://learn.microsoft.com/en-us/cpp/c-runtime-library/p-commode : internal
  `int *__p__commode(void)` returns the address of `_commode`, controlling default
  file commit mode; global state is application-scoped by default. It is not a
  supported public application API, and this research does not make it one.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/global-state : app and OS
  CRT state are distinct. Static linking /MT isolates component state; OS-mode
  exports are another configuration. These facts do not promise one global address
  across processes, CRT instances, DLL unload/reload, or all supported Windows.
- https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/fflush : the
  commit-to-disk mode affects flush behavior. Successful buffered output alone
  cannot prove disk durability or equivalent error behavior.

The unchanged authored MSVC `held_crt` has CALL 0x16c0 at RVA0x1043; that exact
three-byte helper XOR EAX,EAX;RET returns0. MOV ESI,EAX at0x1048 preserves the value
across the cdecl accessor call at0x104a via thunk0x1d06. The thunk is FF25 through
IAT0x20a8, named api-ms-win-crt-stdio-l1-1-0.dll!__p__commode. HIGHLOW at0x1d08 binds
its address. PUSH1 at0x104f precedes MOV dword[EAX],ESI at0x1051, then CALL0x13e0.
Thus the exact store is four zero bytes, not a sentinel or a pointer copy.
`check_commode.py` checks those bytes, import identity and relocation against the
same hashed original artifact used by the prior inventory. It is a bounded research
checker, not a new hostile-input loader or complete caller proof.

A conforming cdecl callee preserves ESI; EAX carries the returned pointer, ECX/EDX
and arithmetic flags require conservative unknown state after the external call.
The following PUSH/MOV do not restore unknown flags. The sentinel's own CMP/TEST
can establish local flags, but cannot repair unknown memory or external effects.
No numeric ESP is assumed; the store must be disjoint from protected stack words.
Earlier startup imports remain additional unresolved effects.

## Resource contract

Resource identity is (process, CRT instance, load generation, object), not a stable
VA or module basename. A pointer must refer to the complete live aligned four-byte
word, with initialized mapping and write permission, disjoint from image globals,
metadata, saved registers and return words. Prior contents are not needed to perform
an overwrite; reading/restoring a prior value in probes requires initialization.
The owner retains lifetime; no freeing the returned pointer, caching across unload,
using another process's token or conflating /MD, /MT or OS-mode state is permitted.
Aliases returned by repeated calls or another thread name the same resource only
when their owner/generation is established. Per-thread storage is not assumed;
process-global is also not a substitute for identifying a particular runtime.

The model's `frame_proven=True` is explicitly a hypothetical test premise. It
specifies that the call/store has no unmodeled writes to image or other resources,
no unmodeled exception/nonreturn, and no concurrent mutation. The real accessor has
no such implemented frame proof. Default calls block, havoc tracked knowledge and
leave a sticky blocker. A later observed success cannot clear it. Unknown/null,
misaligned, out-of-range, expired, cross-owner and fractional address inputs reject.
An external call can mutate errno/TLS or other state even if it returns the expected
pointer: those effects remain unclosed. No model result grants emission eligibility.

## Independent probes and limits

An authored C program is built /W4 /WX /O2 once with /MD and once with /MT. Two fresh
processes per build record the returned address, repeated address, worker-thread
address, owner module base/path and initial/observed/restored word. Before touching
it, VirtualQuery checks committed writable full-word backing and GetModuleHandleEx
locates the owning loaded image. Main writes0, calls the accessor again, then joins
one worker that reads it; it restores the initial word before output. No invalid
pointer is passed to the runtime and no racing main/worker access is intended.
Timeout terminates the isolated process (its private state dies with it); normal
error paths restore state after worker completion. The outer harness has a bounded
15-second launch and no retry. This is internal-interface research in a separate
program after ordinary CRT startup, not observation inside the original callback.

Preregistered hypotheses: each process's repeated/worker pointers agree; observed
values are0; restoration matches its original value; /MD ownership resolves to
ucrtbase.dll while /MT resolves to the probe image. The checker retains raw output,
exit, source/probe/original hashes, each owner path/base and on-disk version/hash.
It does not require addresses to match across processes or infer that differing
processes share storage when their VAs happen to match. An empty executable file
version is permitted for authored /MT probes; runtime /MD version is required.
No OS-mode, multiple loaded CRTs, concurrent mutation, unload/reload, allocation
failure, abnormal return or actual startup instrumentation is claimed.

Eight model functions independently specify literal zero bytes, wrong owners,
stale generations, full bounds, scalar-versus-pointer confusion and sticky unknown
effects. They are synthetic premises, separate from four process observations and
from the existing twelve compiler translations. The CPU/option/sentinel/lifecycle
checks remain unchanged. Windows Server2025 observations establish no XP/7 support;
three historical original-fixture timeout causes remain unresolved.

## Smallest implementation gate

After medium review, implement only a research owned external-cell effect with
private lifetime-bound capabilities, explicit CRT-instance and generation identity,
full scalar bounds, zero-store behavior and conservative volatile state. Bind exact
caller/import provenance; an opaque returned address cannot construct a capability.
Test non-image ownership, alias equality under the same owner, stale/cross-owner
rejection and failure without mutation. Keep a separate unproven accessor frame;
no automatic composition into the sentinel or ordinary CRT acceptance. A genuine
next closure requires a justified accessor effect contract, plus earlier startup
and later exit-registration effects; more successful probes alone cannot supply it.

No Wine/Microsoft implementation source was imported. Authored sources and model
use the project's MIT OR Apache-2.0 policy.

Initial CI 40368889099 failed before probe execution because a redundant accessor
declaration conflicted with the SDK stdio.h DLL linkage (C4273 under /WX). The
probe now uses the existing SDK declaration; warnings remain errors. This diagnosed
build failure is separate from the historical process timeouts.
