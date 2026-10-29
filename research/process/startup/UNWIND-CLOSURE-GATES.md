# Remaining global-unwind contract and entry-to-exit gates

This inventory follows native cleanup, conditional wrapper return and selected
caller execution. It grants no API certificate or whole-PE eligibility.

## Established within the component domain

- Original caller/wrapper/owned-handler instructions, temporary guest FS record,
  notification, finally bridge, funclet, dispatcher and cleanup bodies execute.
- Younger registration retirement requires matching handler completion and actual
  epilog exit. Source storage/context identity survives that process.
- A conditional continuation-input cut checks arguments, TargetIp, source/root,
  epoch/ticket, saved words and captured comparison; real wrapper POP/RET follows.
- A separate post-return token checks source row provenance and original selected
  caller through the unexecuted transfer call. No search-token revival is used.

## Exact missing contracts

1. **Delivery acquisition.** Tests still supply the callback CPU and716-byte
   CONTEXT object. Original Windows evidence in ENTRY-TO-EXIT.md/DISPATCH-COMPOSITION.md
   establishes distinct captured/delivery objects and ESP changes for a pinned
   run, not a complete native materialization rule for all admitted executions.
2. **Dispatcher context.** Delivery packets now admit a scoped opaque identity,
   independently tied to runtime, thread, unwind epoch and callback. Normal
   cleanup executes without observing its bits. The original nested handler
   DOES dereference it on the collided path (0x4027ea/0x4027ee); that path remains
   rejected. No dispatcher byte size/content or writable-object authority is
   inferred from a normal callback. See DISPATCHER-EFFECTS.md for the bounded
   evidence, actual instruction inventory and unresolved traversal effect.
3. **Observable API footprint.** The provider writes unwind flags2 and supplies
   contexts. Source CONTEXT preservation and exact reserved record fields are
   component restrictions, not consequences proved for arbitrary RtlUnwind.
   Microsoft's contract specifies TargetFrame/TargetIp/ReturnValue but not a full
   register/memory callback footprint. Determine the guest-observable read/write
   projection across all admitted handlers, including failure/nested paths. Do
   not demand exact reproduction of fields proven unobservable, and do not erase
   unknown fields or assume missing effects harmless.
4. **Final transfer.** The selected caller currently stops before CALL/JMP
   restoration. Bind actual selected bridge instructions, owned saved context,
   cleanup state and original landing stores to the existing continuation model.
   A callback/cut result alone cannot authorize that transfer.

## Bounded next contract pass

Astra High is warranted for items1–3 because they decide what a sound API boundary
may abstract. Sol should first review the current diff/CI and can continue item4
where existing contracts suffice. No Ultra is needed.

Acceptance for the contract pass:

- Inventory every admitted read/write of EXCEPTION_RECORD, CONTEXT and dispatcher
  context from actual code, including all callback/failure paths. Identify data
  that remains unknown and prove which fields are not observed.
- Use primary RtlUnwind/exception/context documentation plus independently authored
  original probes for a multi-frame and nested/failure case. Retain ordinary versus
  separately instrumented runs, unchanged hashes, runtime/module/load identities.
- Specify exact native object allocation, ownership, lifetime, flags and stack
  rules. Nonzero opaque identity must not become an arbitrary host pointer.
- An effect/continuation certificate must be distinct from supplied context cuts;
  missing proof rejects before PE emission. Preserve existing negative tests.
- Only after composed original entry-to-exit stdout/stderr/exit and side effects
  match on Windows/ELF may any newly admitted program be counted as translated.

Primary references already used by the original evidence:

- https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context-r2

The original incoming borrowed OS handler/loader boundary and broader startup
remain independent gates. No rcedit, ordinary CRT, XP/7 or general-app claim is
made. Retained Windows output-present/process-alive timeouts remain unexplained.
