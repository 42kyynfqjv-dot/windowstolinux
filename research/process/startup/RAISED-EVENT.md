# Owned software exception event

This is the bounded `RaiseException` integration contract for PR #45 / SUB-579.
It extends the [original dispatcher composition](DISPATCH-COMPOSITION.md), not
ordinary CRT startup or whole-PE admission. The initial process interception
state, pre-Main startup, and later CRT exit remain outside the proof.

## Original call and event ownership

The retained authored program pushes four arguments and executes the imported
call at `0x401117`: code `0xe0424242`, flags `0`, count `0`, and a null argument
pointer. The instruction-derived return address is `0x40111d`. These addresses
identify the evidence; the compiler binds decoded instructions, operands and
import provenance rather than recognizing application names or hashes.

This experimental component API receives byte regions and a bound IAT address;
it is not a PE import resolver. Its provider must establish that the cell names
the documented API in the same unchanged image. The evidence harness checks the
PE import directory independently before constructing the manifest. Numeric
address equality alone does not grant API identity or whole-image admission.

The first admitted API class is a synchronous, continuable software exception
with no parameters. The event is created from a verified live call activation,
the complete initialized argument range, and the bound imported target. A
private owner and fresh event generation prevent foreign, stale or replayed
events from authorizing handler execution. Each handler borrows the same event's
captured context; its borrow does not create a different processor snapshot.

`RaiseException` returns no value, but it is not universally nonreturning. A
filter can request continuation. This slice instead requires proof of an owned
positive handler selection before emission. That nonlocal transfer abandons the
original call continuation. Negative-filter continuation, an unhandled event,
noncontinuable flags, parameter arrays, nested raises and unknown interception
effects remain outside this slice.

## Captured context is not call-site state

Three authorities remain separate:

1. The guest call-site state owns the original argument words, stack activation
   and protected return continuation.
2. The event owns its exception record and the lifetime of the captured context.
3. The selected landing constructs its own restoration context in owned storage.

Windows describes `CONTEXT` as processor state when the exception occurs. It
does not promise equality with registers before the API call, or that captured
EIP equals the call's return address. The native component must not populate
unobserved fields using call-site values or zeroes.

For this admitted code, filters observe the exception code. The original context
helper observes only captured ESP relative to the same thread's stack bounds,
unless its runtime selector bypasses those comparisons. The private
`CapturedContext` therefore exposes only:

- `preflight(owner)` for live event and thread ownership;
- `captured_below_limit(owner)`;
- `captured_at_most_base(owner)`.

Under the explicitly admitted valid-stack, fault-free capture domain, the two
predicates are false and true respectively. No numeric captured ESP is selected
as a substitute. Raw context-field access, context mutation, pointer escape and
cross-event reuse require another contract and reject here. The valid capture
premise is not a claim about arbitrary Windows stack state or the internal stack
consumption of every `RaiseException` implementation.

`ContextCheckProof::projection_body()` lowers the same decoded decision tree as
the numeric component helper: runtime selector test, lower-bound comparison,
upper-bound comparison, and the original failure edge. It uses the capability
methods and checks ownership even on the selector-bypass path. Its tests use an
adversarial provider to check all predicate outcomes and query order; that test
provider is not production authority for creating a valid event.

## Dispatch and failure boundaries

The existing original handler, local-unwind, cleanup, notification, selected
transfer and restoration proofs remain required. Exception records and context
borrows expire at the defined event transfer/completion boundary; retaining a
pointer is not permission to access expired storage. Any later copy needs its
own initialized storage and lifetime proof.

Debugger first-chance handling, vectored handlers and other external callbacks
can affect an exception before ordinary frame handling. Their absence or closed
effects remain an explicit process-context requirement. An owned FS chain or one
successful observation cannot establish that requirement. Unproved secondary,
asynchronous, nested or collided exception behavior is not silently discarded.

The exception code is taken from the original call. Microsoft's note about
clearing reserved bit 28 **before displaying a message** does not authorize
silently masking the record's code. Unknown system flags and unavailable record
fields are not filled with guessed values.

## Evidence gates

Acceptance requires original-byte/import binding, independent argument and
owner/lifetime negatives, both context-selector paths, rejection of unavailable
context fields, and preservation of cleanup, notification and selected-transfer
results. Windows and Linux component runs must use the same original PE and
generated source. Ordinary Windows baseline, instrumented observation, native
component runs and whole-PE translation counts remain distinct.

Existing observer snapshots contain the handler's current registers and a
context pointer. They are not observations of the pointed-to captured registers.
No additional ten-register probe is needed for the narrow predicate projection.
If capture evidence is extended, named `ContextFlags`/`Esp`, parameter count and
pre-call SP should be recorded without an equality oracle; a sample does not
prove universal stack consumption or absent external effects.

## Reproduction and reviewed checkpoint

Use `cargo test --locked --example frame_unwind` for the production proof and
emitted-runtime checks. The reviewed invocation change adds 16 test functions to
the previous 120 (136 total); the separate root suite retains 175. The new tests
cover call facts, unknown register authority, predicate lowering, event issuance,
scratch bounds and stale context/owner transitions. Imported test suites are not
counted as additional independent cases.

Run `check_raised.py ORIGINAL FRAME_COMPILER --output DIRECTORY`. It extracts the
unchanged original bytes/import binding and runs 15 inherited positive component
scenarios, seven runtime-boundary rejections and eight compile-time mutations.
Five compile mutations are inherited dispatcher checks; three alter the original
RaiseException arguments. Local execution against a retained Windows baseline is
not fresh cross-host evidence. The workflow runs the checker on both hosts and
requires identical original PE, generated Rust and harness hashes before reporting
cross-host agreement. Whole-PE translation pairs remain zero.

The older connected and dispatched modes remain regression gates. Their local
checks retain 15 positive scenarios each, rather than creating new Windows
observations. Historical Windows timeouts remain unresolved; neither timeouts nor
retry policy changed in this work.

## Primary contracts

- [RaiseException](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raiseexception)
- [EXCEPTION_RECORD](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record)
- [EXCEPTION_POINTERS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_pointers)
- [x86 CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context-r2)
- [GetExceptionInformation](https://learn.microsoft.com/en-us/windows/win32/debug/getexceptioninformation)
- [Frame-based exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/frame-based-exception-handling)
- [Vectored exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling)

These contracts are independently implemented. No proprietary handler source or
Wine source is imported, and no universal context, XP/7 or utility-compatibility
claim follows from this component.
