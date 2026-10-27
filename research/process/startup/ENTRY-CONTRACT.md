# Decision: a semantic process-entry boundary, not a loader implementation clone

SUB-579 / PR45 remains incomplete. This decision narrows the original-entry
dependency using actual evidence and documented observables. It does not enable
ordinary startup, supply an empty incoming chain, or count component tests as PE
translation. Production rejection stays in place.

## Identity established, symbol and effects not inferred

At commit 853146d8da5ffa027eaafe203a07a2b9f9ff8080, startup workflow 40598163347,
job 122519267246 stopped the same retained rcedit PE before its entry instruction.
`entry-module-observed.json` records the report. The first incoming handler is in
the actual LOAD_DLL file `C:\Windows\SysWOW64\ntdll.dll`:

- x86 machine 0x14c, file version 10.0.20348.5756, SizeOfImage 0x1aa000;
- file SHA256 1e78588dcb44d47c1656f9f6eab8ab5beb5279959bcebf74c0f869d8d1c73322;
- handler RVA 0x7c630; **no exact named export**, private symbol unresolved;
- file machine/timestamp/image size match headers read from the mapped image.

The file path comes from its debug-event file handle, not a guessed System32
path. Hashing that file does not establish byte-for-byte identity of every loaded
page. No runtime implementation bytes or PDB are redistributed. Exact export
matching deliberately does not label an interior/private address using a nearby
symbol. The report supplies provenance, not an implementation dispatch key.

The observer temporarily patches one entry byte in its owned child, restores it
and terminates before the utility workload. It runs under a debugger. This is
not evidence that an ordinary process has identical dispatch behavior. The
retained ordinary utility baseline and file hash remain unchanged. The rest of
the incoming chain and the private handler's exact effects remain unproved.

## What the guest can observe

Microsoft's [exception dispatch contract](https://learn.microsoft.com/en-us/windows/win32/debug/exception-dispatching)
specifies saved context/exception information, inner-to-outer frame search and
debugger/default handling when frames do not handle the event. Resumption of a
noncontinuable event creates another exception. These are semantic requirements,
not a promise of a particular ntdll frame layout or private symbol.

[SetUnhandledExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter)
changes the process-wide top-level callback, runs it on the faulting thread when
not debugged, and permits it to modify continuation state. Its return values
include resume, search and handler selection. [UnhandledExceptionFilter](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-unhandledexceptionfilter)
has debugger/error-mode-dependent behavior and is used during process/thread
creation. Neither document identifies our private handler as that API.

[RtlUnwind](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind)
distinguishes a target frame/continuation from exit unwind and specifies the
integer return register. [Nested handler semantics](https://learn.microsoft.com/en-us/windows/win32/debug/using-an-exception-handler)
require intervening termination code before transfer to a selected handler.
These contracts justify implementing native effects, while retaining the actual
application's filters, cleanup instructions, context changes and notification
writes. Copying the loader's implementation is not required by these contracts.

## Selected architecture and explicit proof boundary

Represent the incoming environment as a **borrowed root capability**, scoped to
one process/thread generation and the enclosing entry activation. It is distinct
from the end-of-chain sentinel and from application-owned registration storage.
Original prolog/epilog may copy, retain, compare for identity and restore this
predecessor through validated operations. Numeric address equality alone cannot
mint it. Its lifetime encloses every application registration that points to it.
Identity comparison means an established relationship between preserved values;
it does not justify comparison with an arbitrary literal, ordering, or a claim
that every Windows entry has the same nonempty chain. Those observations require
their own contract. Root normal-return/exit effects also require explicit binding;
finishing an application activation cannot silently retire the incoming frames.

For the first integrated handler path, admit only a proved **application-contained
exception domain**. This allows actual faults, filters, resume and unwind; it is
not a blanket assumption that exceptions never happen. Every admitted event and
filter/cleanup effect must remain inside validated application activations or
terminate through an already bound explicit termination API. To justify opacity:

1. Root identity cannot escape to arbitrary loads/stores, arithmetic, native
   calls, application callbacks or an indirect code transfer. Any such use needs
   a separately proved layout/effect contract and otherwise blocks conversion.
2. Search is proved to select an application handler or validated continuation
   before reaching the borrowed root, for all admitted event classes and inputs.
   A sample where the root was not reached does not establish this obligation.
3. Targeted unwind executes required inner cleanup scopes while live and stops
   at a validated application activation. Exit unwind, target outside the entry
   activation, nested/collided effects or cleanup faults need explicit closure;
   none may be silently mapped to ordinary return or ignored.
4. Restored CONTEXT fields, stack/frame generation, target boundary and
   continuability are checked by the shared proof and emitted transition. Unknown
   fields stay unknown. Full saved context is not the current six-register helper
   frame. Root restoration is not permission to retire the loader's frame.
5. Host signals, debugger interaction, vectored handlers and asynchronous effects
   are outside this first domain. Declare that environment restriction and reject
   guest operations introducing those effects. Do not claim universal Windows
   exception equivalence or treat the instrumented entry run as its baseline.

The root is thus a preserved boundary value, not a hand-written replacement for
the application handler. Native code still follows compiled original instructions.
Induction over admitted transitions must show that the external handler is never
invoked and its storage is never inspected. Under those obligations, the private
symbol, numeric ASLR address, chain length and host loader's frame allocation are
unobservable to the admitted program. They need not delay this bounded integration.
The obligations have **not yet been established for rcedit**.

## Reaching the root is a different capability, not silent termination

If an event can cross the boundary, conversion remains unsupported until a native
process-level dispatch contract is composed. That contract must cover top-level
callback registration/replacement and previous callback identity, thread/context
lifetime, resume/search/handler outcomes, recursive faults, terminal status and
any observable exit actions. Default UI/debugger behavior cannot be replaced with
exit125 and described as equivalent. A Windows DWORD exception exit is not an
equivalent POSIX eight-bit exit code merely because the low byte matches.

`root_probe.c` independently freezes three observations in `root-frozen.json`:
top-level callback resumes (`TR`,0), callback explicitly terminates (`T`,37), and
an inner frame handles the event without reaching that callback (`FH`,0). The
ordinary uninstrumented Windows executions are separate from original-entry
metadata and existing VR/IOFH probes. They test observable contract distinctions,
not private ntdll identity or complete effect closure. The source and expectations
are committed before execution. No new translated pair is claimed.

At commit d4aea434c0ff7591a270136a6c5f538fc366a29b, dedicated workflow
[40598659445](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40598659445)
passed both jobs. Windows job 122520935321 observed all three frozen outcomes,
with empty stderr, on Windows Server 2022 10.0.20348. The exact source/compiler/
PE hashes and outputs are in `root-observed.json`; the workflow retains the
unchanged executed PE and per-launch diagnostics in artifact 12776469490.
The previous five SEH and two context probes also passed separately. These are
ten original Windows observations in three suites, zero startup translations.

This demonstrates why one cannot erase a reachable external root or assume it
always terminates. It also tests an application-handled case where that callback
is not invoked. It does not prove rcedit's handlers close every path, identify
ntdll's private symbol, or establish absence of unseen external effects. The
recommended opacity proof is the concrete next integration gate, not a result
inferred from the three samples.

## Cohesive next implementation and stopping rule

The existing continuation dispatcher is a useful base but is insufficient: its
helper-return activation has neither a full saved x86 context nor event/unwind
transitions. Extend that real proof/emitter boundary with the borrowed root and
event phases, then execute the unchanged original prolog/filter/cleanup path.
Use the original scope and instruction effects to prove the five obligations;
do not select replacements by image hash/name, sampled address or expected result.

Acceptance must include actual same-artifact resume/search/ordered-cleanup/native
restoration comparisons and rejection of escaped roots, wrong-thread/stale
contexts, noncontinuable resume, incomplete context, unproved cleanup effects and
unwind across the boundary. The existing VR/IOFH Windows cases are behavioral
oracles, not evidence that their unchanged PEs already translate.

If a reachable path crosses the root, report its originating guest instruction,
event class and observable external effect. Either close that shared process-level
API contract or keep the input rejected. Do not require complete replication of
all ntdll internals without such a path, and do not add more address-only probes
as a substitute for integration. This is the bounded architectural decision from
the new evidence; no user permission or environment change is needed to pursue it.
