# Original dispatcher and owned FS composition

This is an experimental original-instruction component in PR #45 / SUB-579.
It is **not whole-PE admission**, ordinary CRT startup, or rcedit compatibility.
The main converter continues rejecting those unsupported programs.

## What is connected

`frame_unwind::prove_dispatched` binds the unchanged original Main/Outer/Inner
prologs, initializer, full EH4 handler, scope tables, filter/local/global-unwind
wrappers, notification stores, finally bodies, selected transfer, CONTEXT stores,
Restore and capture instructions. Addresses and operations come from those bytes;
application names, hashes and expected answers do not select generated behavior.

The handler proof follows original signed filter branches. The emitted local
helper follows its actual runtime loop, including unsigned target comparison,
parent-before-callback writes and filter-zero test. The EH4 TryLevel, authored
cleanup cursor, lifecycle cursor and FS chain are separate state. Original
callback execution earns an ownership-bound completion receipt. Unlinking a
registration does not retire its storage before the original callback finishes.

Each frame is installed from its instruction-derived record into one thread
registry. Local-unwind storage is reserved first; the decoded MOV FS installs
the temporary record and the decoded POP FS restores its exact opaque
predecessor. Failure preserves reached effects. Notification stores retain
their action/target/frame order and typed identities. The selected bridge's
register clobbers and nonlocal jump execute before the original selected landing
constructs and restores its owned CONTEXT.

## Explicit boundary

This composition starts at the already documented live Main-entry component
boundary. Numeric stack, cookie, captured context, initialized feature words and
module identity are admitted inputs under validated ownership/range constraints.
Original Windows exception delivery remains an external effect boundary.

The non-null-target RtlUnwind contract requires an owned, live target reachable
before a nonempty borrowed root, application-contained callbacks, original
continuation and ReturnValue. Only the proved synchronous callback graph is
admitted: valid initialized memory/stack, bound guard/helper effects, no
unmodeled calls, traps or secondary raise. No exception is silently discarded.
Nested/collided delivery, foreign-root traversal, asynchronous exceptions,
vectored/debugger effects and unknown callback effects require additional
containment proof and remain outside this component's admission domain.

The local nested helper is decoded and independently tested, including its
guard, recursive call and collided-record write; that does **not** connect an
arbitrary nested exception to Windows delivery. Its raw flag mask obligation is
explicit. The ordinary unwind route uses only proven flag predicates, never a
fabricated complete flag word.

Two Microsoft descriptions disagree about unlink-before versus unlink-after
callback timing. The admitted original code only copies/restores its predecessor;
it cannot inspect, compare numerically, dereference or leak that opaque token.
Under the closed callback boundary, the implementation uses unlink-after as a
normal form. It makes no claim of identical intermediate raw FS traces or OS
sentinel addresses. New code observing those values must reopen this proof.

RtlUnwind's original wrapper resumes at its bound TargetIp and executes its own
saved-register POPs. The external API result does not promise those registers
were already preserved. Main's later normal epilog and CRT exit are still outside
the native component; the selected application registration remains live.

## Evidence and counterexamples

The checker retains 15 positive numeric cases and 10 runtime-boundary cases from
the preceding connected component. They now exercise original handler/local-FS
composition; they are inherited cases, not 15 newly independent Windows
observations. Windows and Linux compile the same extracted original bytes into
byte-identical Rust, with strict PE/source/harness/launch hashes. Reports separate
each host's component executions, the ordinary Windows baseline and whole-PE
translation pairs (zero).

Independent review reproduced and fixed new proof defects before admission:
temporary-record corruption hidden by a later restore, stale loop-level reuse,
scalar ESP pivot, missing sentinel/target guards, and incomplete nested guard /
collided-record sequences. Scalar/flag/row snapshots and loop-phase obligations
now reject these mutations. Adapter regressions cover wrong frame generation,
missing notification, protected lifetime and relative-ESP rebasing between the
selected and notification bridges.

The separate observer uses bounded own-child debugger instrumentation. It never
changes the PE file, is not an ordinary execution baseline, and records exact
runtime/module identity. Its first run captured 42 snapshots, then rejected a
CRT teardown thread after the desired interval (run **40625096944**). That failure
is preserved. The corrected observer ends instrumentation after Main's original
FS restoration, restores all breakpoints, and logs later teardown threads without
observing their contexts. Run **40625668689** passed all five dedicated jobs; its
success and injected failure-control reports verify child cleanup.

On that pinned Windows Server 2022 build 20348 runtime, active application records
remained linked through unwind callback return and were absent at the next
callback. An opaque OS registration preceded them. The target was retained;
RtlUnwind resumed with EAX=0 and ESP advanced by 16, while EBX/ESI could differ
before the wrapper's POPs. This is measured evidence for that build, not XP/7 or
universal Windows behavior. Historical unrelated Windows timeouts remain
unexplained; no timeout thresholds or retry gates were relaxed.

## Reproduction

The existing `startup-inventory.yml` workflow builds the frozen original once,
retains its ordinary Windows result, and runs the separately labelled observer.
It then runs `check_dispatched.py ORIGINAL COMPILER --output DIRECTORY` on Windows
and Linux; Linux requires the Windows component evidence. Local preparation and
compiler mutations can run without claiming a fresh Windows observation.

Primary contracts:

- [RtlUnwind](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind)
- [SEH in x86 environments](https://learn.microsoft.com/en-us/previous-versions/ms253960(v=vs.90))
- [The exception model](https://learn.microsoft.com/en-us/archive/blogs/cbrumme/the-exception-model)
- [Frame-based exception handling](https://learn.microsoft.com/en-us/windows/win32/debug/frame-based-exception-handling)
- [Debugger event handle ownership](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)

Original implementations and probes are independently authored Rust/C under the
repository license; no proprietary handler source or Wine code was imported.
