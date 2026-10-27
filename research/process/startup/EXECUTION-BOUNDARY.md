# Original handler execution: demonstrated architectural boundary

## Result and scope

SUB-579 cannot soundly compose its current checked-record component with the
existing streaming call/emission contract. The missing abstraction is **guest
exception delivery and nonlocal continuation across live activations**, including
guest register/context writes and ordered cleanup. This is a concrete limitation
of the current architecture, not a claim that native recompilation is impossible.
Production admission stays rejected; PR45 remains draft and In Progress.

This finding changes the implementation plan: extending the record component or
admitting a few more opcodes alone cannot close startup. The experiment below
executes independent Windows programs and uses the real production decoder on
unchanged original byte slices. It does not execute the original handler on Linux.
No new translated pairs, complete handler CFG, or full rcedit support are claimed.

Medium review clarification: a CALL node's ordinary successor is not by itself
proof that an IR cannot support exceptions. Exceptional effects can be composed
outside a local CFG. The gap established here is the absence of that composition
in the inspected binding, emitter, checked-fault and startup interfaces together.
The probes demonstrate required behavior; source inspection establishes the
current implementation gap. They do not mandate one particular IR representation.

## Reproducible evidence

Commit `e9c32e7f51f3cd5657c7ab2afac8ac63f346ba98`, dedicated workflow
[40591497396](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40591497396)
passed both jobs. `execution-boundary-results.json` records exact source/compiler/
PE/slice hashes. Windows Server 2022 10.0.20348, MSVC 14.44.35207 x86 `/O2 /GS`.
The two expectations were committed in `context-frozen.json` before execution.
The original five probes remain unchanged and pass separately.

| Independent program mode | Frozen and observed output | Observable requirement |
| --- | --- | --- |
| `r` | `VR`, empty stderr, exit 0 | A real access violation captures EAX=0. The filter verifies the faulting EIP and integer-context validity, writes an owned scalar address to saved EAX, then requests continuation. Windows retries the same `mov eax,[eax]`, returning 42. |
| `u` | `IOFH`, empty stderr, exit 0 | An inner filter changes the exception code and continues search. The outer filter observes the changed code, then an intervening finally executes before the selected handler. The abandoned inner call never executes X/Y/Z/Q markers. |

The second mode is an authored ordinary C call, not a handler-name shortcut. The
first uses explicitly authored x86 inline assembly to make the faulting instruction
unambiguous; it neither guesses an instruction length nor patches EIP. These probes
demonstrate effects that a future engine must preserve; they do not prove every
Windows exception behavior or rcedit's original entry state. They use their own
process and no security-setting change. Ten-second launch bounds have no retries;
failure diagnostics and the exact executed image are always uploaded.

Reproduce Windows: from the configured MSVC x86 14.44 prompt,
`python research/process/startup/measure_context.py NEW_OUTPUT_DIRECTORY`.
The report, disassembly and per-case launch evidence are retained in
[artifact 12773084652](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40591497396/artifacts/12773084652).
Link timestamps can change PE hashes across builds; each execution checks its
own unchanged image hash, with the frozen source and flags unchanged.

Reproduce the original-slice experiment using retained `rcedit-windows` from run
40577863473, without executing extracted bytes:

```sh
cargo build --locked --example stream_graph
python research/process/startup/inventory.py original
python research/process/startup/observe_boundary.py original target/debug/examples/stream_graph
```

The SHA-256 of the original PE is
`ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f`.
The dedicated workflow downloads that retained artifact and repeats both commands.
The measured addresses are research observations, never converter dispatch keys.
No third-party implementation source or extracted runtime implementation is imported.

## Minimal dependency/effect graph from actual original bytes

Direct destinations below are resolved from E8/E9 bytes, with a four-hop budget,
cycle rejection, unique full file backing and displayed-byte checks. Excerpts may
include adjacent functions; this is not a claim of complete reachability recovery.

1. Handler 0x47b290 writes the filtered exception code at 0x47b2ae. Its call at
   0x47b2a9 reaches 0x4f4148. The floating-point path reads MXCSR at 0x4f4168;
   omitting that state can change the exception code. Production rejects STMXCSR.
2. Call 0x47b2cf reaches context validation 0x47ccdc. A conditional path reads
   FS:[0x18], then compares CONTEXT+0xc4 (x86 ESP) with thread stack bounds and can
   issue INT 0x29. The guard-pointer comparison controls this path; the current
   evidence does not prove it unreachable in all original loader states.
3. Call 0x47b312 reaches 0x47cfc0. Its `call ecx` at 0x47cfd0 decodes into a
   structurally valid 16-node graph, with **only fallthrough 0x47cfd2**. Structural
   success grants no callback target binding, memory authority or execution proof.
4. Positive-filter call 0x47b3b2 reaches 0x47d000. At 0x47d00f it calls an IAT slot
   0x521110 labeled RtlUnwind by the retained dumpbin import-linked disassembly,
   after pushing a continuation 0x47d015. This is evidence of the required external
   unwind effect, not an independently revalidated import-binding certificate.
5. Local unwind reaches 0x47ce50 via 0x47b34f and 0x47d02b. It installs another
   FS:[0] registration for 0x47cf20, updates scope state before cleanup callbacks,
   and restores the chain afterward. The nested handler writes through its fourth
   argument and can return raw disposition 3. Thus nested/collided unwind is a
   concrete reachable dependency to analyze, not covered by a continuable Boolean.
6. Call 0x47b3e8 reaches 0x47cfe0. This changes EBP to the target frame, invokes
   notification code and ends at **0x47cff7 `jmp esi`**, not RET to the caller.
   The following handler instruction is INT3. Treating transfer as an ordinary
   successful API return would execute a different successor.
7. Notification at 0x486950 writes destination, frame and code to module state
   before returning. It cannot silently be erased as harmless scaffolding.

The four production-decoder experiments preserve these distinctions: callback
slice structurally decodes; indirect transfer, FS validation read and MXCSR store
reject explicitly. Adding support for their byte encodings would still leave the
effects in points 1–7 unrepresented.

## Exact mismatch with current production contracts

`src/stream/graph.rs::decode` gives Call a single ordinary successor and Return no
successor. `src/linker/stream/emit.rs` binds calls to returning native API effects,
advances to that successor, and treats Return as the program result. Its checked
memory contract faults are not Windows exception events. Other bounded helper
paths exist in the project, but none is composed with this startup dispatcher.
`src/startup_state.rs::begin_exception` deliberately makes all later ordinary
operations pending/rejected. It has neither an initialized x86 CONTEXT mapping nor
a validated restore/unwind transition.

Consequences demonstrated by the probes:

- Replacing a fault with exit125 cannot produce `VR`; silently supplying zero or
  resuming without restoring EAX cannot complete the repaired load either.
- Calling a cleanup routine and returning normally cannot produce the same
  abandoned-frame semantics as `IOFH`; omitting cleanup loses F, and falling
  through the original inner call executes a forbidden marker.
- Clearing pending based only on a negative filter result does not validate the
  changed context, target instruction, stack ownership or continuability.

These are counterexamples to proposed shortcuts, **not mistranslations produced
by the current converter**, which correctly rejects this domain.

## Cohesive implementation required before admission

Keep this in the existing milestone. Replace the normal-return-only composition
boundary with explicit effects shared by lifting, proof and emitted code:

1. **Guest activations and continuations:** carry thread/module/frame generations,
   numeric ESP/EBP, saved register knowledge, return PC and a validated finite set
   of callback/continuation targets. Original scope data must determine targets;
   addresses, symbols or application hashes may not select replacement behavior.
2. **Effectful exits:** ordinary return, raised guest event, unwind request, resume
   and terminal failure are distinct outcomes. API contracts and faulting guest
   operations must expose them to the same statically compiled control graph.
   Each outcome invalidates or preserves aliases by an explicit effect contract.
3. **Owned thread/context state:** capture only known valid register/flag fields,
   initialize exception records, expose checked writable handler views, and restore
   only a validated same-thread continuation. Model the FS chain and stack limits
   from explicit initial-state evidence. Do not grant an empty-chain assumption or
   erase loader-owned frames. Floating-point/context fields remain rejected until
   their effects are represented or their relevant paths are soundly excluded.
4. **Ordered unwind:** execute original cleanup instructions while their frames
   remain live, retire each abandoned activation afterward, and preserve nested/
   collided events and notification writes. Never drop live records first and then
   reauthorize their stale pointers to run cleanup. Unknown destructor targets or
   nested effects keep conversion blocked.
   Distinguish scope retirement from activation retirement: one activation can
   contain several cleanup scopes and the selected handler. Finish each required
   scope in order before retiring an abandoned activation; retain the selected
   activation and its surviving locals. Restore original saved registers, numeric
   ESP/EBP and FS chain according to lifted operations, not a blanket caller reset.
5. **Native lowering:** emit only recovered original basic blocks and bounded,
   proven successor dispatch. This can be a Rust state machine over compiled
   blocks; it must not fetch/decode arbitrary PE bytes at runtime. No Wine or AI
   runtime. A finite-target or ownership proof failure rejects before emission.

Acceptance is one composed path through original prolog/handler/helper operations,
not a new isolated model: same-artifact Windows/ELF behavior for resume, search and
unwind, plus instruction-level snapshots, noncontinuable/invalid-context and
stale/wrong-thread/corrupt-record/cleanup-fault/unknown-target negatives. Actual
rcedit admission additionally needs its original incoming chain, remaining CRT
startup and external effects; this report does not close those gates.

## Primary contracts and limits

- [x86 CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context-r2)
  identifies architecture-specific registers and ContextFlags.
- [RtlUnwind](https://learn.microsoft.com/en-us/windows/win32/api/winnt/nf-winnt-rtlunwind)
  specifies target frame, continuation and return-register value.
- [try-except](https://learn.microsoft.com/en-us/cpp/cpp/try-except-statement)
  distinguishes continuation, search and selected-handler control flow.

Neither those documents nor two successful probes close undocumented runtime
branches, original loader state, debugger/async interactions or all nested faults.
Previous original-Windows timeouts remain unexplained and retained; no retry or
threshold change is part of this work. Modern Windows evidence is not XP/7 or
ordinary third-party application compatibility.

## Reviewed next Astra implementation contract

Implement the shared effect boundary in the real decoder/binding/proof/emitter
path, then compose it with checked startup state in this same PR. Deliver the
following as one integrated change, with reviewable commits:

- Lower original calls, returns and proven indirect transfers with activation
  identities and finite continuation targets. Preserve per-register known bits,
  initialized stack ranges, protected return slots and borrowed capabilities.
- Introduce owned event/context state and distinct return, search, selected unwind,
  resume and terminal outcomes. Language filter -1/0/1 and raw dispatcher
  dispositions must have separate typed contracts. Validate context fields under
  ContextFlags, thread/frame generations, target boundaries and continuability.
- Execute cleanup scopes while storage remains live; invalidate abandoned-frame
  capabilities only after their last required cleanup. Preserve the selected
  frame, module notification writes and actual register/stack restoration.
- Bind original scope/helper targets and API effects through shared rules. Reject
  unclosed RtlUnwind, nested/collided unwind, floating-point, loader-frame or
  destructor effects. A rejecting intermediate commit may be useful, but final
  acceptance needs the composed original-instruction path and observable native
  execution, not another component-only model.
- Reuse frozen probes as behavioral oracles and add independent multi-scope,
  saved-register, wrong-thread, stale-context, noncontinuable, cleanup-fault and
  unknown-target cases. Compare unchanged PE/Rust hashes, output/exit and relevant
  state. A smaller execution slice must be labeled as such; whole-PE startup
  admission requires complete original entry/dependency closure.

No new external resource or user decision blocks that implementation. The
architectural finding requires substantive Astra work; the current PR remains
draft until its integrated acceptance gates actually pass.
