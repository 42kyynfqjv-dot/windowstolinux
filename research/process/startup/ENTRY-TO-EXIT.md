# Entry-to-exit critical path after captured-object review

The target for this existing track is the unchanged authored ordinary-CRT
unwind/report program already measured by `reported_binding.py`,
`check_reported.py` and `stdio-frozen.json`. Preserve its original PE/source/
toolchain hashes. Recompilation produces a separately identified artifact; no
binary surgery, alternate entry or guessed-main invocation counts as completion.
This target exercises more of the current work than another small new fixture.
It remains substantially smaller than rcedit, which is a later independent gate.

The current evidence is incomplete. Normal report comparisons accept supplied
Main/driver state, handler comparisons accept captured-state cuts, and the stream
components accept constructed CRT state. Passing all three does not prove that
one executable can establish and connect those states by its own instructions.
The shortest credible route is to remove these cuts in one composition, retaining
the artifact and independent Windows baseline, rather than add more receipt types.

1. Bind incoming module/thread/stack/borrowed-chain state at the actual entry.
   Execute original initialization and its external effects. Keep borrowed-root
   containment: no incoming chain dereference/dispatch without a proved contract.
2. Execute the original Main/handler path from that state, including RaiseException,
   original handler prefix/helpers, selection, ordered cleanup and nonlocal restore.
   Captured context must be an owned delivery effect with justified observable
   fields; CALL registers are not a substitute. The new checked-object helper
   composition closes one context-check call, not delivery acquisition or dispatch.
3. Connect the same live FILE/descriptor/lock/locale/PTD state to actual formatter
   execution. Remove the formatter driver cut, and prove or reject its C++ FuncInfo,
   failure/termination, temporary buffering and cleanup paths. Preserve short writes
   and unknown volatile state. A precomputed report string cannot replace printf.
4. Follow original return into exit registrations, flush/close and termination.
   Return/flush failure must preserve actual status, physical stdout/stderr and
   process termination behavior. Matching bytes alone is insufficient.

Acceptance is a normal converter invocation on the entire unchanged PE from its
header entry, producing deterministic native Rust/ELF with no supplied runtime
vectors, expected result stencil or skipped startup. Record PE/Rust hashes, compare
Windows/ELF exact stdout, stderr and exit with independent source expectations,
and test failure paths including short/failed writes, invalid captured state,
wrong owner/lifetime, cleanup failure and rejected unsupported startup effects.
Keep unrelated fixtures and the reserved utility families as holdouts.

Next cohesive hard step: connect the existing original handler prefix/helpers
(including the decoded context check) to owned delivery objects and the existing
selection/cleanup/restoration engine. Define the observable delivery contract
and rejection gates before enabling it. The context/record constructor currently
validates supplied captured input; it does not implement acquisition. Once that
step is connected, advance formatter and exit on the same state rather than
branching into another isolated probe chain. This needs a bounded Astra High
architecture pass; routine regression and evidence review belongs on Sol.

No current whole-startup, rcedit, ordinary-app or XP/7 support claim follows.
