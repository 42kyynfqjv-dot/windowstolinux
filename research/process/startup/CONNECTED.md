# Connected initialization, checks and restoration

This extends the [original frame composition](FRAME-COMPOSITION.md) in the same
experimental compiler. It removes the earlier Main initialization gap and the
externally supplied saved-context array. It does **not** admit the original PE,
ordinary CRT startup or rcedit. The original Windows experiment and the generated
native component still have different entry boundaries.

## Original instructions now composed

1. Original prologs construct the frame, saved slots, encoded scope relation,
   guards, ordinary words and initial EH4 TryLevel. Actual CALL targets establish
   nested frame order.
2. The complete Main initialization interval supplies the fill arguments, calls
   the original fill helper, balances its arguments, writes observation cells,
   obtains the current module through the bounded GetModuleHandleW(NULL) effect,
   and activates the original scope. The fill helper is decoded and proved for
   every destination low-four-bit class and both possible values of each used
   feature bit. Its byte value is symbolic. The resulting native fill is an
   implementation of that proved effect, not a function-name substitution.
3. The original handler prefix proves record normalization, cookie/owner/table
   argument flow, guard and context call ordering, the incoming flags boundary,
   and the exception-pointer installer. Both original guard checks read protected
   frame tags. The context helper decodes both selector outcomes and its failure
   edge; the runtime selector is never copied from an assumed live PE-file value.
4. Original filters preserve scratch writes. Original finally wrappers and
   Dispatch bodies execute under private live-frame leases. EH4 TryLevel advances
   before each finally, separately from the lifecycle cursor and authored cursor.
5. The selected original landing recovers ESP, stores the handled marker and
   TryLevel, constructs CONTEXT fields in the same owned frame, calls the original
   Restore body, transfers nonlocally, and executes the original capture stores.
   No external saved-register array authorizes this transfer. EAX/ESP/EBP/EIP are
   derived; other registers and flags remain unknown where not proved.

`FrameMemory` accesses the existing `FrameImage` words and byte knowledge. There
is no parallel scalar memory copy for the connected path. Ordinary-slot authority
comes from the prolog certificate. Pointer, guard, return, record and saved slots
cannot become writable merely because their current numeric values look scalar.
Private bindings tie each image to the lifecycle owner and frame generation.
Failure prevents completion receipts and later restoration; completed/partial
effects are not rolled back and advertised as a successful guest return.

## Explicit entry domain and remaining cuts

- A live single guest module has its original preferred base and complete image
  extent. Stack ranges are disjoint from the entire mapping, including untouched
  gaps and virtual tails. Bound original regions and IAT words must lie inside it.
- Numeric entry stack, runtime cookie, current context, thread bounds, handler
  scratch entry, feature and selector values are explicit component inputs.
  They are synthetic in native tests, not recorded original Windows registers.
  The borrowed predecessor remains opaque; it is neither assumed empty nor run.
- Captured CONTEXT and NT_TIB fields belong to the same live thread. ESP is within
  its bounds even for the selector's bypass branch. This deliberately narrower
  domain excludes invalid inputs before fragment effects; it does not emulate
  Windows `INT 29` or cookie-mismatch termination. Failure targets stay recorded.
- The fill contract assumes a valid writable stack, DF clear, flat ES and the
  required instruction availability. Feature words are initialized but unknown.
  Its volatile registers, flags and XMM outputs are not claimed preserved.
- GetModuleHandleW(NULL) returns the owned current module base. Dynamic loading,
  alternate module instances and external mutation are not added by this effect.
- The supplied scratch entry is a separate explicit invocation boundary for
  handler and finally components. Proved temporary extents are checked against
  module/stack ownership. It is not a reconstruction of Windows dispatcher's
  internal stack or an assertion that its real handler/funclet SP values match.
- Windows exception delivery, full original search/RtlUnwind, temporary FS
  registrations, notification writes, nested/collided exceptions and registration
  teardown remain unexecuted. Original handler selection is composed from the
  validated table/filter effects; that is not proof of every dispatcher edge.
- The selected capture boundary does not execute ordinary CRT exit or claim full
  CONTEXT restoration. No XP/7 or third-party application compatibility follows.

## Review findings and independent tests

The review reproduced a numeric stack/module alias that separate model maps had
hidden. Persistent and temporary stack ranges now reject image aliases. A further
review found that initialization could change a local used by earlier scalar
specialization. Such changes, overlapping writes and pointer-provenance erasure
reject until a general state-refinement proof exists.

The subsequent independent audit reproduced two more defects. Temporary stack
accounting omitted pushes cleaned up before a later call; every original PUSH
now contributes to the checked maximum depth, with a 64-versus-16-byte regression.
An unused partially initialized word incorrectly caused outcome extraction to
fail after otherwise valid execution. It now remains an unknown full-word
observation; no unknown byte is read or converted to zero. A 717-byte fill in an
independent layout checks that restoration and trace still match.

Independent tests cover displaced CONTEXT layouts, two-frame delegation, varied
restored EAX and cookies, filter write persistence, cursor progression, wrong or
stale ownership, missing receipts, partial failures, helper path mutations,
unknown bytes, protected ranges, invalid flags, scratch extents and corrupted
saved-context bindings. Original artifacts and compiler flags are unchanged.

## Reproduction and evidence accounting

```sh
cargo build --locked --example frame_unwind
python research/process/startup/check_connected.py ORIGINAL_ARTIFACT_DIRECTORY \
  target/debug/examples/frame_unwind --output NEW_OUTPUT_DIRECTORY
python research/process/startup/check_connected.py --selftest
```

The checker binds authored source, object, PE, extracted instructions and generated
Rust. It reuses independently frozen original Windows scalar observations and
checks absolute restored SP/BP using explicit original prolog arithmetic, not the
production emitter's expected-value output. Local mode is labelled as comparison
against a retained baseline. Fresh CI separately runs the component on Windows;
Linux requires those retained files and successful launch records, the same PE,
byte-identical generated Rust and equivalent harness bytes before claiming a
cross-host comparison. Missing or tampered evidence fails.

Current local checker: 15 native cases (12 feature/selector combinations and three
additional initial traces), runtime boundary and altered-code rejections reported
individually in JSON. The separate independent synthetic fixture has different
layout, code addresses and restored values. These are component tests, not more
original Windows executions or whole-program translations. **Whole-PE pairs: 0.**
Final-head CI status and exact counts belong to the retained report and PR/Linear
checkpoint; previous green commits do not establish the new head's result.

Historical original-Windows launch timeouts remain unresolved. No deadline was
increased and no failed launch was retried or hidden by this work.

## Next coherent admission gate

Mechanically execute the original search/local-unwind and notification paths over
the same thread/frame storage, including temporary FS registration and teardown.
Bind the resulting original cleanup decisions to owned receipts and the already
proved selected landing. Prove containment at the borrowed incoming chain and
retain rejection for unresolved nested/collided or external effects. That work
must close these actual effects before either whole-startup admission or merging
the incomplete milestone; another supplied Boolean cannot replace it.
