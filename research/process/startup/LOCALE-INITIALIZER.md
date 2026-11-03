# Original repeated locale initializer

This earlier checkpoint is superseded by [the feature initializer](FEATURE-INITIALIZER.md),
which completes the C array and reaches0x401678. Its review and failed Windows
evidence below remain retained.

The explicit controlled native-profile entry now completes original locale callback
0x4109ba and reaches **0x4127b0**, the raw processor-feature BOOL storage callback.
Both empty and three-entry synthetic variants retain their previously published
FILE/environment state. Full startup/default/rcedit support remains unproved.

## Executed original effects

The byte-guarded callback executes CALL0x40b42a, original MOVZX EAX,AL, XOR EAX,1
and protected RET. It reuses the existing guarded original helper and live registry
context; no replacement success result is supplied. The helper reads its actual
initialization flag at0x41d148. In the connected entry, earlier initialization
produced the nonzero flag, so the original fast path returns through MOV AL,1.
Unknown upper EAX bits remain unknown until the original MOVZX clears them.

The callback does not allocate, replace references or free a locale object on this
observed repeat path. Existing PTD/multibyte object identities and reference-count
assertions remain checked by the canonical gate. A zero flag still executes the
original initialization path; missing contracts reject after preserving preceding
original stores. An unknown flag is never converted to an initialized state.

Six independent instruction cases cover unknown/nonzero upper registers, a known
nonzero flag other than1, repeat execution, zero/unknown flags and damaged return
authority. Nine original-artifact cases cover changed caller/helper bytes,
unknown/uninitialized state, expired initialization/provider, corrupt return and
fresh-call repeated reuse. Failed acquisition preserves original pointer-value
stores and leaves the initialization flag clear; it does not fabricate normal
completion. Inputs in direct component cases are explicitly supplied states;
connected original-entry cases use the earlier actual producer.

## Review and CI evidence

Review of72c3b24 found an opaque-owner alias defect: native FILE construction
could overlap a preexisting global critical section in the same mapped section.
An original-body regression first demonstrated unexpected success. Native FILE
construction now invokes the shared opaque-owner range check before reservation
or byte effects. The regression rejects with the global owner retained, prior
vector publication preserved and no new FILE locks or slots. Canonical FILE views,
fallible reservation, thunk/ABI and other partial-failure checks remain intact. Its
558 replay input hashes independently match exact commit blobs.

Its PR workflow41378889653/job125065106041 failed before converter execution:
original Windows corpus case1 exceeded15seconds after outputC01. Correct artifact
13112293419 has PE hash52b0377c5641d44a3dc2dd1e916fb96b91851556a11dd8bce01daa4edc14299b,
empty stderr and a live PID/creation-time-verified process. WCT reported no cycle;
its thread node8/status2 and CPU0.0 do not establish a root cause. The same PE hash
passed three earlier launch-context samples. Output-probe artifact13112765306 is
an independent successful control, not the failing case.

A later/parallel passing push does not repair this failure. Original artifacts,
observer data and timeout remain retained. No timeout increase, dropped comparison
or rerun was used to hide it. A further root-cause experiment needs evidence of
the stalled thread's execution/termination location; present WCT metadata alone
cannot identify loader, CRT, harness or process-exit causation.

## Next bounded scope

Original0x4127b0 calls IsProcessorFeaturePresent(10), stores the whole EAX result at
0x41d2fc and returns zero. Reuse the coherent existing CPU/OS feature profile, but
retain any unspecified raw BOOL bits instead of fabricating a complete scalar.
Inspect consumers of that stored result and reject unsupported observations.
Independent tests should distinguish truth knowledge from exact numeric bits,
invalid/stale profile state, original store ordering and code mutation.

Windows resource-failure equivalence, exceptional cleanup, copy-error termination
0x407b5f and broader startup remain unsupported. Synthetic environments only;
no real environment values are acquired/logged. Historical Windows timeout causes
remain unresolved. Final committed-source replay and CI are separate gates.

Local validation: 360 CRT tests passed (two artifact gates separately handled),
canonical entry with nine original-artifact cases, six independent instruction
cases, 114 Python tests (one skip), Clippy with warnings denied, formatting and
all152 word cases at512KiB plus64KiB padding. Final published-source replay and
new CI are tracked separately.

The superseded local replay for fedea20 was intentionally interrupted after this
review finding; its manifest, log and partial outputs are retained. It is not
qualified final-head evidence. CI runs were not cancelled or masked.
