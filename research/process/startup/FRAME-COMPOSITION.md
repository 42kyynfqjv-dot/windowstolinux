# Original frame, filter and finally composition

The subsequent [connected initialization/check/restoration integration](CONNECTED.md)
closes several cuts described below. This page preserves the earlier fragment
checkpoint and its evidence; it is not the current support matrix.

This checkpoint compiles original instruction fragments from the retained authored
Windows SEH experiment into one native composition. It remains separate from PE
admission. **There are zero newly translated whole programs.** The original
Windows run and the generated fragment harness have different entry contracts.

## What now comes from original instructions

`src/frame_unwind.rs` composes the frame, selection, pointer-installer, dispatcher,
cleanup and funclet proofs. `examples/frame_unwind.rs` accepts image-bound fragment
regions rather than a caller-selected frame or a list of invented cleanup results.

| State or effect | Established source and boundary |
| --- | --- |
| Parent frame layout, scalar initialization, registration and guards | Original prolog and initializer instructions construct typed frame images. Protected return, saved-register, guard and record words remain separate from ordinary scalar storage. Numeric entry SP and cookie are explicit harness inputs. |
| Nested frame order | Each original direct CALL must immediately follow its proved prefix or separate activation fragment and target the next original frame prefix. The final original indirect CALL must bind the retained RaiseException IAT entry. Reordering manifest frames, changing a target or omitting intervening bytes rejects; this does not prove effects inside Main's earlier gap or OS exception delivery. |
| EH4 scope activity and selected frame | Original TryLevel stores, validated EH4 rows and original filter instructions determine the selected frame and handler landing. The authored cleanup table is a different format and is never treated as EH4 metadata. |
| Event code | The innermost original argument pushes establish the bounded RaiseException call inputs. Actual Windows exception delivery is outside the cut. |
| Pre-filter event normalization | Original normalizer instructions prove the admitted event code is unchanged across the supported paths over an unknown initialized feature word. Feature ownership/initialization is still an entry premise. |
| Exception pointers | Original installer stores operate on owned handler-local record/context identities and the live owner's pointer slot. The pair is bound to the same composition owner and frame, and invalidated after use. Numeric host pointers are not substituted for these capabilities. |
| Filter memory effects | Original writes update owned scratch words and are carried into subsequent frame state. They cannot overwrite an already initialized scalar, cookie, record or saved slot used by the proof. |
| Persistent custom cleanup cursor | The original finally helper's LEA/PUSH argument order identifies its caller's cursor and local. The cursor survives successive scopes in the same frame; it is not reset from a supplied action index. |
| Complete finally effects | Original helpers call the compiled original Dispatch, then execute their original post-call frame loads and absolute global stores. Completion is issued only after the complete helper succeeds. |
| Cleanup lifetime and order | The selected scope chain executes inner scopes before outer scopes while each owner remains live. A frame retires after its final required scope; the selected frame remains live. |
| Later manual restoration | Original Restore instructions read the explicit saved-context input and transfer the proved EAX/ESP/EBP/EIP fields. ECX/EDX/flags are reported unknown. The selected handler landing and this later manual Restore remain separate cuts. |

The frame adapter also preserves unknown entry registers rather than copying
synthetic current registers into unrelated entry states. A separate activation
fragment may update only the proved TryLevel in this composition; changing a
dependent scalar or cursor without new state refinement rejects conversion.

These restrictions address three concrete review findings: lost filter scratch
writes, activation writes that invalidated scalar/cursor assumptions, and
unsupported attribution of entry-register values. Their regressions exercise the
proof and generated code, rather than only the lifecycle model.

## Evidence and count boundaries

The local report used for this checkpoint is
`/tmp/w2l-frame-final-local/native-frame-report.json`. It binds:

- Original PE SHA-256:
  `55a2435e8800b54f81c20b55373b56206c24bdeeeadc9580bb39b80bf5e04ce5`.
- Authored source SHA-256:
  `143932ec0de25e0e3269c4d7774d78f411efae331e8aa52dd3c97cae05ecaeb1`.
- Original object SHA-256:
  `853bd1b85ec5b43e0580ba023848fd1a7a1652f2a91f454079637849f0792404`.
- Original baseline platform: Windows Server 2022, build family 20348.

The object, PE bytes, relocation records and complete instruction boundaries bind
the fragment extraction. Disassembly text is checked against those bytes; a symbol
name or report field alone does not establish a region's identity.

The retained Windows baseline observes trace `291`, inner/outer locals `118/213`,
selected local `300`, both cleanup cursors `-1`, and no abandoned-path markers.
Its separately executed manual Restore observes EAX `77` and matching saved
stack/frame pointers. The native fragment checks reproduce the declared scalar
observations while retaining the following distinctions:

| Check | Count and meaning |
| --- | --- |
| Original Windows experiment | One retained unchanged-PE baseline; this is not a newly admitted program. |
| Native feature-word cases | Six independent values: `i32::MIN`, `-1`, `0`, `1`, `2`, `i32::MAX`. The actual Windows feature value was not observed. |
| Additional native trace cases | Three nonzero initial traces, including wraparound. These are independent native cases, not three additional Windows observations. |
| Compiler rejection mutations | Fifteen: malformed frame/event boundaries, protected state, cyclic metadata, aliasing, wrong bindings, activation levels, restoration/target bounds, disagreement with original event arguments, wrong direct-call targets and reordered frames. |
| Artifact-binding tests | Seven tests against the retained object/PE/disassembly inputs. |
| Mandatory comparison evidence | Nine tests: missing/self-supplied Windows evidence and non-true verification reject, and five retained-file/hash/failed-launch cases. These do not execute mutated binaries. |
| `frame_unwind` example tests | 51 test functions: 30 inherited from existing modules and 21 new for this integration. Do not add the inherited tests again to a project-wide total. |
| Root suite | 175 existing tests; this checkpoint does not present those as newly added tests. |

The checker also rejects five runtime input-boundary cases: three invalid stack
inputs, debug flags and the wrong saved target. They are harness/precondition
checks, not implementations of those Windows failure behaviors.

At this documentation checkpoint, local evidence has been reviewed; **fresh final
commit cross-host CI is not yet claimed**. The workflow runs the generated
component on Windows and Linux and checks retained hashes and byte-identical Rust.
The Linux CI invocation requires the Windows component artifact; local optional
mode cannot silently substitute for that gate. Missing, stale or failed Windows
evidence rejects before comparison success is reported.
When available, those results must be reported for their exact commit. Native
Windows component runs remain separate from execution of the original PE.

Local formatting and all-target Clippy checks passed, as did the 175 root tests,
51 example tests, seven artifact-binding tests and the checker outcomes listed
above. Separate evidence, startup, launch and observer regressions also passed;
the platform-specific observer test remains skipped on Linux. These overlapping
suite executions are not summed into an inflated unique-test count.

## Explicit unresolved composition

1. Main's initializer and activation are separated by 66 original bytes at RVA
   `0x12cd`: outgoing arguments, a call to `memset`, stack cleanup, stores,
   `GetModuleHandleW(NULL)` and its result store. These bytes are retained as
   `main-unproved-gap.bin`, not skipped under a claim of equivalent startup.
   The current fragment composition assumes the same frame survives that cut.
2. The original handler invokes the event normalizer, then additional
   cookie/context helpers before the pointer-installer fragment. Proving the
   normalizer's event-code identity and the installer's pointer effects does not
   close those earlier calls, their failure paths or their execution ordering.
3. Exception delivery, original thread/module initialization, borrowed predecessor
   lifetime and the complete original handler execution remain unproved. The
   generated frame images do not establish that an arbitrary original Windows
   entry satisfies those premises.
4. The selected landing at VA `0x40135c` differs from the later manual Restore
   target at VA `0x4013a5`. The slice neither executes the selected landing nor
   proves the intervening saved-context preparation. Its complete register/SP/
   cookie inputs are synthetic test inputs, not captured Windows state.
5. FS teardown, nested/collided failures and complete CRT entry/exit remain outside
   the admitted composition. Original rcedit/ordinary CRT admission remains
   rejected; no XP/7 or general application compatibility follows from this test.

Historical Windows launch timeouts remain unexplained. Improved failure capture
and a passing later run do not resolve their cause.

## Reproduce

Run from the repository root with the repository's Rust/Python test setup and
compiler-time Z3 available, plus the retained
`startup-unwind-slice` artifact extracted into `original-unwind`. The directory
must contain its original PE, object, disassembly, source, reports and launch
evidence; do not reconstruct a passing report around a modified executable.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo test --locked --example frame_unwind
cargo build --locked --example frame_unwind
python3 research/process/startup/frame_binding.py --test-artifact original-unwind
python3 research/process/startup/test_frame_gate.py --artifact original-unwind -v
python3 research/process/startup/check_frame.py original-unwind target/debug/examples/frame_unwind --output frame-check
```

Use a fresh `frame-check` directory. The checker verifies provenance, prepares the
manifest, converts twice, checks deterministic source, compiles and executes the
native harness, and retains rejection diagnostics and a detailed JSON report.
On Windows use `python` and `target/debug/examples/frame_unwind.exe`. Cross-host
comparison additionally requires the retained native Windows component artifact;
its absence is reported rather than inferred away.

## Next cohesive gate

Close a continuous original event path around these fragments in this same
milestone. The dependency plan is concrete: prove the bounded Main gap's memory
and module-result effects; compose original handler-prefix cookie/context checks
with the typed installer and filter; execute the selected landing and original
saved-context setup so restoration no longer depends on a separately supplied
synthetic context. Preserve original bytes, frame identity, exceptional edges and
borrowed-root constraints throughout. Every unresolved reachable effect must
continue to reject before whole-program emission.

Acceptance needs the same original artifact and an independently specified native
execution covering initialization, selection, full cleanup observations, landing
and restoration as one connected path, plus adversarial ownership/guard/failure
cases. Complete CRT entry remains a further gate. If an external helper blocks
that path, identify its originating instruction, required observable contract and
failure effect; do not substitute another isolated accessor probe or guessed
startup entry. Keep these related prerequisites in one reviewable integration.
