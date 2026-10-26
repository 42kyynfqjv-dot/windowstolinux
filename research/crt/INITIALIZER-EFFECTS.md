# SUB-540: three initializer effects and dispatch model

Closure is NOT achieved. The callback identities and direct-call bindings can be
checked reproducibly, but external effects, indirect returned pointers, exception
paths and transitive callbacks prevent a complete startup-state proof. Production
ordinary CRT remains rejected. No constructor/main bypass is authorized by this work.

## Evidence binding

callback_inventory.py checks the unchanged held_crt hash against its measurement,
reads actual table words, verifies HIGHLOW relocation sites20bc/20c8/20cc, checks
encoded E8 targets against the compiler disassembly, and resolves direct import
thunks against PE import descriptors/IAT. It emits27 direct call sites across the
three callback bodies. Internal helper callees remain explicitly unnamed where no
import binding exists. This is an exact trusted compiler-profile checker, not a
hostile-input PE parser or a complete transitive control-flow proof. It fails on
changed table identities; Windows/Linux regenerate matching reports for each PE.

Detailed static analysis uses the unmodified CI40313382722 held_crt snapshot,
SHA2565331defc936aa3a22ac442ef65c44625112934106b7408c0aac3fa9e6e4a6766.
All addresses below are hex RVAs except explicitly labelled VAs. Fresh CI reports
bind the current artifact separately, without claiming timestamp-identical rebuilds.

## Callback effects

| Callback | Resolved operations and state | Open obligations |
|---|---|---|
| 1030 | _set_app_type(1); _set_fmode(4000); zero written through __p__commode; helper13e0 initializes onexit state; fnclex; helper18a0; register callback VA4018d0 through15c0; _configure_narrow_argv(1); InitializeSListHead(VA4030c8); conditional __setusermatherr; _controlfp_s via1710; _configthreadlocale(0); _initialize_narrow_environment; normal return0 | CRT-global ownership and returned pointer provenance; imports' failure/exception/alias effects; floating-point state; callback registration lifecycle |
| 10e0 | Calls1770 then returns0. Accessors1750/1760 return VA4030d0/4030d8; helper ORs low words with24/2, reads and writes back adjacent high words | Requires validated full8-byte owned image ranges, no alias with protected slots, no concurrent mutation; normal no-fault domain only |
| 10f0 | Calls1830, which registers VA401840 with SetUnhandledExceptionFilter; zero helper16c0; _set_new_mode(0) | Process exception-filter ownership; filter1840 reads exception records, writes through VCRUNTIME exception-context pointers and may terminate. Heap policy is external state |

Helpers16c0/16d0/16e0 return0/1/4000 respectively;1740 returns without memory effect;
1700 returns AL=1. Helper1790 tests image word3004, so conditional math-handler
registration cannot be discarded without state provenance. Helper18a0's observed
initial/end addresses are both24a8, so its table loop is empty for these exact bytes;
that local fact does not establish purity of other callbacks/imports.

13e0 checks byte30a9 and parameter policy. It can initialize two onexit tables via
imports or write six FFFFFFFF sentinel words at30ac..30c3, then set30a9=1. Error
paths return false or invoke fast-fail helper17c0 (INT29).15c0 selects _crt_atexit
versus _register_onexit_function using the first sentinel, and converts the imported
result; callback1030 does not check every registration/policy return. argv configuration
failure or helper failures reach fast-fail.1710's _controlfp_s failure also fast-fails.
These branches are not ordinary successful return traces. External exceptions and
SEH dispatch remain unresolved.

No identified direct image write above targets TLS callback slots30f0/30f4. However,
__p__commode supplies a pointer, imports receive image addresses, and callbacks may be
registered/executed externally. Until each effect has a bounded ownership contract,
absence of a literal store to those two addresses is insufficient. The model marks
tracked values unknown on an unknown effect; it never retains zero by optimism.

## Independent model and probes

initializer_model.py is a contract prototype over explicit callback effects, not
an x86 interpreter. It validates table extent/alignment/protected overlap and callback
ownership before dispatch, skips null, preserves order, stops integer dispatch on a
nonzero result, and ignores return values for void callbacks. Known writes require
owned state. Unknown external effects invalidate tracked values and stop as blocked;
unknown integer return also blocks later callbacks. Exception/nonreturn behavior is
not synthesized as success. No model output grants emission permission.

Eight independent unit functions cover order/nulls, first-error with prior writes,
void-return treatment, unknown-state invalidation, unknown return, changed/outside
callback and aliased table, unowned write and misaligned range. These are research
model checks, separate from79 root Rust functions and existing graph checks.

initializer_probe.c uses separately authored callback arrays with null slots.
Expected success is ABCD/exit0; failing first C callback is A/exit7, with B/C/D absent.
This directly probes the runner CRT dispatch behavior; it does not execute the
original compiler startup table or prove original callbacks harmless. Probe/source/
binary hashes and exact observations join crt-probes.json. Four earlier exit/flush
probes and separate observer remain intact. Runtime DLL versions belong to the
observed held_crt run; shared runner context alone is not a per-probe module trace.

Primary source reviewed2026-10-26:
https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e
It documents signatures, table traversal/null skipping and error return. It explicitly
calls these internal methods and advises application code not to call them. These
calls are isolated research probes, not a recommended public application interface.
First-error ordering is an independently specified model rule tested empirically;
the short public page alone is not a complete callback/exception contract. Existing
SUB-538/539 Microsoft exit, cookie and debugger documentation continues to apply.
No Microsoft/Wine implementation source was imported; original work MIT OR Apache-2.0.

## Smallest next gate

After medium review, isolate callback10e0's two option-word updates for a bounded
owned-data effect contract: exact helper/accessor bytes, relocation-backed pointers,
full ranges30d0..30df, OR masks24/2, high-word preservation, alias/protected-slot
exclusions and wrap/bounds tests. This can establish one callback's local effect
without pretending the entire startup is closed. Separately enumerate the remaining
1030/10f0 import contracts with required pointer aliases, failure and process-state
ownership before broader implementation. A native replacement of startup remains
blocked. Initializer model/probes are not application translation evidence.

Preserve12 compiler/102 authored comparisons/18 launch checks and four held-out
rejections. Actual original-run base is distinct from observed-run base, on-disk module
hashes from memory, and Server2025 from XP/7 compatibility. Three historical timeout
causes remain unresolved. No merge/release or new security settings.
