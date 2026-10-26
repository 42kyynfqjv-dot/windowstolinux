# SUB-548: original-startup composition decision

**No original-startup composition certificate is justified.** Production remains
unchanged and rejects ordinary CRT programs. The installed accessor's conditional
instruction effects are useful evidence, but do not establish the original
callback's object lifetime or incoming state. This gate closes the static
precondition/stack audit, not CRT startup effect closure.

## Evidence and scope

Baseline: unmodified `held_crt.exe`, SHA-256
`76c0f70559e311e73cfa261b190f224e5dbecd21276b8c8636ba5b7861377a92`,
from the frozen compiler experiment. SUB-547 final CI 40378633459 recorded x86
SysWOW64 UCRT 10.0.26100.33648, SHA-256
`f4d768583fd3fc020d30fd3a2d9d2f39dd2a5a49c99cc5e2040dfb61424a4778`.
Its separate process resolved RVA 0x879d0 to `MOV EAX,imm32; RET`, with HIGHLOW
at instruction RVA+1 and returned object RVA 0x104768. Live bytes matched the
relocation-adjusted file. This does not identify the original process's runtime
instance, actual base, object generation, or object mapping at callback execution.
Future CI reports carry their own hashes; the values above are historical evidence,
not a claim that every installed runtime has this layout.

`composition_audit.py` checks the original artifact's exact callback prefix,
constant helpers, imported predecessors, identity binding and recorded relocation.
It consumes the regenerated callback inventory and the existing runtime report;
it is not a second independent live-memory observation or an eligibility issuer.
The small RVA reader is for these trusted compiler artifacts, not a production PE
parser. Four new test functions use literal synthetic bytes/records and altered
preconditions to test this audit boundary. They prove neither Windows API effects
nor completeness of startup. No new Windows program comparisons are claimed.

## Original sequence and conditional argument

| RVA | Action | Established local fact / missing premise |
| --- | --- | --- |
| 1030–1033 | Save ESI, push 1, call `_set_app_type` | Original saved word and application-type argument; external effects unresolved |
| 1038–103e | Helper returns 0x4000, push, call `_set_fmode` | Text-mode argument; external state/failure effects unresolved |
| 1043–1048 | Helper XORs EAX, then MOV ESI,EAX | ESI becomes scalar zero on normal return through this sequence |
| 104a | Call `__p__commode` thunk | Separate runtime's leaf argument is conditional on matching original module/code/stack premises |
| 104f–1051 | Push 1, store ESI through EAX | Would write four zero bytes only after complete owned-object proof |
| 1053 | Call sentinel 13e0 | Policy 1 alone does not establish incoming sentinel flag/mode/image state |
| 1058–105e | ADD ESP,12; restore ESI; TEST AL; conditional failure | Three pending arguments removed, saved ESI restored; failure path must remain modeled |

Immediately before accessor CALL, stack top-to-bottom is fmode=0x4000,
app_type=1, saved ESI, callback return. Immediately before sentinel CALL it is
policy=1, fmode, app_type, saved ESI, callback return. Each CALL temporarily adds
its own protected return word. ADD ESP,12 removes only those three argument words;
POP ESI then restores the original word. This reasoning requires normal cdecl
returns, valid accessible stack, and no unproved stack corruption. ADD changes
ESP-dependent flags; later TEST AL replaces the relevant branch flags. It does
not establish AL itself or make the failure branch unreachable.

C initializer order is 1030 then 10e0, bounded by the table's null entries.
The C++ initializer 10f0 belongs to a later phase, not an earlier source of state.
Earlier startup before entry into 1030 is also unresolved; the two listed imports
are only the predecessors inside this callback. Later operations in 1030 and
other initializers are outside this bounded argument.

## Premises required before any future composition

| Premise | Current status and required evidence |
| --- | --- |
| Runtime instance/generation | Missing at original callback. Bind original process, resolved IAT target, architecture, canonical loaded module hash, actual base and immutable code, not a separate probe's numeric RVA. |
| Object ownership/lifetime | Missing. Full aligned writable four-byte mapping at store time, initialized runtime object, no overlap with protected image/stack words, and lifetime spanning access/store/sentinel must be established. Address equality does not prove ownership. |
| Aliases/external mutation | Missing. Track all relevant aliases and external writes, or explicitly justify a closed, single-thread/no-asynchronous-mutation domain. Sampling no changes is insufficient. |
| Incoming startup state | Missing. Establish earlier initializer effects, runtime initialization, sentinel image words and all external-call invalidations. |
| `_set_app_type` effects | Public contract classifies app type; complete original-context frame/effect relation remains unproved. |
| `_set_fmode` effects | Public contract changes default translation mode. Return/error and external state must be retained; success cannot be assumed from a successful baseline alone. |
| Store and sentinel | Store requires the above ownership proof. Sentinel's success/failure paths and incoming mode/flag state require their own closed preconditions. No isolated test flag can grant these. |

Any future private certificate must carry verified original-context provenance,
not caller-supplied numeric IDs or `Session::isolated`. The existing owned-cell
example remains hypothetical. There is deliberately no new constructor here.
A null/partial/misaligned/unwritable target, stale generation, wrong runtime,
protected alias, concurrent mutation, unknown external effect, or exceptional
return must block composition. Unknown earlier effects remain blocking even if
a later isolated leaf succeeds. These are **future proof obligations**, not claims
that four audit tests execute all these semantic scenarios. Current reports always
set both `composition_authorized` and `emission_allowed` to false.

## Primary contracts and limitations

- Microsoft [`_set_app_type`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/set-app-type?view=msvc-170)
  documents an internal void cdecl console/GUI classification operation. It is not
  a complete implementation-level frame condition for unrelated startup state.
- Microsoft [`_set_fmode`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/set-fmode?view=msvc-170)
  documents default file translation mode and zero on success. Invalid inputs can
  invoke the invalid-parameter handler and, if execution continues, set errno.
  The observed argument is valid `_O_TEXT`; invalid-input behavior is not evidence
  that this original path takes that error, nor proof all external effects close.
- Microsoft [`GetModuleHandleEx`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa)
  states UNCHANGED_REFCOUNT does not increment the module reference count. An
  observation handle is not a lifetime pin; it must not be released as an owned
  reference. Module handles are process-local. Prior process observations cannot
  authorize a later process's object.
- Instruction/ABI provenance remains in the earlier runtime-boundary, sentinel
  and owned-cell documents. Implementations and tests are authored independently;
  no proprietary CRT source is imported or translated.

## Decision and next executable gate

Stop further isolated accessor success probes: they cannot supply these original
context premises. Retain the ordinary-CRT barrier and existing evidence for future
whole-startup work. The next useful gate is a separately authored **freestanding
runtime-input program using a documented public Windows API**, with an explicit
custom entry and fixed mainstream compiler configuration. It is a new validation
target, not a replacement entry point inserted into `held_crt`.

Bound the next design to `GetCommandLineW` and a deliberately small ASCII argument
contract. Specify Windows command-line text versus Linux argv reconstruction,
quoting/empty arguments, length/encoding rejection, borrowed string lifetime,
read bounds, failure effects and exact observable output/exit oracle before
implementation. Decide whether the chosen observable domain is defensible; if
not, reject it explicitly and compare a bounded named-environment-variable API
contract rather than inventing command-line equivalence. Freeze authored source,
compiler flags and test vectors before converter evaluation. No production API,
general memory or CRT expansion is authorized by this document. Astra High should
design the architecture gate; medium review should challenge the input mapping
and independence of expected results before implementation.

Existing evidence remains 12 compiled program pairs, 102 authored comparisons,
18 original-only launch checks and four held-out rejections. Windows Server 2025
is not XP/7 validation. Valid-stack/no-fault, load-base and external-mutation
assumptions remain explicit. Four historical Windows timeout causes remain
unresolved; successful later runs do not explain them.

## Reproduction

Run `python3 -m unittest discover -s research/crt -p test_composition_audit.py -v`.
Against downloaded compiler-measurement reports, run
`python3 research/crt/composition_audit.py EVIDENCE` to create the blocked report;
`--compare` regenerates and compares it without rewriting. CI creates it on Windows
and compares identical artifact/source hashes on Linux. The report is evidence of
checked static premises and explicit missing obligations, never conversion success.
