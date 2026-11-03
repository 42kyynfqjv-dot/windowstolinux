# Byte-backed startup state: SUB-579 integration boundary

`src/startup_state.rs` is an isolated Rust component using the same checked
`Space` storage as generated programs. It is compiled by the root tests; it is
**not wired into the PE decoder, startup admission or emitted programs**. This
checkpoint closes the model's absence of actual byte storage and map identities,
not ordinary CRT startup or exception dispatch. There are zero new PE/ELF pairs.

## Implemented composition

- Opaque process-backed module and thread tokens, distinct RX code/immutable
  scope data/separate cookie-word mappings and thread-owned stacks. Failed composite maps
  roll back; lifetimes cannot end while registrations use them. Numeric addresses
  remain guest values; token generations cannot be recreated from integers.
- Module cookie versions with initialized cookie/complement bytes. Establishing
  a cookie is an explicit trusted input, **not** an entropy algorithm or a promise
  that a caller-selected value meets `/GS` security requirements.
- Typed pointer, encoded-scope and cookie-XOR-frame relations stored alongside
  actual little-endian words. Equal or partial alias writes remove provenance.
  Registration checks all 16 initialized bytes, module/thread identities, a
  separately stored frame-guard relation, nonoverlap and nested predecessor.
- Active record/guard writes keep their physical effect but block all subsequent
  ordinary operations. Unknown external effects and exception events also block
  process-wide. There is no Boolean “handled” escape hatch or resume API.
- Validated chain snapshots preserve innermost-first handler addresses, exception
  code and continuability. They request dispatch; an executable mapped byte does
  **not** prove an instruction boundary or valid handler implementation. Scope
  header contents, filters and unwind remain unresolved, including empty chains.
- Exact eight-byte successful FILETIME/QPC output footprints into the invoking
  thread's stack. Values are externally supplied; no time, counter or ID is baked
  in. QPC's supplied BOOL must be nonzero and its actual bits are retained, rather
  than inventing the canonical value 1. Volatile registers, flags and LastError
  are unknown. Void FILETIME has unknown EAX. Zero QPC success, invalid ranges,
  wrong owner and active metadata aliasing do not become normal success.

`Space::validate_range` is a shared identity/range check. It deliberately neither
initializes bytes nor grants permissions. Writes and reads still check their own
permissions and initialization. This is the only common storage API extension.

## Binding to the retained instructions

The original artifact/hash and addresses remain in DECISION.md. The retained
`__SEH_prolog4` excerpt starts after `push 14h; push scope; call`. Let S denote
ESP before those three instructions and E=S-12 at helper entry. Its pushes and
`lea ebp,[esp+10h]` produce EBP=E+8. The four-word registration is at EBP-16:

| Offset | Observed stored value |
| --- | --- |
| 0 | Incoming FS:[0] chain pointer |
| 4 | Handler address |
| 8 | Scope address XOR module cookie |
| 12 | 0xfffffffe initial try level |

For the observed 20-byte local allocation, the saved guard is E-44, and
`[EBP-24]` receives that pointer. The copied helper-return word is below it;
the helper RET leaves ESP=E-44. An independent literal trace checks S=0x8100,
EBP=0x80fc, record=0x80ec, saved-SP field=0x80e4, guard=0x80c8 and guard bytes
59 25 a5 a5 for cookie a5a5a5a5. These are arithmetic/byte checks, **not execution
of the original prolog** or proof of all saved-register/flag effects.

The component accepts only the initial -2 record state and normal LIFO removal.
It is not an implementation of changing try levels or unwinding a selected scope.
Its empty incoming chain is an explicit construction premise; FS base/TEB bytes
and actual incoming chain have not been recovered. No arbitrary original process
is assigned that premise by the converter.

## Evidence and limits

Fifteen Rust component tests use literal byte vectors and independent expected errors:
normal/nested records, retained-prolog offsets, forged numeric bytes, equal partial
overwrites, unknown initialization, full ranges, map rollback, thread/process/
module identity, cookie generations, lifetime reuse, active guards, unresolved
exceptions, API neighbors/clobbers and uncontracted failure. They exercise actual
checked-memory bytes. They are component tests, separate from the existing eleven
Python model tests, three inventory tests and five original-Windows probes.

Primary requirement provenance remains CONTRACT.md. The Windows probes establish
normal cleanup, search, unwind, continuation and direct termination observations;
they do not execute this Rust component. No comparison count is added for them.
No proprietary implementation or Wine source was ported.

## Next integration gates, same PR

1. Recover and validate the original TEB/initial chain and complete conditional
   cookie/control graph. Bind module mappings and actual instruction boundaries;
   an RX byte and a four-byte scope range alone are insufficient.
2. Mechanically execute prolog, saved registers, guard and restore through shared
   IR, including original flags, stack bounds and scope-header-selected checks.
   Use the component's byte/identity transitions as assertions, not replacements
   for original instructions. Close time/ID/counter and predecessor call effects.
3. Bind actual handler/filter and failure graphs, their stack/register restoration,
   noncontinuable events and termination/unwind semantics. A dispatch snapshot is
   not a dispatcher; do not clear pending state until these obligations hold.
4. Only then admit a program and count same-artifact Windows/ELF observations.
   Full rcedit/ISCC/ordinary CRT remain rejected. No new XP/7 or driver claims.

The hard remaining boundary is the actual handler/control graph and incoming
process state, not a missing authorization. Keep PR #45 draft and SUB-579 In Progress.

See [BINDING.md](BINDING.md) for measured scope-header/handler evidence and the
nonadjacent cookie/complement correction. The prior fourteen-test count is
historical; one new regression covers the actual separate-word layout.
