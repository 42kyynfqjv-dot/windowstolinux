# SUB-507 bounded stack arguments: design decision

Status: design and test-only prototype. Production still rejects PUSH, stack loads
and LEA. No new executable compatibility has been demonstrated in this milestone.
Proceed to a separately reviewed implementation of the contract below; do not add
general stack/memory support by accepting all instructions iced can decode.

## Decision and primary sources

Use one ordered stack containing tagged entry, return and data words. The existing
SUB-506 return-only Vec cannot remain a separate physical stack once data words
are introduced: doing so would give incorrect ESP-relative argument locations.
Use flags-preserving cleanup, not ADD ESP with guessed flags.

Primary sources inspected:

- Intel SDM volume2 order325383-081US Sept2023,
  https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf:
  PUSH 4-516/517 (decrement ESP by operand width then store), MOV 4-35/37
  (copy source to destination), LEA 3-595/596 (effective address, no flags),
  ADD 3-32/33 (arithmetic flags), CALL 3-139/140 and RET 4-558.
- Microsoft [__cdecl](https://learn.microsoft.com/en-us/cpp/cpp/cdecl?view=msvc-170),
  documentation commit c182dcffdd6405ad84d8bef963bbe8f83d469ba9:
  arguments are passed right-to-left and the caller cleans them up.
  This motivates caller cleanup, but the proposal is a single-word subset and
  does not claim C ABI coverage, varargs, preserved registers or compiler output.

The candidate new forms, in 32-bit default address/operand mode, are exactly:

| Bytes | Operation | Model action |
| --- | --- | --- |
| 68 id | PUSH imm32 | push known little-endian 32-bit data word owned by current frame |
| 8B 44 24 04 | MOV EAX,[ESP+4] | read immediately preceding caller data below current return tag |
| 8D 64 24 04 | LEA ESP,[ESP+4] | discard exactly one top data word owned by current frame |

All preserve arithmetic flags. Existing EAX operations retain their existing
flag effects. ADD ESP,4 is excluded: even without unsigned wrap, absolute ESP
0x7ffffffc versus 0x80000000 yields different signed-overflow/sign behavior after
adding4. A symbolic stack depth does not determine these flags. PUSH imm8/sign
extension, PUSH registers, POP, RET imm16, other displacements/base/index/scale,
prefixes, ESP reads/other writes and all other memory access remain unsupported.
Exact byte-form checks and typed iced metadata checks must both be enforced.

## State, ownership and address relation

Stack slots are ordered bottom to top. Initial state is [Entry], current frame0,
unknown EAX and unknown flags as today. Return contains an opaque continuation,
new frame identity and parent frame. Data contains owner frame and a known u32.
Frame identities distinguish successive invocations of a shared callee; they are
internal metadata and never observable by the x86 program.

For a concrete native execution with incoming ESP=S, a vector of n slots maps its
top to S-4*(n-1). Each PUSH or CALL adds one word and each cleanup or internal RET
removes one word. Slots map to contiguous little-endian 32-bit words; no integer
address is invented in the converter. Return tags correspond to real return EIPs
in that relation, but their values cannot be read, written or converted to data.
The entry tag stands for the original entry caller's return, not numeric zero.

Native environment preconditions: flat32-bit stack addressing, incoming S aligned
to4, valid entry return, and readable/writable storage for at most128 additional
words (512 bytes), with no address wrap, stack fault or asynchronous interference.
These are conditional semantic assumptions, not facts established for every PE by
header parsing. Existing native-stack-fault limitations remain. Authored Windows
fixtures can demonstrate particular executions only. General stack commitment,
guard pages, exceptions, entry arguments/environment and concrete ESP observation
require a later design. No reads above the entry sentinel are permitted.

Transitions must fail without mutating state when their preconditions fail:

- PUSH appends Data(current frame, immediate) if total capacity permits.
- CALL appends Return(new frame,parent,continuation), sets current frame and
  increments internal depth. Existing forward-target/continuation checks apply.
- Argument load requires top=Return(current frame,parent,pc) and the immediately
  preceding slot=Data(parent,value). It sets EAX=value. No search down the stack
  is allowed. Entry sentinel/return tags or local data at the wrong offset fail.
- Cleanup requires top=Data(current frame,value); pop exactly that word. It cannot
  discard caller data through a return boundary, discard an entry/return tag or
  create access to stale discarded memory. EAX and flags are unchanged.
- Internal RET requires top=Return(current frame,parent,pc); pop and resume pc in
  parent frame, leaving caller arguments in place. Local uncleaned data fails.
- Entry RET requires current frame0 and stack=[Entry], then existing known exit
  range0..255. It is terminal; leftover data or unknown/out-of-range EAX fails.

A call need not have an argument if the callee does not load one. Multiple data
words may be pushed/cleaned one at a time, but only the nearest caller word is
readable through this exact load. Older words are not additional supported ABI
arguments. A nested callee may push its own immediate argument, call another
helper, clean it, then read its original caller argument again. Arbitrary data
forwarding (PUSH EAX), locals and frame-pointer conventions remain excluded.

Capacity: at most128 data+internal-return slots, excluding the entry sentinel;
32 internal-call depth and1024 decoded/executed instructions remain unchanged.
Capacity/ownership/known-state checks run on the deterministic executed path,
matching current semantic validation. All decoded branches still obey opcode,
boundary and conservative call-depth checks even when untaken. Abstract state is
not merged by instruction offset: the same node may see different frames/data
on successive calls. Validation must revisit it with actual path state. No graph
cache may confuse two invocation contexts. Runtime checks must mirror validation.

## Independent expectations and negative matrix

Golden trace: [Entry] -> PUSH7 -> CALL(continuation10) gives
[Entry,Data(owner0,7),Return(frame1,parent0,10)]. Load yields7. PUSH11/CALL20 in
frame1 allows nested load11; return20/cleanup restores access to outer argument7;
return10/cleanup leaves [Entry]. EAX7 is then a valid terminal result.

Repeated calls with words0x12345678 and42 must load different values and return to
their respective continuations. Internal return may carry a wide EAX; entry exit
checks remain separate. Unknown flags must remain unknown through all three new
operations, and known flags must survive unchanged.

Reject: load at entry, missing argument, return-address-as-argument, load while a
local word displaces the current return, cleanup of return/entry, uncleaned local
or entry data, capacity129/depth33, unknown/out-of-range entry result, unaligned or
alternative displacement, other registers/address forms, prefixes, arbitrary ESP
adjustment, writes to stack arguments, stale/above-entry data, and all prior
malformed/overlap/backward-call conditions. Decoder rejection and state rejection
must be tested independently; many encodings are valid x86 outside this policy.

## Prototype evidence and implementation gates

`tools/decoder-eval/src/stack_design.rs` is cfg(test) only. Six functions exercise
literal ownership snapshots, nested/repeated calls, rejection without mutation,
capacity/depth limits and iced metadata/flag effects. The review adds an enforced terminal state, wrong-owner failure checks and an
independent concrete byte-layout oracle at three aligned starting ESP values.
It is a state-machine sketch,
not a lifter or emitter. Tests explicitly confirm production rejects all three
candidate new forms. There is no new Windows baseline or generated ELF for this
contract yet. Existing42 Windows/Linux cases validate only existing production.

Before production support, a medium review should audit the symbolic-address
relation, ownership and flags argument. A bounded implementation must then:

1. Add typed PushData/LoadArgument/DropData IR only for the exact forms above;
   preserve the handwritten decoder oracle and independent literal expectations.
2. Replace the return-only state with one checked stack in validator and emitted
   native support. Preserve known-state, graph, depth, execution and PE bounds;
   ensure emitted source has no decoder/Wine dependency or invented native ESP.
3. Add independent literal state/IR tests, full encoding/prefix/truncation rejection
   tests and joins/shared/nested context cases. Cover 128/129 capacity including
   return words, unbalanced cleanup and attempted return-address reads/writes.
4. Author a real PE that pushes7, calls a helper loading the argument and adding5,
   returns, cleans one word using LEA and exits12. Compare original Windows with
   generated Linux ELF. Add nested/reused-helper arguments and flag-preservation
   cases; keep exact expected stdout/stderr/exit and deterministic Rust checks.
5. Run all existing tests/mutation matrices plus new forms on exact final CI head.
   Publish unsupported behavior and native-environment assumptions explicitly.

No production implementation is authorized by a green prototype alone. The next
scoped engineering turn should implement only after the contract review confirms
these gates; user keep-going authorization already covers ordinary project work.
Astra High is recommended for that validator/emitter stack replacement, with
medium verification afterward. Wider memory/API/ABI support remains separate.

## Medium review outcome

The terminal-state documentation gap in the prototype is fixed: successful entry
RET halts the model and every later transition fails without mutation. Invalid
entry EAX and wrong-owner load/cleanup preserve state. A byte-addressed test oracle
checks little-endian data/return placement and ESP-relative load, internal return
and cleanup at three starting ESP values. This illustrates the conditional address
relation; it does not prove valid Windows storage or model native stack faults.

Implementation is ready for the exact SUB-508 slice after this review. No unresolved
architecture blocker was identified within the stated native-environment domain.
POP and return-address observation remain excluded; LEA cleanup preserves unknown
flags and avoids the unmodeled absolute-ESP ADD flag effects. Full decoding,
branch joins and actual parameterized Windows/ELF execution remain implementation
gates, not claims made by this straight-line state prototype. Keep the six model
tests as a test-only specification; do not mistake them for production coverage.
