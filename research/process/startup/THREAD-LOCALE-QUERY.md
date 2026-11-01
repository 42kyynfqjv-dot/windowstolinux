# Original thread-locale mode-zero query

This records e90af45. See [current boolean/environment entry](BOOLEAN-ENV-ENTRY.md)
for subsequent execution progress.

The original startup argument0 enters0x407158 through CALL0x4015da. Its unchanged
98-byte body calls the unchanged required wrapper0x40a2e1, which calls the existing
registered/lazy UCRT PTD getter0x40a332. The canonical 868-byte UCRT allocation,
current fiber publication, module/code ownership and live registry checks remain.
The required wrapper's actual conditional null-result branch to0x4077ff rejects;
it does not synthesize termination or a successful return.

The original +848 word load, bit1 test, SETE/INC, argument comparisons, saved ESI
restore and RET execute. The query returns1 for bit1 set or2 for bit1 clear.
The original caller pops its argument. Execution stops before the next actual
CALL0x4015e0→0x401bd5. The canonical startup fixture checks EAX2, popped ECX0,
FP control state and all prior publications. The mode-zero supported domain is
checked before executing: unknown and nonzero modes reject. Mutation, errno,
invalid-parameter and global mutation branches are not admitted by this work.

Ten independent body cases cover both results, exact flag effects, unknown bits,
invalid/nonquery inputs, stale and protected storage, callee-saved registers and
single-use return. Ten production cases execute the actual getter/registry
composition, covering caller/wrapper/getter mutation, stale allocation, uncertain
FLS slot, unknown decisions and LastError preservation. Body-only supplied getter
cases are not represented as translated Windows programs or API producers.

The opt-in FP profile was reviewed: its known controls are deliberate target
policy backed by actual stopped-entry Windows observations. It preserves unknown
status/tag/data, rejects rebinding and leaves default/XP7 equivalence unproved.

CI failures41355071228/41355066928 at63d1c40 were formatting failures in the
initializer tuple, not FP equivalence failures. Formatting-only fix18416a0 was
published separately while preserving the unpublished query implementation.
The full63d1c40 local replay completed at generated Rust hash
0ed768d14c391a3cf692aac53be56386623e631e8d0c306a1a14140fa5531cf7,
with five retained component comparisons and zero whole-PE pairs. That success
is not a final-query replay or final-head CI claim. Historical Windows timeout
causes, full startup/rcedit/default admission and other unsupported effects remain
unresolved. The new final replay and final-head checks must be read separately.
