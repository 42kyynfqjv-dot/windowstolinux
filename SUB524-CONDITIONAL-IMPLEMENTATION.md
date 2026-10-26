# SUB-524 bounded conditional scalar integration

Implements the reviewed [SUB-523 contract](SUB523-CONDITIONAL-DESIGN.md) only in
the linker profile. Primary Intel instruction and Microsoft ABI provenance is in
that contract. No third-party implementation was imported.

| Exact unprefixed bytes | Shared validator/emitter operation |
| --- | --- |
| 8B442408 | EAX = Integer direct-caller argument2 |
| BA01000000 | EDX = Integer1 |
| 8B4C2404 | ECX = Integer direct-caller argument1 |
| 3BC8 | CMP ECX,EAX; preserve registers, set CF/ZF/SF/OF |
| 0F4DC2 | EAX = EDX if SF==OF; preserve flags |
| 03C1 | EAX += ECX modulo2^32; set CF/ZF/SF/OF |

ECX/EDX begin with distinct Unknown tags. New argument loads require the whole
word, current protected return and direct-caller Data ownership, then Integer.
Existing pointer-capable argument1 behavior is unchanged. CMP/ADD reject either
non-scalar operand. CMOV requires known flags and Integer EAX/EDX even on false;
requiring old EAX on true is conservative policy, not a hardware old-target read.
MOV preserves known/unknown flags. Cleanup invalidates flags as before.

Decoded internal CALL/RET carry actual ECX/EDX/flag effects, with no invented
clobber or caller restoration. External successful _write invalidates flags and
both volatile registers, preserving its prior EAX=count/ESI/stack contract.
Unknown origins use4+2*steps and5+2*steps, beyond entry tags0..3. The existing
1024-step cap bounds arithmetic; step count increases along each path, so repeated
external calls produce fresh distinct origins. State clones preserve existing
origins; separate paths are never merged or compared as a global value identity.
The exact same checked State transitions are embedded in generated Rust, with no
PE decoder dependency in the generated executable. No instruction/resource limit,
return/ESI ownership, relocation bijection or immutable-buffer rule is relaxed.

## Independent checks

Four new production Rust functions bring the root total to58. Literal CMP rows
cover signed min/max, overflow and equality; ADD rows cover positive/negative
overflow and carry/wrap. Tests verify operand/flag preservation, atomic typed
rejection, owned arguments, distinct unknowns, CALL/RET actual effects, external
clobbers and the existing instruction cap. Expectations are not computed by the
production flag helper or the Python model.

`python3 tools/check_conditional_production.py` drives actual loader, decoder,
validator, emitter, rustc and ELF execution. Its18 native-only cases cover exact
IR emission, both helper selections, seven signed comparison observations, three
ADD signed-flag observations, shared/nested callees and post-return register use.
Seventy CLI rejections cover five prefix classes, every internal truncation of the
six forms, neighboring operands/forms, unknown flags/registers, pointer argument,
protected stack words, untaken invalid paths, a join skipping EDX initialization,
and stale volatile use after output. Rejection preserves an existing output file.
All native cases require deterministic source, Hello/empty stderr and a literal
expected exit. They are separate from the unchanged compiler Windows comparison,
not new Windows equivalence pairs. The earlier10 compiler-shaped native cases and
52 rejections remain; the10 Python prototype functions remain design evidence.

## Unchanged compiler acceptance and limits

Both host harnesses now require the frozen `compiler/structures/conditional.c`
artifact to convert, alongside shared.c. The original source, compiler flags and
PE bytes are not patched. Windows must report Branch/empty stderr/exit99; Linux
must independently convert the same hashed PE to identical Rust, compile it and
match all three observations. Source hash and unmodified PE checks remain. The
entry short-circuits after its first mismatched check, so the native boundary cases
above separately exercise the opposite helper selection. Passing final CI is
required before reporting this seventh compiler-built program as validated.

Six prior compiler programs,102 authored Windows/Linux comparisons and18 mandatory
original launch samples are retained. Nested.c still rejects at its unsupported
stack-copy instruction at RVA1050; backward tail transfers and stack stores remain
outside this issue. Ordinary CRT/general applications and XP/7 compatibility are
unvalidated. Existing valid-stack/no-fault, CMOV-capable CPU, regular-file complete
output and bounded immutable-buffer assumptions still apply.

The two historical different-fixture Windows15-second timeouts remain unexplained.
No timeout/retry/diagnostic policy is changed. A new timeout is a failure to retain
and investigate, not permission to retry silently or claim the cause resolved.

Next: focused medium review of exact forms, call effects, unknown identities,
independent tests and final same-artifact evidence. Further nested compiler support
requires its own bounded design for observed stack copies, stores and tail calls;
it is not implied by this conditional integration.
