# SUB-516 production structural intake

The reviewed SUB515-LINKER-DESIGN.md profile now has a Rust parser in src/linker.rs.
Candidate fields are private and its only terminal operation rejects emission.
CLI selects DLL characteristics8540 before strict parsing; parse failure never
falls back to the authored profile. Unsupported entry reports RVA/opcode through
the existing production decoder. Even supported entry bytes unconditionally reject
until typed pointer provenance and operand binding are implemented. No new opcode,
stack or API semantics. Structural validity is never translation success.

Production CLI tests use independently laid out SUB-515 synthetic bytes: two
structural barriers,44 malformed mutations,2560 truncations. All2606 attempts must
exit1 and preserve existing output bytes. Rust formatting/Clippy and prior46 root
and43 evaluation functions remain required. Existing102 Windows/Linux pairs and
corpus timeout identity diagnostics remain. Unchanged minimal MSVC output must now
report validated intake and unsupported entry opcode56; ordinary CRT stays rejected.

The test-only MSVC-built external observer uses documented CreateProcessA with
DEBUG_ONLY_THIS_PROCESS and CREATE_PROCESS_DEBUG_INFO.lpBaseOfImage, then continues
events. It observes only its own child; no debug privilege, memory writes, PE patching,
or security setting changes. Original non-debug execution remains the baseline;
observer execution is separately reported with exact image SHA, actual/preferred
base and exact Hello/empty stderr/exit0. This supplies actual-base evidence only
for that instrumented launch; debug state differs from ordinary launch. It does
not prove every allowed base, XP7 compatibility, or relocation-aware translation.
The observer compiler/runtime is test infrastructure, absent from generated ELF.

Primary instrumentation contracts:
https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-create_process_debug_info
https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent

Next medium review: profile dispatch/failure boundary, checked ranges and aliases,
relocation target provenance and output-write barrier; confirm actual-base evidence
labeling. Typed pointer/ABI integration requires a separate bounded Astra High gate.
No general debug/relocation/data feature support; POGO remains opaque inaccessible
metadata. Historical unexplained Windows corpus timeout is not declared solved.

## Measured implementation evidence

Commit7e13c224c06284eb37ea7354d8ff88d235f692de, CI40270967594 passed all four jobs.
The unchanged minimal compiler PE now reaches validated intake and unsupported
entry RVA0x1000 opcode0x56; no Rust output is written. Both ordinary originals
still emit Hello/empty stderr/exit0. The separate instrumented minimal run reports
actual base0x4c0000 versus preferred0x400000, same output/exit and unchanged SHA256
e6e9ee50d418e7913a2578d2302c1730099b72006f74b957ee7b5c3fa28e717e. This is one
observed relocated Windows execution, not a translated ELF or all-base proof.
The ordinary non-debug baseline base remains unmeasured. Server2025 NT10.0.26100.0,
MSVC19.51.36260.0; no XP7 claim. Final-head evidence is recorded in PR/Linear.
