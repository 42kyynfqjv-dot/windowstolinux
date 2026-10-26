# SUB-521 structural measurement

Sources/expectations/harness frozen before first compilation at
323072341c3c1e1513de0eb9bcc685d69dccf013. Initial CI40278547489 uses the
same custom-entry flags, MSVC19.51.36260.0 / LINK14.51.36260.0 and Windows
Server2025 NT10.0.26100.0 baseline. No program/PE edits or flag search.

| Program | Windows stdout / stderr / exit | Conversion |
| --- | --- | --- |
| nested | Nested / empty /0 | reject unsupported instruction RVA1050 |
| shared | Shared / empty /0 | reject unsupported83 form |
| conditional | Branch / empty /99 | reject unsupported83 form |

These are three additional Windows observations, zero new translated pairs.
Both converters must reject the same hashed PEs with identical diagnostics and
preserve output. Existing five accepted compiled programs and102 authored pairs
remain mandatory. Compiler optimization produced meaningful structural differences:

- Nested: entry CALL1050, outer PUSH [ESP+8] twice at1050/1054, backward CALL1040
  at1058, ADD ESP,8 at105D, JE at1063. The second inner call becomes stack argument
  stores (C7442408 and C7442404) followed by backward JMP1040 at107B. This is a
  tail transfer, not two nested CALLs; unsupported copy is the reported first barrier.
- Shared: CALL1050 at1016 and1027, distinct arguments and both result checks.
  First cleanup20 at101B is supported; cleanup8 (83 C4 08) at102C is not.
  Helper1050 retains the supported two-argument sum. This is the smallest useful gap.
- Conditional: entry uses the same shared-call/check shape and cleanup8 at102C.
  Helper additionally starts MOV EAX,[ESP+8] at1050, MOV EDX,1 at1054, MOV ECX,
  [ESP+4] at1059, CMP ECX,EAX at105D, CMOVGE EAX,EDX at105F and ADD EAX,ECX at1062.
  The requested condition became conditional movement, not a branch. These later
  forms are disassembly findings, not successful converter execution beyond a gap.

Exact hashes and complete commands/disassembly are in structures-report.json and
variation_*-disassembly.txt in each run's compiler-measurement-reports artifact.
PE timestamps change hashes across rebuilds; each comparison verifies unchanged
artifact bytes across hosts. Sources remain byte-identical to the freeze commit.
No production support changed in this measurement.

Next bounded gate: exact83 C4 08 two-word cleanup under the same current-owner Data
and unknown-ESP flag contract. Require unchanged shared.c to independently convert
and execute with Shared/empty/0 while preserving protected words, incomplete-cleanup
rejections and five prior programs plus102 pairs. Nested/conditional retain rejection.
This reuses the reviewed cleanup contract; medium effort is sufficient for a narrow
implementation and regression pass. A new ABI/flag uncertainty requires Astra High
before widening that slice. Tail transfers, argument stores and extra-register
conditional movement need separate future architecture work.

Ordinary CRT/XP7/general applications remain unsupported/unverified. Valid stack,
no faults/asynchronous mutation and regular-file/full-write assumptions remain.
The historical unrelated timeout is still unexplained.

## Subsequent production gates

SUB-522 requires unchanged shared.c acceptance. SUB-524 adds unchanged conditional.c
acceptance under the exact six reviewed forms; see SUB524-CONDITIONAL-IMPLEMENTATION.md.
The table above records the initial SUB-521 measurement, not current acceptance.
Both host harnesses require these two structural programs to convert while nested
continues rejecting RVA1050. Source/flag freeze and same-hashed-PE checks remain.
