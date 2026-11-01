# Original boolean helper and environment entry

The original helper0x401bd5 is MOV AL,1; RET. It defines only the low byte,
preserves upper-EAX knowledge and integer flags, and consumes the original
protected return. The actual caller TEST AL,AL and branch run. No boolean value
is substituted by an API callback or expected-output table.

Original CALL0x4015e9 enters0x406c9c. Its exact five-byte tail JMP targets0x406a0b
and preserves the same activation. The original initialization check reads
0x41ce48; an already initialized path returns0 via the actual XOR/RET. The real
uninitialized startup path pushes ESI, calls the existing original locale
initializer0x40b42a, then calls original producer0x40b966. That producer's frame
prolog and saved registers execute. The next unsupported effect is **IAT
CALL0x40b96e, kernel32!GetEnvironmentStringsW at0x4150e4**. No environment data,
allocation, conversion, publication or cleanup success is fabricated.

Four frozen original regions match the unchanged authored PE: three-byte boolean
helper, five-byte tail thunk, 23-byte manager prefix and eight-byte producer
prolog. IAT0x4150e8 is FreeEnvironmentStringsW. The next source path scans UTF16,
uses original conversion0x40b8c5, allocates a narrow buffer and frees the Windows
snapshot. Manager0x406a65 builds the environment table, with publication at
0x41ce54/0x41ce48 and non-null CRT free paths. Those effects are not admitted here.

## Tests and review

Seven independent boolean cases cover known/unknown upper bits, flags, callee
registers, invalid return authority and replay. Seven artifact cases cover actual
byte guards, mutations, expired initialization, foreign thread, duplicated return
and unknown upper bits. Four environment-prefix cases cover ready/unready/unknown
initialization and callback failure after an observable write. On nested failure,
actual child-call storage and earlier writes remain; no cleanup is invented.
The real original-entry composition checks the saved ESI and FP state at the
GetEnvironmentStringsW boundary. Supplied-callback cases remain component tests.

Review of e90af45 found no further query/provenance defect. Its full local replay
finished with five retained component comparisons, zero whole-PE pairs and Rust
SHA25638de1d8dcd6c30b1d1c43a1df60511e125d538014136ee28f8c97de7887f5afe.
Both Rust CI runs41357619443/41357613506 passed at the recorded review read;
inventory41357613505 was still pending. New final-head checks are separate.
An initial new test expected an unknown comparison to reach branch evaluation;
the existing lowering instead rejects unknown scalar knowledge. Another expected
a failed callback to have returned its frame. Both oracles were corrected to
preserve the actual rejection/state, without changing runtime behavior or dropping
assertions. Failed logs remain in the local evidence directory.

## Next bounded contract

Define an owned UTF16 double-NUL environment snapshot and its resource lifetime
for GetEnvironmentStringsW/FreeEnvironmentStringsW. Retain ordering, hidden drive
entries, non-ASCII input, case collisions and mutation/snapshot semantics under an
explicit native launch policy. Existing UTF8 conversion is a reusable dependency;
it does not establish this API's resource/error semantics. Empty environment,
NULL/error cases, buffer bounds, stale frees and failure partial effects require
independent expectations. Native host environment is not automatically a Windows
snapshot. Broader freeing and resource equivalence remain open. Full startup,
rcedit/default support and historical timeout causes remain unproved.
