# Independent streaming corpus result

Freeze d4abc13 precedes evaluation. Measurement commit be7354b,
CI40437531308 on Windows Server2025/build26100: all six unchanged compiler
programs pass174 independent Windows file/pipe/failure baselines. All six
conversions reject: **zero new ELF translations**. See RESULTS.json for exact
per-run PE hashes and diagnostics; relink timestamps may change later hashes.
MSVC compiler/linker versions and actual commands are retained in uploaded build
logs. Each later run checks its own unchanged PE hash across hosts.

| Source | Structure | O1 first rejection RVA | O2 first rejection RVA |
|---|---|---|---|
| ROT13 | four ASCII branches; byte load/modify/store |10ec NEG|1122 NEG|
| XOR | reverse traversal; in-place byte XOR; DEC |10be NEG|10f9 NEG|
| NUL compaction | distinct input/output indices; conditional store |10d0 NEG|1105 NEG|

The first rejection is shared compiler lowering of the authored ternary EOF/error
return. Full disassembly shows GetLastError; SUB EAX,109; NEG EAX;
SBB EAX,EAX; AND EAX,11. It computes0 exactly for error109 and11 otherwise.
These are observed instruction facts, not proof of production support after NEG.
The profile also forbids scalar arithmetic on opaque errors; simply decoding NEG
would not establish sound admission. XOR adds DEC and a non-self memory XOR.
ROT13 modifies partial-byte registers; compaction carries two related indices.
Their later proof/operand/frame eligibility remains unmeasured behind rejection.

Recommended next cohesive gate (Astra High): inventory all six actual graphs and
implement reusable exact scalar/flag semantics for the error-selection idiom and
reverse counter, with a sound observation contract for opaque error equality,
byte operations and loop-carried index relations. Prove wrapping/CF behavior and
all error classes; do not recognize a fixture graph or rewrite compiler outputs.
Include independent32bit boundary/flag truth tables, non-self byte operations,
unsafe bounds/stale prefix/unknown-clobber cases and resource rejection. Target
these six unchanged outputs and174 Windows/ELF pairs, reporting partial admission
honestly if the existing solver cannot prove compaction/partial-byte relations.
Keep one integrated PR with review/testing, not one issue per opcode.

This selected corpus establishes a reuse limit: the successful uppercase program
has not generalized to these independent compositions. It does not measure a
compatibility percentage. Common I/O is independently authored using the prior
reviewed contract; source/scaffolding similarity and shared error expression limit
independence. Transformation expectations use Python byte translation, mapping
and filtering, not converter semantics. Thirteen cases are finite observations;
none proves all-input equivalence, partial OS scheduling or total termination.
No forced partial-I/O cases are counted as real Windows process executions here.

Reproduce in x86 MSVC shell: python research/cli/corpus/measure.py <directory>.
On Linux after downloading the same artifact: python3
research/cli/corpus/check_native.py <directory>. Exact rejection diagnostics and
output sentinels must agree; accepted cases must additionally agree in generated
Rust and actual output/stderr/exit. No support expansion was made for measurement.

Initial CI40437390365 stopped before compiler evaluation at frozen-file hash
validation: new nested JSON lacked an LF checkout rule. Commit be7354b added it;
frozen bytes/expectations stayed unchanged. This is a diagnosed checkout issue,
not one of five earlier unexplained Windows process timeouts. No silent retry,
relaxed deadline, binary editing or source/flag tuning was used.
