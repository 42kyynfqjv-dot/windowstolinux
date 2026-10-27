# Heap effects measurement — partial SUB-577

## First completed Windows measurement

At af2b420849e991133de7702b9bee75cbfee62e87, push run40554018988 produced artifact
12756257376 on Windows Server2025 build26100. MSVC14.51.36231, Windows SDK10.0.26100.0;
cl/link exact paths and SHA256 are in report.json. Frozen source and configuration
commit f188f69 remains unchanged. These are custom-entry /O2 programs, not CRT apps.

| Program | Original successes | Real I/O failures | Converter result | PE SHA256 in that run |
| --- | ---: | ---: | --- | --- |
| grow |16|2|reject: linker IAT extent/alignment|60aa650d1288c56cb0f9499692d086036f2387644e9623dbb61b06b1f4f9e84f|
| shrink |16|2|reject: linker IAT extent/alignment|ffae3dae3c7c5f894e63b9825f3fa11de0b11bc61c24d6850f2ed65a35248ade|

All32 original successes match independent exact bytes/empty stderr/exit0. Four
real file-handle failure cases return read11 or write14 as expected. The frozen
programs do not force allocator OOM. Sixteen inputs per program are conformance
samples, not all-runtime-input proof. Native checks of these same PE hashes retain
the same rejection and preserve the output sentinel.

The independently authored Rust example calls the shared heap core and matches
all32 expected/Windows success observations locally. **Zero heap PE translations**;
no generated Rust or identical cross-host Rust claim. Native CI repeats this
component comparison and records it separately. Final-head workflow/artifact links
are maintained on PR43 and SUB-577, without replacing historical failure evidence.
Linker timestamps may change PE hashes in later builds; every comparison verifies
its own unmodified Windows-produced PE, not a reconstruction or assumed stable hash.

Local checks:148 unique root functions (138 inherited +10 new), formatting, Clippy,
five heap mutation detections using those10 tests, seven inherited memory mutation
detections and10 emitted-frame vectors. The example compiles the same core; its
inherited tests must not be counted again. Mutation review found the original test
could detect stale epoch while missing stale same-address generation; a direct
capability check now catches that omitted generation update. No production defect
was inferred from the original incomplete test alone.

Further review reproduced an evidence-harness defect: a report with an empty
program list exited0 and printed32 matches. Strict program/order, full observation,
image identity, timeout and error-outcome validation now precedes execution; six
malformed-report regressions reject. Summary counts are computed from checked
rows. This corrected evidence reporting, not converter semantics.

Complete listings establish additional SHL/SHR/OR forms and nullable heap ownership,
spills, byte access, resize-failure cleanup and output loops. See CONTRACT.md for
the exact first structural errors and cohesive continuation; permitting larger IAT
tables alone would be unsound. ISCC/rcedit still reject. Modern Windows comparisons
do not establish XP/7 behavior. Eight earlier original-Windows timeout causes plus
the separate PR37 same-head diagnostic occurrence remain unexplained.

Reproduce local component checks with cargo test --locked, cargo clippy --all-targets
--locked -- -D warnings, python3 research/process/check_memory.py and
python3 research/process/heap/check_guards.py. Windows: configured MSVC x86 prompt,
cargo build --locked, python research/process/heap/measure.py OUT. Linux consumes
that unchanged OUT artifact: cargo build --locked then
python3 research/process/heap/check_native.py OUT.

## Preserved first measurement failure

Head c23cceb, push run40553692359 stopped before compilation/observation because
Windows checkout changed cases.json line endings. Its pinned SHA256 is
08e4dbf0a238df8f8bfc40805b8263c7f2e362a8ec3f2585cc112b521bbe5973. Added explicit LF
checkout attributes; source, flags, vector semantics and frozen hashes are unchanged.
This is a harness provenance fix, not a converter or original-program timeout fix.
