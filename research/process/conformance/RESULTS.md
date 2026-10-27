# Memory conformance evidence

Sources/expected bytes were frozen in commit 3799b1f before compiler or converter
measurement. Windows artifact 12750223072 from CI run40542178244 contains unchanged
MSVC14.51.36231 /O2 images, compiler/linker hashes and source hashes on Windows
Server2025 build26100. SDK10.0.26100.0. No source/flag tuning or binary edits.

| Program | PE SHA256 in first measured run | Original behavior | Integration result |
| --- | --- | --- | --- |
| slice | 4b262df799f4cb83c3fa942b396ae352605f6030ee6284a1f216f0eed34c276c |12 file vectors, two real I/O failures pass | Local generated ELF matches the frozen file vectors; final cross-host gate required |
| swap | 4a0680a5704cb7a52b308ea580a7dbb3d50fa7f0d2db340499cd035ce62382fe |12 file vectors, two real I/O failures pass | Local generated ELF matches all14 recorded observations; final cross-host gate required |

Both first hit the old exact-four-import extent restriction. The implementation
now checks bounded subsets of the same existing functions, with independent import
regressions. No new Windows API semantics were added. `swap` then passes the
existing frame/solver gates and uses the shared checked-memory runtime. The
workflow requires its acceptance and same-PE, byte-identical Rust on both hosts.

The first `slice` proof rejected store RVA0x1094, `[ESP+EDX+0x17]`, because
its constant anchor lies in preceding padding while EDX starts at1. The corrected
candidate discovery treats that anchor only as a lower bound for an unsigned
scaled index. Complete effective-address/initialized-range obligations still must
hold for a live disjoint region; count/saved slots are excluded. Zero-bias region
starts retain the existing narrower proof search (cross-region access still
rejects). This avoids unnecessary state enlargement in unrelated loops without
relaxing safety or increasing solver limits. Both unchanged programs now pass
locally. Five unsafe PE mutations and two exhausted-solver cases must still reject.
The frozen sources and expected outputs are unchanged.

An initial all-region candidate experiment exhausted existing LLVM proof resource
limits. It was not accepted, and limits were not raised. The final lower-bound and
zero-bias candidate restrictions pass all six retained LLVM graphs locally.

CI40543360596 also exposed a stale historical v1 uppercase harness assertion:
the new import-subset parser permits its three supported imports. The original
measurement assumed rejection. The harness now records acceptance and a Linux
comparison checks the **unchanged v1 pipe EOF result11 after correct output**, not
v2's corrected EOF behavior. The failed run is retained; this was not a timeout.

CI retains each run's exact PE hash; linker-generated timestamps may change between
builds, so this table does not claim byte-reproducible builds. Final-run artifacts
and PR evidence are authoritative for final-head comparisons. The unchanged
original PE in each run must be the PE consumed by both converters.

New conformance evidence:24 original file observations +4 original failure
observations, with28 genuine comparisons required across both programs.
Core tests and existing streaming comparisons are counted separately. These
custom-entry programs do not exercise Heap APIs, ordinary CRT, or third-party
application startup. Empty/odd/even/capacity cases use independent slicing/pair
expectations and untouched binary bytes. Eight historical Windows timeout causes
remain unexplained; no retry is a diagnosis.
