# Memory conformance evidence

Sources/expected bytes were frozen in commit 3799b1f before compiler or converter
measurement. Windows artifact 12750223072 from CI run40542178244 contains unchanged
MSVC14.51.36231 /O2 images, compiler/linker hashes and source hashes on Windows
Server2025 build26100. SDK10.0.26100.0. No source/flag tuning or binary edits.

| Program | PE SHA256 in first measured run | Original behavior | Integration result |
| --- | --- | --- | --- |
| slice | 4b262df799f4cb83c3fa942b396ae352605f6030ee6284a1f216f0eed34c276c |12 file vectors, two real I/O failures pass | Remains rejected by memory-range proof |
| swap | 4a0680a5704cb7a52b308ea580a7dbb3d50fa7f0d2db340499cd035ce62382fe |12 file vectors, two real I/O failures pass | Local generated ELF matches all14 recorded observations; fresh cross-host gate required |

Both first hit the old exact-four-import extent restriction. The implementation
now checks bounded subsets of the same existing functions, with independent import
regressions. No new Windows API semantics were added. `swap` then passes the
existing frame/solver gates and uses the shared checked-memory runtime. The
workflow requires its acceptance and same-PE, byte-identical Rust on both hosts.

`slice` is not called unsafe on the strength of an abstract SAT result. Its store
at RVA0x1094 is `[ESP+EDX+0x17]` with EDX starting at1. The static constant address
anchor lies one byte before the input buffer. Current region selection associates
it with the preceding four-byte local at relative -36 rather than the buffer at
-32. The generated bad4244 ownership/range obligation is SAT (query57); no Rust
is emitted. Supporting this requires a sound owner-plus-symbolic-offset selection
proof, including exclusion of preceding count/saved slots, not suppressing SAT or
changing the fixture. This remains the concrete second-program acceptance gap.

CI retains each run's exact PE hash; linker-generated timestamps may change between
builds, so this table does not claim byte-reproducible builds. Final-run artifacts
and PR evidence are authoritative for final-head comparisons. The unchanged
original PE in each run must be the PE consumed by both converters.

New conformance evidence:24 original file observations +4 original failure
observations, with14 genuine comparisons required for the accepted program.
Core tests and existing streaming comparisons are counted separately. These
custom-entry programs do not exercise Heap APIs, ordinary CRT, or third-party
application startup. Empty/odd/even/capacity cases use independent slicing/pair
expectations and untouched binary bytes. Eight historical Windows timeout causes
remain unexplained; no retry is a diagnosis.
