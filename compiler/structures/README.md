# SUB-521 preregistered structural measurement

These three sources and cases.json observations are fixed before first compilation.
Nested: inner(7,5)=12, checked inside outer; inner(12,3)=15. Shared: same helper
returns12 and7, both checked. Conditional: helper(7,5)=8, helper(3,4)=7; deliberately
expect9 in entry and observe failure exit99. Output is respectively Nested, Shared,
Branch, six ASCII bytes each; stderr empty. Expectations are arithmetic specified
independently of the converter, not extracted from emitted code.

Run compiler/measure.py, compiler/diversity.py, then compiler/diversity.py --structures
under the existing MSVC x86 environment. All use precisely the documented baseline
/O2 /W4 /DFREESTANDING /GS- /Zl custom entry flags. Available compiler version is
recorded, not immutable pinned. No source rewrites, flag search or PE edits after
measurement. Compiler optimization can remove or reshape requested structure;
actual dumpbin output decides observed diversity. Source intent alone is insufficient.

Every original must meet the frozen Windows expectations. Accepted cases must
independently convert twice on Linux from identical hashed PEs to identical Rust
and matching stdout/stderr/exit; rejected cases must preserve output and agree
on diagnostic across hosts. No acceptance quota; unsupported results are evidence.
All reports, authored PEs and disassembly join the existing CI artifact. Existing
five compiler comparisons and102 authored pairs remain separate mandatory gates.
Ordinary CRT, XP7/general apps, stack faults and non-regular output environments
remain beyond this measurement. New semantics require a separate evidence-backed
contract and Astra High handoff.
