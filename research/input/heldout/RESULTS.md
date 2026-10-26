# SUB-560 held-out measurement

Preregistration commit06dc3f0 fixed four C sources, O1/O2 configurations and14
literal expectations each before any evaluation. Measurement run40410456789 at
04bf7ab8e7f752accca860c5ddacd075a7e43af4 passed all five CI jobs. Windows artifact
12692352644 and Linux artifact12693361769 retain exact reports and PEs. Hashes below
identify that run; PE timestamps change on a subsequent build, so compare both
hosts within the same run rather than requiring cross-run PE byte equality.

Windows Server2025 10.0.26100, MSVC19.51.36260.0 (installed14.51.36231 directory),
fixed freestanding x86/no-default-library/GS-disabled experiment. O1/O2 are the only
optimization differences. Commands, compiler component versions, disassembly and
imports are retained as div_hold_*-*.txt. LF source and vector bytes are enforced.
First run40410207902 failed before corpus evaluation because Windows checkout
changed cases.json line endings; .gitattributes fixed checkout bytes, not the
frozen source or expectations. No retry masks an execution timeout here.

## Outcomes

Four unique programs, eight source/configuration artifacts,112 original Windows
stdout/stderr/exit scenarios passed. Zero artifacts accepted, zero new translated
programs and zero new Windows/ELF pairs. Linux independently reproduces all eight
rejections on the same hashed PEs and checks prior acceptance/diagnostic equality.
This measures current limits; it does not establish equivalence for rejected code.

| Program/config | First diagnostic RVA | Instruction / interpretation | PE SHA256 in measured run |
|---|---|---|---|
| shared_O1 | 1000 | PUSH EBP: EBP frame/prologue model absent | d31b662dfbfe8b3aa9040498d6499f8e8d53937112bc94dff0d13c297624b6f6 |
| shared_O2 | 103f | LEA EAX,[ESP+8]: saved-ESI stack-relative capability form absent | b743e7d09883e7654e49c4628eda1e32300c114b2c0bba1934b58a0c2b3d34de |
| nested_O1 | 1016 | PUSH EBP: EBP frame/prologue model absent | b0d4cef6e2f4bb331008a7ae95d64b0331bf052350680f60482c00ed2d7de5d1 |
| nested_O2 | 107b | MOV EDX,EAX: scalar/capability register-copy form absent | 9832c51b381337a4b6c06b52e0b1a746f01888245e1d5024cfd6d14a8ae004ae |
| composed_O1 | 1000 | PUSH EBP: EBP frame/prologue model absent | becede3dc634ae65a7c6e4d56d53bf35b6ee5c4d80f7d9e768c361924635609b |
| composed_O2 | 104b | CMP EAX,imm32: post-call result comparison form absent | 3365274027b6a9046e23573316064f560b4b718037bba0ff9d17bb96de1745d8 |
| larger_O1 | 1000 | PUSH EBP: EBP frame/prologue model absent | 63c8f342db3de6b65c894f0a7c465f4a4960802fe8b99f686450d9229cfb4e72 |
| larger_O2 | 1000 | SUB ESP,12: larger allocation/capacity contract absent | f622991f5f346033a43d3b82c5aeda9585823ee068111df20e8f637a7451d50e |

## Structural evidence and next prerequisite

Disassembly confirms shared_O2 has two calls1044/1062 to the same helper1080 and
stores the first scalar return in ESI. Nested_O2 has entry call1063 to1070, with
calls1076/109a from that helper to1000. Thus nested/shared machine composition
survived compilation. Composed_O2 calls1070 at1043, then compares EAX with202 and
scales a successful return using LEA [EAX*2+6]. Larger_O2 allocates12bytes and passes
capacity5; accepting SUB ESP12 alone would not establish buffer/API range safety.
The O1 artifacts demonstrate a real frame-pointer prerequisite, not generic app
support. Complete listings remain authoritative for all additional forms.

First unsupported instruction is not a complete feature inventory. In particular,
adding CMP EAX,imm32 to composed_O2 alone would expose callee argument/WORD forms
using ECX and EAX plus EDX comparison and different LEA encodings. More fundamentally,
the existing refiner expects a single affine variable with coefficient1. A caller
comparing a multi-symbol helper return or constant error202 needs sound predicate
entailment from each returning path, not fabricated range narrowing or sampled
branch selection. Return paths already distinguish error constants from guarded
success ranges; reusable bounded entailment can exploit those facts.

Review reproduced that refiner limitation with test-only constant202 and
multi-symbol affine expressions compared with202: both reject as unsupported
predicates even though a constant equality or disjoint result bounds can decide
that comparison. This is source/model evidence for a later proof prerequisite,
not a newly observed semantic-stage rejection of the untouched PE: decoding stops
first. It is relevant to composed_O2 and shared_O2 caller checks, not a shared
first cause across all eight artifacts. EBP frames, larger capacity and nested
pointer/CMOV effects remain separate blockers. The design must inventory those
additional dependencies and cannot promise acceptance from predicate work alone.

Prioritize a bounded design/model for post-call scalar predicate entailment and
register-independent argument/WORD operands. Start from composed_O2's immutable
return expressions/path ranges; prove comparison outcomes when bounds entail them,
otherwise retain existing valid refinement or reject. Preserve wrapping/truncation,
ownership and volatile/flag limits. Do not implement EBP frames, saved scalar ESI,
arbitrary pointer increments or larger buffers in the same design. Astra High is
appropriate for the proof design; medium measurement/review remains sufficient
for this report. Implementation needs a later reviewed gate and unchanged artifact
Windows/ELF evidence. No converter support changed to improve these results.

## Coverage limits and reproduction

This is a deliberately selected authored freestanding MSVC corpus, not a random
or independently blinded application sample. Sources were written knowing the
current support and known gaps, but their acceptance was not evaluated before
freezing. Shared/nested/composed share a decimal-input task to isolate composition;
they do not supply broad algorithm coverage. Only14 inputs per artifact are original
observations; no exhaustive compatibility percentage follows. O1/O2 do not measure
other compilers, x64, ordinary CRT, GUI, arbitrary environment mutation or Windows
XP/7. Four older held-out families and historical timeout causes remain unresolved.
Prior16 compiler programs/51 input-composition pairs/102 authored/18 launch evidence
remain required in the same CI workflow.

On an existing MSVC x86 developer environment after cargo build --locked:
`python research/input/heldout/measure.py EVIDENCE` writes originals/reports.
Transfer that entire evidence directory unchanged to Linux and run
`python3 research/input/heldout/measure.py EVIDENCE --compare` after cargo build.
The harness hashes frozen source/expectations, preserves output on converter
rejection, compares host-independent Rust for accepted programs, captures every
launch stage/hash and persists failure data with no silent retries. Existing CI
runs both stages and uploads reports even on failure. Do not edit frozen sources,
compiler flags or generated PEs to manufacture acceptance.
