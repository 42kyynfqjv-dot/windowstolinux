# SUB-519 frozen four-source results

Sources/expectations frozen in b407fb690efdd899637a273540b4048d19e615e8 before
compilation. First measurement CI40275598174 completed all five jobs successfully.
Fixed baseline MSVC19.51.36260.0 / LINK14.51.36260.0 on Windows Server2025;
source LF policy and compiler options unchanged. No production code, binary edits,
flag search or program rewriting. Exact flags/source/Rust/PE hashes are retained
in diversity-report.json and disassembly/relocation text artifacts for each run.
Rebuild timestamp changes can change PE hashes; each experiment transfers its own
exact original PE to Linux without rebuilding or modifying it.

| Frozen variation | Windows original | Linux conversion/execution | Structural evidence |
| --- | --- | --- | --- |
| changed | Value / empty stderr / exit0 | accepted; identical Rust and output/exit | baseline shape; changed constants/data |
| helper_failure | Hello / empty stderr / exit99 | accepted; identical Rust and output/exit | baseline shape; first JNZ failure outcome |
| write_failure | Hello / empty stderr / exit99 | accepted; identical Rust and output/exit | baseline shape; second JNZ failure outcome |
| three_arguments | Hello / empty stderr / exit0 | rejected identically; output preserved | extra push, six-word cleanup, third argument read |

First-run original PE SHA256:

- changed: 124ee4aa8560372645f59d04fcd4e1444996bf8a3c9540be5d05785850d2d479
- helper_failure: 9b9314bc3216edf9fe352082b405fdc66d9cae148b0a5a463389d1113ce3bda9
- write_failure: 8d0d71713fdf1b53681854de0cc50ee77253ed46ee4d2d70de9358e790c8a6fb
- three_arguments: 88c82038782568c603479598440706a2751f4df0089933659596b189905d773a

Exact rejected diagnostic on both hosts:
`w2l: linker intake validated; emission blocked: unsupported 83 form`.
Disassembly identifies RVA101D bytes83 C4 18 ADD ESP,24 as the first unsupported
instruction. Helper RVA1048 bytes03 44 24 0C ADD EAX,[ESP+12] is another uncovered
form. This second gap is a source/disassembly finding, not a claim that production
continued after the first error. Both need explicit ownership/flags acceptance.

The three accepted variants add outcome/data evidence for one compiler structure;
they are not three new structures. There are now four accepted compiler-built
programs including baseline, separately counted from102 existing authored pairs.
Six local-only literal native cases and model traces remain separately counted.
Ordinary CRT remains rejected; no XP7/general application compatibility claim.
Valid stack, no-fault and printable ASCII regular-file/full-write assumptions remain.
Historical unrelated corpus timeout is still unexplained.

## Next bounded gate

Astra High should first specify then implement only third caller-Data access for
03 44 24 0C and six-word cleanup for83 C4 18 in the linker profile. Preserve top
callee Return, direct-caller ownership, ESI saves/protected returns and full typed
scalar checks. Arithmetic flags follow ADD; cleanup flags become unknown until
redefined. Negative tests must reject saved/return/foreign words, missing third
argument, incomplete cleanup and neighboring offsets/prefixes/forms. No general
register/memory/ABI expansion. Completion requires this unchanged three-argument
PE to pass the same hashed Windows/Linux chain while preserving all current cases.
This changes shared validator/emitter state semantics, so Astra High is justified;
return to medium for review afterward. Current measurement has no external blocker.
