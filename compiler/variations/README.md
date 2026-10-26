# Frozen SUB-519 compiler diversity measurement

Four independently authored C sources and cases.json expectations are frozen in
this commit before CI compilation. Use precisely the baseline /O2 /W4 /DFREESTANDING
/GS- /Zl and /NODEFAULTLIB /ENTRY:entry@0 configuration; /Bv records tool versions.
This is the documented minimal custom-entry experiment, not ordinary CRT startup.
No PE edits or flag search. LF checkout and source/PE/Rust hashes are mandatory.

Expected Windows results, specified before measurement:

| Source | Reason | stdout | Exit |
| --- | --- | --- | --- |
| changed.c | helper(7,4)=11 and changed immutable bytes | Value | 0 |
| helper_failure.c | helper(7,5)=12 differs from13 | Hello | 99 |
| write_failure.c | five output bytes differs from expected6 | Hello | 99 |
| three_arguments.c | helper(7,5,3)=15, deliberate ABI boundary probe | Hello | 0 |

All stderr is empty. All sums are bounded defined signed arithmetic. Compiler
optimization may collapse or reshape checks. Record actual instructions before
claiming structural diversity; constant changes alone do not establish it.

Every original executes on Windows. Accepted cases must independently convert
on Linux from the identical hashed PE to byte-identical Rust, then execute with
exact stdout/stderr/exit. Rejected cases retain exact first diagnostics and must
reject on Linux while preserving output. No acceptance quota or converter changes
to force these programs through. Baseline and102 prior pairs remain separate.

## SUB-520 implementation gate

The measurement above remains historical; the frozen C sources, expected outputs
and compiler flags are unchanged. After implementing the two observed forms, both
host harnesses now require all four variants to be accepted. Rejection of any one
fails CI; it cannot silently count as a successful implementation checkpoint.
See ../../SUB520-THIRD-ARGUMENT.md for the narrowed semantic contract.
