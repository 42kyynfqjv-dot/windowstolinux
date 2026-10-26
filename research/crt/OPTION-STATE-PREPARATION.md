# Independent SUB-541 preparation while PR #1 merge is blocked

This worktree branches from reviewed d80d79a and does not change PR #1's merge head.
The five literal byte vectors in option-state-vectors.json were specified before
implementing the effect engine. They expose little-endian byte changes, nonzero
high-word preservation and idempotence. Masks are explicitly hexadecimal0x24 and
0x02 (decimal36 and2), as in the observed x86 OR instructions; unqualified24 in
older gate prose must not be interpreted as decimal24.

These are specifications, not executed native evidence or additional passing tests.
The negative list defines concrete owner/bounds/provenance scenarios for Astra High
implementation. EAX/final flags follow the callback's final XOR; they do not describe
intermediate helper flags. Prior blocked state remains blocked across compositions.

Next Astra High turn should bind original artifacts, implement the reviewed test-only
owned effect, consume these fixed expectations and add a separate authored C/CPU
operation comparison. Production ordinary CRT stays rejected. Publish on this fresh
feature branch/draft PR after coordinating the outstanding PR #1 merge, preserving
its exact head. Future PR merge requires separate authorization.

Implementation now lives in examples/crt_option_state.rs; see OPTION-STATE-IMPLEMENTATION.md for executed evidence and limitations. The paragraphs above preserve the preregistration checkpoint.
