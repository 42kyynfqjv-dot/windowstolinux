# Independent check of the bounded CI audit

The routine audit of 69b844fd correctly reported its pending workflows, exact
commit/tree identity, predecessor failure, and component-only evidence. It did
not verify a completed cross-host artifact pair because those jobs were pending.
That was an explicit limit rather than an incorrect success claim. It handled
this narrow metadata/local-evidence task successfully; this provides no evidence
for expanding its runtime implementation scope.

The independent source check found published commit
`69b844fdf6b8c85a845f7535ee42441611877580`, parent
`16951511c536f35d671ef821b7110a5ed813fbd4`, tree
`a8daf3ef93f0e3a98ff6b516cf4a4beae4c5fa8a`. Local commit 503dccca has that same
tree. No remote-versus-local content mismatch was found.

Startup run 40809390166 subsequently completed successfully. Downloaded artifacts:

| Artifact | ID | Verified ZIP SHA-256 |
| --- | --- | --- |
| startup-unwind-slice (Windows) | 12869318052 | 85e55fd61f08dcce3c39b76c02bee235fed75d02bf42714cf40e14ff621234ed |
| startup-unwind-native (Linux) | 12870285387 | e2d79253f35f4da3c1287ca90a1c7e0435bc4be494a0dc188bd5442a1e3f0d38 |

The PE bytes in both ZIPs hash to
`21735228fe1ab8938c26a08db0ce76e019ad1aa9d7e91afc6ed590bac30f129f`.
Both `normal-wrapper-windows` and `normal-wrapper-linux` reports identify that
same PE and emitted Rust
`3be6641997c5d0d1b8838fc3b179cc4817d6892145656587ec931677c6ac6edb`.
The actual Rust files are byte-identical and match the recorded hash; the five
wrapper result lines are identical. Linux records its comparison to the Windows
report. Both report 36 finally component scenarios, zero finally Windows pairs
and zero whole-PE translation pairs. Those counts have different meanings.

The older local evidence PE is
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
It must not be claimed as the CI rebuilt PE. Emitted Rust matches across those
builds, but each cross-host PE comparison uses its own identical original file.

For predecessor 16951511, full run 40807719716 and startup 40807719740 passed.
Full run 40807728976 failed original Windows imported-output hello execution,
job123230560030. Artifact12868966896 has independently rechecked ZIP hash
`8d423144595dbc8b33a7ecd02b06e56b02f9b1c11272b78d631f11004abb66f8`.
Its launch JSON records Hello stdout, empty stderr, alive after15s, kill/reap1;
PE `30a0afa2dba23697256b96df129e62a9cc7c099edf68bfcb87eaf125fc3757e3`.
The successful parallel run does not explain or erase this failure. Historical
original Windows timeout causes remain unresolved.

The initial focused regression passed during the routine audit. Subsequent
implementation validation uses a changed working tree and is reported separately
in LIVE-FINALLY.md; it is not retroactively attributed to 69b844fd. No merge,
formal PR approval, or full startup/rcedit support follows from this audit.
