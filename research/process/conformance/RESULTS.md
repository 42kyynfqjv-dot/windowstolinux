# Memory conformance evidence

Sources and independent byte expectations were frozen in commit 3799b1f before
compiler/converter measurement. The first Windows run is pending. No accepted
program or original-versus-translated execution is claimed yet. The workflow
retains source/toolchain/PE/Rust hashes, complete disassembly/imports, 24 regular-file
observations, four error observations and exact conversion outcomes in
`memory-conformance-windows`; `memory-conformance-native` records Linux results.

Neither custom-entry source exercises Heap APIs or ordinary CRT startup. The
existing streaming corpus separately verifies the shared emitted-memory integration.
