# Agent instructions

Keep compatibility claims tied to independently reproducible original-versus-translated execution. Reject unsupported instruction and API behavior explicitly. Do not use proprietary executable fixtures. Keep work on feature branches and open reviewable pull requests; do not merge or publish releases without authorization.

Use Wine and Proton to study API behavior and design tests. Do not replace mechanical recompilation with a Wine/Proton wrapper. Review exact component licenses and record provenance before reusing source or tests; keep original code MIT OR Apache-2.0. Label and measure any dynamic binary-execution fallback separately from Rust-native API support.
