# Agent instructions

Keep compatibility claims tied to independently reproducible original-versus-translated execution. Reject unsupported instruction and API behavior explicitly. Do not use proprietary executable fixtures. Keep work on feature branches and open reviewable pull requests; do not merge or publish releases without authorization.

Use Wine and Proton to identify API behavior questions and test ideas. Implement the required behavior independently in Rust from documented contracts and authored observable tests. Do not port Wine source, claim clean-room development without a real process, or replace mechanical recompilation with a Wine/Proton wrapper. Record requirement provenance; keep original code MIT OR Apache-2.0. Label and measure any dynamic binary-execution fallback separately from Rust-native API support.

## Standing GitHub push approval

The user grants standing approval to push changes for the ongoing WindowsToLinux project to `42kyynfqjv-dot/windowstolinux`. This approval was explicitly reaffirmed on 2026-10-31. Do not ask the user to reconfirm routine project pushes.

Keep the separate authorization requirements for formal PR approvals, merges, releases and deployments. A formal PR approval still requires specific user confirmation at approval time.
