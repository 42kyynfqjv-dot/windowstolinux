# SUB-547: installed runtime identity and first unresolved effect

This is a finite proof-feasibility measurement. It does not enable ordinary CRT.
The first boundary admits only register MOVs and a return; every memory operation,
call, branch, prefix-sensitive unknown or invalid instruction stops the effect
claim. Thus the maximum graph has one straight-line path. No successor beyond an
unresolved operation is assumed harmless. A call target is recorded, not executed
or recursively summarized. Limits are 4096 captured bytes and256 instructions;
these are stricter than the issue's maximum edge/depth budgets.

The independently authored x86 probe resolves __p__commode in the already-loaded
ucrtbase.dll. The target must belong to that same module; forwarded ownership
outside it rejects. ReadProcessMemory reads this process only. Live DOS/NT headers
must identify I386/PE32, the target must fit a nonwritable executable section and a
committed PAGE_EXECUTE_READ region belonging to that module. Capture is truncated
at region/section end. The runtime is held by the probe's normal CRT dependency;
no unload/concurrent mutation or image replacement is admitted in this experiment.

The probe opens the module path in its x86 context and obtains the canonical handle
path. The harness reads that file, validates I386, maps the exact RVA window and
applies every overlapping HIGHLOW relocation for the observed load base. Partial,
duplicate/overlapping or unsupported relocation records reject. The reconstructed
window must equal the live bytes. This supports identity of that window at capture,
not all loaded pages, IAT values, future immutability or the original program's
runtime instance. The loaded target need not share an address with prior runs.

Raw runtime bytes and the installed DLL remain transient on the Windows runner.
Only module/window hashes, architecture/base/RVA, relocation sites and abstract
instruction boundary metadata are uploaded. Original authored PE and probe hashes
bind the report. Linux checks report/source/probe provenance; it cannot independently
recompute live-runtime identity without those installed Windows resources. The
boundary metadata is not an independent execution oracle or native translation.

Primary API contracts: Microsoft PE/COFF specification (base relocations),
GetProcAddress (export resolution), GetModuleHandleEx (address ownership),
ReadProcessMemory (checked copy), VirtualQuery (region protection), and
GetFinalPathNameByHandle (resolved file path). SUB-546 ACCESSOR-CLOSURE.md records
the accessor/global-state/ABI contracts and limits. No proprietary source or Wine
implementation is imported. The decoder is the existing pinned iced dependency;
its classification alone never grants an effect proof.

Four independent Rust tests exercise a literal constant-return leaf, a direct call
with known target and blocked continuation, TLS/memory/branch/truncated boundaries,
and window/instruction limits. No sampled branch becomes a complete graph.

If the measured first boundary is an external call, memory/TLS selection or a
conditional path, record its exact address and dependency; stop this slice there.
Before another analysis extension, decide whether that dependency has a finite
contract. If it does not, the alternative is a separately authored freestanding
runtime-input program using a documented public API and explicit startup contract,
with unchanged compiler output and Windows/Linux comparison. That advances real
input behavior while ordinary CRT remains a named unsupported family; it must not
be described as replacing the original CRT program or bypassing its startup.

All previous12 compiler/102 authored comparisons and18 launch checks remain gates.
Four historical Windows timeouts remain unexplained. Server2025 does not establish
XP/7 compatibility. Medium substantive review precedes merging this research.

Two independent Python tests use a literal synthetic PE layout to verify rebasing,
unchanged preferred-base bytes and partial/duplicate/unsupported/unbacked rejection.

## Measured leaf and next decision

First CI40378191959 at022a1aa measured resolved RVA0x879d0 in the canonical x86
UCRT file f4d768583fd3fc020d30fd3a2d9d2f39dd2a5a49c99cc5e2040dfb61424a4778.
The analyzer reached RET after one immediate-register MOV, with no unresolved
instruction. The refined report identifies exact B8-imm32/C3 form, EAX destination,
returned object RVA and agreement with separate same-file pointer observations.
No runtime bytes are published. The larger4096-byte window includes neighboring
functions; only the reachable six-byte leaf is relevant to the effect argument.

Under immutable captured-code, valid return/stack and no asynchronous-fault premises,
this exact instruction pair writes EAX, reads/pops the return address and preserves
other registers/arithmetic flags. It has no TLS read, conditional branch, external
call or data write. This is a version-specific instruction argument, not a generic
API promise or automatic production certificate. The return object lifetime,
permissions/alias mapping at the original callback and all prior startup effects
still need composition proof. Failure outside those premises remains excluded,
not silently successful. Module replacements/other hashes require a fresh decision.

Next concrete gate: review this leaf identity/effect argument and specify a private
version-bound accessor-to-owned-cell composition certificate with exact object RVA,
relocation, owner lifetime and original-caller prerequisites. No further samples
are needed to establish the leaf instruction effects. If these original-context
premises cannot be discharged, retain CRT rejection and use the documented
freestanding runtime-input alternative rather than another isolated model.
