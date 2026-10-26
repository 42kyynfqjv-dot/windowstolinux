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
