# SUB-541: isolated owned option-state effect

`examples/crt_option_state.rs` is a research executable, never imported by the
production converter. It binds one owned preferred-base PE snapshot to the exact
callback at RVA 0x10e0, helper 0x1770, accessors 0x1750/0x1760 and callback-table
word 0x20cc. The instruction bytes and their direct call targets are checked in
full. Required HIGHLOW sites are 0x1751, 0x1761 and 0x20cc; unexpected relocations
through those code ranges, overlapping records and additional relocated pointers
into the option words reject. Addresses and section profiles are deliberately
fixed for this experiment. This is not a general hostile-input PE loader.

Two separate initialized writable eight-byte regions at 0x30d0 and 0x30d8 are the
only data authority. Both are validated before an effect is returned. Checked
file/virtual backing, permissions, raw aliasing, data directories, relocation
sites and complete initialization exclude partial/BSS/code/header/metadata ranges.
Any changed accessor address rejects, including callback slots and neighboring
cookie/onexit/TLS state. The parser does not infer global alias freedom: unrelated
code, non-relocated pointers and external imports remain unresolved. Exclusive
ownership, valid disjoint stack and fault-free execution with no asynchronous
mutation are explicit assumptions for this isolated operation. They are not
established for actual CRT startup.

The immutable `Bound` borrows its one `Snapshot`; `effect()` accepts no substitute
image, region or state. No effect mutates input, including on rejection. A snapshot
already blocked by an unknown effect cannot bind. The isolated command starts a
fresh research snapshot; it cannot certify that preceding callback 0x1030 produced
such a state. No result is wired into the earlier dispatch model or emission.

## Concrete effect

Masks are **0x24 (decimal 36)** and **0x02**, not decimal 24. For each region the
helper reads the high dword, ORs the low dword and writes the high dword back
unchanged. The returned 16 bytes describe both complete eight-byte writes, including
unchanged high words; this does not authorize omitting their original reads/writes.
ECX ends with the second high dword. The callback's final XOR sets EAX=0,
CF=OF=SF=0, ZF=PF=1; AF is undefined (`None`/JSON null). The model also computes each
intermediate OR's CF/OF/ZF/SF/PF and leaves AF unknown. MOV/CALL/RET preserve those
flags. Other registers are preserved, subject to the valid stack precondition.

Relative to callback entry, nested calls use at most eight bytes below incoming
ESP. Their RETs balance those pushes. The callback RET consumes the incoming return
word, so final ESP is entry ESP+4. The model does not invent a numeric ESP, expose
return-address bytes or model stack faults. The separate CPU operation probe omits
call/return scaffolding and checks data/register/defined-flag effects only; exact
original call bytes support the stated conditional stack calculation.

Instruction contracts: Intel Software Developer's Manual, volume 2, MOV/OR/XOR/
CALL/RET, https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html .
PE field/relocation contracts: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format .
MSVC x86 inline assembler for the authored probe:
https://learn.microsoft.com/en-us/cpp/assembler/inline/inline-assembler .
Implementation and probe were independently authored; no third-party implementation
source was copied. Original project MIT OR Apache-2.0 applies.

## Reproduction and accounting

Run `cargo test --locked --example crt_option_state` for 11 new Rust functions.
These include 49 individual instruction-byte corruptions and 9,216 truncated
synthetic files; those are subcases, not additional test functions. The fixture is
an independently authored PE-shaped profile, not a runnable Windows executable.
The nine preregistered negative scenarios map to initialization, accessor target,
metadata/relocation, altered form and blocked-state tests. Cross-image mixing is
excluded by the borrowed API and exercised by two independent snapshots with
different high words; that check is not an executed rejection of a public foreign
handle, since no such handle input exists.

`python research/crt/check_option_state.py EVIDENCE --windows-probe` runs inside the
existing x86 MSVC environment. It checks the unchanged held_crt manifest hash and
continued conversion rejection, binds the original bytes, then applies five fixed
literal vectors in isolated synthetic data snapshots. `option_probe.c` independently
executes authored x86 operations on local arrays, checking bytes, EAX, ECX and the
defined flags. The probe is compiled with `/W4 /WX /O2`. It never executes copied
original PE code. The five vectors were frozen in d45b0ff before implementation.

`python3 research/crt/check_option_state.py EVIDENCE --compare` on Linux checks the
same PE hash, deterministic Rust results, the five CPU observations, source/spec
hashes and the uploaded probe binary hash. Reports are crt-option-state.json and
crt-option-cpu.json. Synthetic vector overlays never modify the original PE file.
The Windows original-program baseline, debug observer and isolated CPU probe are
three distinct evidence sources.

Existing counts remain 79 root Rust functions, eight initializer Python functions,
six research graph checks, 12 compiler-program comparisons, 102 authored comparisons
and 18 original-only launch diagnostics. These five CPU/model cases add no translated
programs. CI also retains all four held-out conversion rejections. Modern Windows
Server 2025 evidence does not establish XP/7 compatibility. Three historical
Windows fixture timeout causes remain unresolved; no retries or threshold changes
are introduced here.

## Review gate

Review exact profile/provenance binding, both-region prevalidation, the explicit
ownership assumptions, cross-snapshot lifetime, undefined AF and stack accounting.
Check CPU probe source and its actual CI results independently of model expectations.
Keep complete_startup_proof=false and emission_allowed=false. Callbacks 0x1030 and
0x10f0, external state/aliases, initialization and failure/exit paths still prevent
ordinary CRT translation. This component alone grants no native startup replacement.
