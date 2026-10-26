# SUB-549: bounded runtime environment input

This is a new freestanding capability track. Ordinary CRT startup and the four
remaining held-out conversions remain blocked. The C program has an explicit
custom entry; it does not replace the entry of an existing CRT program. Production
conversion of this new program must also reject during this design phase.

## Choice and primary provenance

Microsoft [GetCommandLineW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew)
returns system-owned command-line text; the executable name may be expanded by the
OS. Linux argv loses original quoting and spacing. A general reconstruction would
invent observable text. We decline that mapping for this gate and select the
previously authorized named-environment-variable alternative.

Microsoft [GetEnvironmentVariableW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew)
reads the calling process environment. Capacity includes the UTF-16 terminator;
success returns the stored length excluding it. Insufficient capacity returns the
required length including the terminator and leaves buffer contents undefined.
Failure returns zero; missing names set ERROR_ENVVAR_NOT_FOUND. Our program does
not inspect last-error state. No internal CRT accessor is required.

These public API contracts specify the boundary; implementations and fixture
sources are independently authored, MIT OR Apache-2.0. No Wine or proprietary
source port, runtime interpreter or AI runtime is used.

## Frozen observable contract

Name: exactly `W2L_INPUT`. Input comes from the launch environment at execution,
not conversion. Parent harness removes inherited variants of this name and sets
only the exact uppercase spelling. Domain: at most one case-insensitive matching
name, well-formed Unicode without embedded NUL, stable during execution. Other
variables have no application-visible role. Windows case-insensitivity versus
Linux case-sensitivity is restricted by this domain; arbitrary aliases/duplicate
names are outside it and must be rejected by future runtime admission.

Caller owns a writable, aligned six-byte local buffer (three WCHARs). Name is an
immutable, terminated UTF-16 literal. Invoke GetEnvironmentVariableW once with
capacity 3. No environment mutation, retries or buffer resizing.

| Condition, in evaluation order | Process exit |
| --- | --- |
| API returns zero (including missing/empty or another failure) | 200 |
| Returned length exceeds 2 | 201 |
| Any of the one or two returned code units is outside ASCII 0..9 | 202 |
| Otherwise | Decimal integer 0..99, allowing leading zero |

All outcomes have empty stdout/stderr. Buffer contents are never read on zero or
overflow. Zero-return failures are deliberately indistinguishable in the authored
program; this does not claim their causes or last-error effects are equal. The
success domain assumes normal process environment access. The separate native
prototype maps missing/empty to 200; it does not simulate OS allocation/fault
failures. Invalid Linux byte encoding returns 203, an unsupported-input diagnostic
outside Windows differential equivalence, not an invented Windows API result.
Lone UTF-16 surrogates and embedded NUL cannot be represented by the agreed input
mapping and are excluded. Resource admission must reject oversized launch input
before allocating unbounded conversion buffers; the eventual cap must be frozen
in the implementation contract and checked before UTF-16 encoding.

`vectors.json` freezes 15 independently enumerated expectations: absent/empty,
0/7/07/42/99, length overflow, whitespace/quote/backslash/letter, Unicode BMP,
surrogate pair and UTF-16 length overflow. Distinct values must change the result
of the SAME compiled artifact. Numeric results were specified before running the
prototype. There is no application command-line parser: quote/space/backslash are
literal environment characters. Original Windows and the separate Rust prototype
are compared against the table, never used to manufacture expected results.

## Abstract state and implementation gates

At conversion the environment value is unknown. A proof cannot replace it with
an observed string. The future IR must represent a runtime result with disjoint
zero, too-long and short-success alternatives. Only short-success initializes
one or two complete UTF-16 units plus the terminator in the owned local region.
Zero/overflow leave the buffer unknown; all reads on those paths must reject.
Joins retain conditional initialization, scalar ranges and unknown flag state.
Runtime digit checks refine values; unknown bytes cannot become zero.

An implementation needs separately reviewed:

1. Strict KERNEL32 import/IAT binding for this exact API; x86 stdcall three-argument
   cleanup of 12 bytes, protected return/saved state, EAX result, volatile ECX/EDX
   and flags unknown, preserved ABI nonvolatile state. Observe actual compiled
   forms before choosing decoder extensions; no arbitrary instruction expansion.
2. Proven literal name and full six-byte output pointer provenance, disjoint from
   immutable code/import/relocation/return/saved slots. The buffer is caller-owned,
   not an OS-owned borrowed pointer; the name is read-only. No pointer escape or
   retained reference after the call; lifetime ends on frame cleanup.
3. A precise external write effect and guarded read proof, UTF-16 byte/word alias
   tracking, unknown-input arithmetic/branch semantics and balanced frame teardown.
   Negative cases: bad size/name, partial/misaligned/foreign/stale buffers, protected
   overlap, read after failure/overflow, unknown digits/flags and mixed-owner joins.
4. Linux native runtime environment acquisition and bounded Unicode handling with
   no constant folding from a baseline. Deterministic emitted source for identical
   PE bytes regardless of converter environment; same ELF run with all inputs.
   Exact raw Windows API emulation is not established by this program's observable
   projection: future support must keep other consumers/last-error reads blocked.
5. Independent production-path rejection tests and real unchanged PE -> Rust -> ELF
   comparisons for all frozen vectors, with source/compiler/PE/Rust hashes. A
   standalone Rust prototype is not mechanical translation evidence.

Do not activate a general API shim from this design. First review the measured
compiler forms and choose a bounded implementation/prototype gate addressing the
actual state/memory/ABI prerequisites. A novel unknown-state architecture needs
Astra High; routine review follows on medium.

## Reproduction and evidence limits

Sources/flags/vectors were frozen before converter evaluation. Windows CI builds
unmodified C with available MSVC x86 `/O2 /W4 /GS- /Zl`, no default CRT libraries,
custom `entry@0`, Kernel32 import library; `/Bv`, link flags, import listing and
complete authored disassembly are retained. Disabling the cookie is an explicit
freestanding experiment setting, not ordinary CRT coverage. Do not change flags
or source merely to gain acceptance. The existing Windows toolchain version is
recorded per run rather than falsely called pinned.

`python research/input/check.py EVIDENCE` in an x86 MSVC environment records 15
original observations and requires current converter rejection. On Linux,
`python3 research/input/check.py EVIDENCE --compare` builds a separately authored
Rust contract prototype and compares the frozen table and original observations.
The prototype is NOT generated from the PE. CI retains PE/source hashes; source
line endings are fixed. Failures/timeouts fail the run; no retries are hidden.

Existing 12 compiler pairs,102 authored pairs and18 launch checks remain distinct.
These 15 prototype comparisons add no converter compatibility cases. Modern
Windows observations establish no XP/7 claim. Four prior timeout causes remain
unresolved. Full CRT effects, general heap/global memory, arbitrary loops, files,
PE32+ and general Windows environment semantics are outside this gate.
