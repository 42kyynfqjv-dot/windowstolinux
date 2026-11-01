# Locale startup prefix and aligned-frame boundary

## Executed scope

The unchanged authored PE is still SHA256
`1e96cb39e34b9f7bb421d21217b2827b8f7b99853e2e177ee72724dd456dcbf4`.
In the explicit native launch profile, initializer index10 now enters original
callback `0x40b42a`. It writes the three original module addresses to
`0x41d140`, `0x41d13c`, and `0x41d138`, executes required-PTD getter `0x40a2ef`,
and pushes the original four arguments. Execution rejects before CALL
`0x40b460 -> 0x40b235`. The initialized byte at `0x41d148` remains zero.
No multibyte initialization, complete callback10, formatter, whole-startup or
rcedit compatibility claim follows.

The getter executes its original C++ registration prolog, static FlsGetValue
thunk, branches and epilog against the canonical live exception registry. The
fast path returns the same published UCRT heap allocation (868 bytes), with its
allocation/slot/fiber identity intact. Repeated acquisition creates no new heap
allocation or view and retires each temporary C++ record. The existing lazy
producer is connected without substituting an allocation result. A required-PTD
termination branch remains an explicit rejection; the trailing trap cannot become
a successful structural return. This does not prove exceptional handler execution.

Unknown values do not become pointers. A view requires the actual UCRT allocation
root, matching live FLS publication and current fiber; the distinct 40-byte
VCRuntime view cannot supply it. Failures preserve completed original stores and
registration effects. A nonzero input flag follows the original skip branch;
that component case does not establish that initialization actually happened.

## Independent evidence and provenance

`check_normal_wrapper.py` verifies callback, getter, handler and alignment-test
bytes directly against executable mappings in the unchanged PE before replay.
The FlsGetValue import and later code-page imports are also checked. Native
regressions cover positive and repeated acquisition, consumed-return replay,
callback/getter/prolog/epilog/handler/thunk/import mutation, missing or stale view,
wrong PTD layout, unknown/sentinel values, stale index/fiber/slot and partial
writes. Nineteen declared-state scenarios supplement the connected original-entry
case; their setup is explicitly separate from Windows observations and original
startup producers.

The earlier ten unique Windows Unicode/quoting cases were independently redecoded
from both retained ZIPs. The corrected LF checkout archive's C, manifest and vector
bytes match the repository, and both probe PE hashes were checked. These remain
command-line conformance observations, not new Windows/ELF translation pairs.
The five recorded wrapper comparisons also remain component comparisons.

## Reproduced architectural limit

The original helper begins:

```
40b235 MOV EDI,EDI
40b237 PUSH EBX
40b238 MOV EBX,ESP
40b23a PUSH ECX
40b23b PUSH ECX
40b23c AND ESP,-8
40b23f ADD ESP,4
40b242 PUSH EBP
40b243 MOV EBP,[EBX+4]
40b246 MOV [ESP+4],EBP
40b24a MOV EBP,ESP
40b24c SUB ESP,0x238
```

For both four-byte stack residues, current AND computes correct numeric bits but
loses pointer authority. ADD then rejects while validating/discarding stack words;
its result is not committed and PUSH EBP has not executed. The focused native test
checks this exact failure and preserved original return/saved EBX.

A separately declared same-root aligned reference state also tests ADD across
unknown ordinary padding/pushed data. Both residues discard it successfully without
inventing known bits; padding does not add another demonstrated barrier. This is
not a production provenance repair. The original copy tail then executes in that
reference state. It leaves two tags for the original return identity: the
original return slot and its compiler-created mirror. `validate_active` rejects
this duplicate. This reference-state experiment is not an admitted production
alignment lowering. Neither casting an arbitrary scalar ESP back to a pointer nor
relaxing protected-return uniqueness is sound.

### Bounded next ownership integration

Astra High is justified for a shared aligned-activation contract, not for routine
CI or documentation. It must:

1. Derive the new stack address from the same live capability with checked
   alignment, extent and initialized/protected ranges. Preserve the demonstrated
   ordinary-padding behavior without crossing protected words. Preserve actual flags and
   intermediate effects, including failures before later writes.
2. Represent copied return bits separately from single-use return authority.
   Establish which original/mirror slot each original call/epilog uses; do not
   consume the original merely because a copy was made.
3. Preserve EBX's unaligned caller-frame reference, the original saved registers,
   child stack extent, nested calls and actual epilog/RET ownership. Inspect the
   complete helper before defining the protocol. Its original tail restores ESP from EBP, pops EBP,
   restores ESP from EBX, pops EBX and RETs through the original unaligned slot
   (`0x40b383..0x40b389`); the mirror is not that RET slot.
4. Test both residues, different frame sizes and nesting, arbitrary scalar/foreign
   or stale stacks, out-of-range alignment, corrupted mirror/source, replay,
   changed instructions and failures after partial frame writes. Carry the
   justified contract through shared proof/emission before entering this helper.

After frame admission, `0x40b38a` and the locale/reference body remain separate
executable dependencies. `0x40afbc` selects GetOEMCP for -2, GetACP for -3 and
locale state for -4; later code uses IsValidCodePage and GetCPInfo. The actual
callback selects -3. Its eventual GetACP must agree with the already declared
65001 process profile; Windows ACP is not universally UTF-8. Existing newer-host
observations do not establish legacy ACP or XP/7 behavior.

Primary contracts for the later code-page work:
[GetACP](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getacp),
[GetOEMCP](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getoemcp),
[GetCPInfo](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-getcpinfo).

Default admission, native close/EOF equivalence, incoming Windows delivery and
collided-unwind effects remain unproved. Historical original-Windows case19
process timeout is retained with cause unresolved; no retry or threshold change
resolves it. [Evidence](evidence/locale-startup.json) records exact local checks,
source/PE/Rust hashes and predecessor CI separately from the new head.

## Reproduction

Use the retained unchanged authored PE and recorded observation directory. These
commands execute Rust component tests; they do not launch a Windows PE on Linux.

```sh
cargo test --locked --example crt_stream original_stack_alignment_exposes_pointer_and_return_copy_limits
W2L_PE_MAPPING_INPUT=/path/to/original/unwind.exe cargo test --locked --example crt_stream canonical_image_cookie_and_original_record_initialization_compose -- --ignored
python3 research/process/startup/check_normal_wrapper.py /path/to/original /path/to/observed /path/to/new-output
```

The focused alignment test passes only when both current unsupported behaviors
reject as documented. Its supplied aligned reference state is explicitly a second
experiment. It must not be reported as successful production alignment support.

## Verified local checkpoint

300 CRT tests passed (two artifact-dependent tests are excluded from that count).
Both artifact-dependent tests passed in the complete replay, along with the
19 declared-state locale scenarios; 185 unwind tests and 84 Python tests (one
existing skip), Clippy and formatting passed. The final supplemental padding
reference test also passed and a later fresh emission matched the completed
report's Rust hash. The first complete replay stopped on the import-mutator's
incorrect one-occurrence assertion; its logs remain retained. Correcting the
mutator did not change production semantics.

All three be0e52a CI workflows passed. The published implementation checkpoint is
7e39ef9; its CI was still running at this local evidence snapshot. Follow-up changes
only add the supplemental alignment reference test, documentation and evidence;
production source() emission is unchanged. Check the current PR head's workflows
for final CI; no final-head pass is claimed here.
