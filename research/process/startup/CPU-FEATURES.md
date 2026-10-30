# Bounded CPU and OS observations at startup

## Supported boundary

The unchanged authored input's entry path now executes its entire scalar CPU
classifier, `401ea5..4021be`, and its original RET. The next original instruction
is CALL at `40195a` to `4024ca`; that call still rejects. No later initializer,
feature-selected library implementation, Main or physical exit is admitted.
The previous no-contract case still stops at CALL `401ebe` and preserves its
arguments, protected activation, installed EH4 record and earlier mapped writes.

The classifier is mechanically lowered through shared instruction semantics.
Its CPUID and XGETBV forms require an explicit observation contract; the default
emitter rejects both. Exact original code, mapped-image identity, execute
permissions, live initialization and active call authority are rechecked. The
IAT address, DLL and symbol are separately checked from PE import evidence;
changed import identities reject source generation. The763-byte tail is a closed graph with its original branches, writes and RET;
there is no replacement calculation of the classifier's result.

## Host observations are not instruction admission

This implementation deliberately does **not** install a general CPU feature API
in the production converter. It grants observation access to this closed scalar
classifier only. All of its reachable instructions must lower, including both
sides of feature tests. The caller's next operation remains rejected before any
feature-selected implementation can run. Changing the classifier to execute an
unsupported instruction is rejected; host feature bits grant no decoder,
proof, emitter or continuation authority.

This distinction is essential: masking SSE2 off just to take the shorter branch
would contradict the cookie helper's existing enabled-SSE2 premise. Conversely,
copying host features into a general guest API without proving the code selected
by those features would overstate support. Before extending this observation
scope into full startup, close every newly reachable consumer (and its exception,
state-save and memory effects), or establish a separately reviewed virtual CPU
profile with the requisite semantics. A data structure named a certificate is
not sufficient. Full startup and rcedit remain unsupported.

## Contracts and provenance

* Microsoft [IsProcessorFeaturePresent](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent)
  identifies selector10 as SSE2 availability. The result is zero/nonzero,
  including zero when HAL detection is unsupported. The **bound original caller**
  uses only TEST EAX,EAX; canonical0/1 represents that predicate, not an exact
  BOOL byte guarantee for other callers. Last-error state is conservatively
  unknown after the API. Unsupported selectors reject before clobbering state.
* Microsoft [CPUID/CPUIDEX](https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex)
  defines EAX/ECX selectors and EAX/EBX/ECX/EDX output order. Intel's
  [SDM instruction reference](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
  defines CPUID and XGETBV register effects and unchanged EFLAGS. XGETBV0 requires
  XSAVE and OSXSAVE; its EDX:EAX result is enabled XCR0, not all hardware features.
  [Rust's intrinsic](https://doc.rust-lang.org/core/arch/x86_64/fn._xgetbv.html)
  has an unsafe xsave prerequisite. Host execution is guarded by both feature
  bits before the intrinsic is called. No XSETBV, privileged state changes or
  unsupported-XGETBV exception behavior is implemented.
* Native acquisition is **Linux x86-64 only**, under the ordinary userspace ABI
  with CPUID enabled, stable CPU feature exposure, and OS-managed legacy SSE
  state. It does not claim old Windows HAL or arbitrary guest OS equivalence.
  Each native query acquires fresh observations, so a cached leaf1 APIC ID is
  never substituted after migration. Thread/process identity and initialization
  lifetime are checked first. Heterogeneous/changing feature exposure and
  per-thread CPUID faulting remain outside the admitted domain; no security or
  affinity setting is changed.
* Linux [XSTATE userspace documentation](https://docs.kernel.org/arch/x86/xstate.html)
  explains CPUID plus XGETBV detection, automatic state enablement through AVX512,
  and the separate permission/first-use rules for dynamic features such as AMX.
  XCR0 alone is therefore **not** execution permission for every advertised
  extension. This scope implements no AMX execution, permission request,
  signal-stack expansion or arbitrary extended-state restoration.

Native acquisition reads available leaves0,1,7.0,7.1,0x24.0 and XSAVE metadata
0x0d.0. Max-leaf/subleaf guards prevent unsupported queries. XCR0 is read only
with both XSAVE and OSXSAVE; its bits must be a subset of the supported-state
mask. SSE2/FXSR/SSE, AVX/XSAVE, AVX2/AVX, AVX512/AVX2 and enabled XMM/YMM/ZMM
relationships are checked conservatively. Unknown selectors and incomplete
observations reject. The cookie helper already requires enabled legacy SSE2:
this execution scope requires SSE/SSE2/FXSR hardware and the enabled-legacy-state
premise (provided by the native Linux ABI). The synthetic zero PF10 result is
a HAL-detection-unavailable case with legacy SSE2 still enabled, not a disabled
SSE2 OS or fabricated native result. If XCR0 exists, XMM state must be enabled
regardless of that reporting predicate. These are bounded consistency checks, not a complete model
of every vendor feature dependency. Synthetic observations are explicitly separate test inputs,
not observations from Windows or a fabricated native CPU.

Queries overwrite only their architectural scalar outputs; they do not mint
pointer authority. CPUID preserves flags even when it occurs between the vendor
comparison and its branch. XGETBV preserves ECX, EBX and flags. All checks occur
before register writes. API argument rejection leaves prior errors, registers
and protected return state intact. Original classifier memory writes use the
canonical mapped state and retain ordinary bounds, initialization and permission
checks; a later rejection does not roll them back.

## Evidence and limits

Fifteen connected cases cover unreported-HAL/SSE2/AVX/AVX2/AVX512/AVX10-class observation
combinations, actual Linux observations, actual Linux identity/clock plus CPU
acquisition in one entry path, stale/foreign initialization, wrong thread, dead
mapping, missing leaf, changed live code and host-thread mismatch. Synthetic
class cases assert independently fixed tier values. All cases strictly assert
the expected next boundary or error; a failed positive case cannot count as a
successful comparison. Linux has two native-observation cases; other hosts use
explicit synthetic inputs. None are new Windows/ELF differential pairs.

Five independent Rust regression tests cover inconsistent state combinations,
CPUID/XGETBV register and flag behavior, unknown/pointer inputs, active-call and
initialization lifetime, selector failures, execute/read/write permissions,
bounds, stale mappings, and default rejection of unbound or unsupported
instructions. Every one of the763 tail bytes and86 entry/prefix bytes is mutated
and rejected by source binding. A changed live tail also rejects after retaining
the preceding original writes. Those mutation tests establish binding, not
independent instruction correctness; register/flag/ownership tests provide the
separate semantic checks.

The unchanged PE hash and generated Rust hash are recorded in
[evidence/cpu-feature-review.json](evidence/cpu-feature-review.json). Existing five
recorded Windows component comparisons are retained, with no claim that they
observe these new CPU queries or establish whole-PE execution. There is no new
original-Windows CPU baseline in this checkpoint. Root activation, committed
stack and incoming thread chain are still component premises. Historical
Windows process timeouts remain unresolved.

## Next executable gate

`4024ca` calls `4029b4`, tests AL, then calls `402963`, with `4029f0` cleanup on
failure. Inventory shows `4029b4` constructs a module lock at41ccec through
`402c2d`, publishes the count41cd04 only after success, and cleans up in reverse
order. `402963` obtains an FLS slot through402b3e, publishes41c060, then invokes
402bef with the startup sentinel41ccc4; failed publication frees the slot.
Connect those actual producers to the existing lock/FLS ownership machinery,
preserving original failure ordering and opaque lock storage. Do not assume
lock construction, a valid slot or initialized PTD merely from mapped zeros.
Sol can independently review this CPU boundary and inventory the next producer;
use a bounded Astra pass only for a concrete remaining ownership/effect problem.

### Local validation corrections

An intermediate replay started before the new import-evidence file contract was
added and then compiled the edited harness midway through the run. Its later
registered-errno test failed on the absent `startup-cpu-import.txt`; the original
logs are retained. This was a mixed-revision local run, not a Windows process
hang or a passing regression. The final replay uses a stable implementation and
fresh extraction directory. Earlier report metadata counted only one of the two
Linux CPU observation cases; the final script reports both and zero on other
hosts. Neither correction changes the original Windows observations.

Final local validation: 258 CRT tests passed, with both artifact-dependent ignored
tests passed separately by the stable replay; 175 converter tests and60 Python
tests passed (one existing Python skip). Strict Clippy and formatting/diff checks
passed. Final generated Rust SHA256: `a5a79fa839d50a80ddf29c232e388abaf83bd80d8ea9f5f31e642d69934cef5e`.
