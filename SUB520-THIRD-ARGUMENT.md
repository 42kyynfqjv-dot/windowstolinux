# SUB-520: exact third argument and six-word cleanup

## Contract fixed before implementation

Only the linker-image profile gains `03 44 24 0C` (ADD EAX,[ESP+12])
and `83 C4 18` (ADD ESP,24). The existing authored profile is unchanged.
No prefixes, alternate encodings/registers, other offsets or cleanup sizes are
admitted. Existing second-argument and five-word forms retain their contracts.

The third argument is one complete four-byte tagged word, three words below the
current callee's protected Return at the top of the stack. It must be Data owned
by the immediate caller. A missing, Saved, Return, Entry or foreign-owned word
rejects. Both that value and EAX must be Integer; pointer/unknown arithmetic
rejects. The result is modulo 2^32 with CF/ZF/SF/OF defined by 32-bit ADD. The
load itself changes neither ownership nor the protected return word.

Six-word cleanup first validates the entire six-word interval as current-owner
Data, then removes it atomically. It cannot discard saved ESI or a return tag.
The absolute initial ESP remains unknown. ADD ESP,24 therefore invalidates all
tracked flags; no numeric address or fabricated flag value is emitted. A later
JNZ requires a flag-defining instruction such as CMP. MOV, saves and restores
cannot make unknown flags usable. AF/PF and other conditions remain unsupported.
This conservative treatment may reject programs whose ESP flags could otherwise
be proved, and does not claim to reproduce unobservable flag bits.

The existing valid flat stack, complete mapped word/no fault, no asynchronous
mutation and return-address isolation assumptions remain required. Resource
limits, per-call ESI snapshots, pointer provenance, all-path validation and
balanced terminal states remain unchanged. Separate Op variants encode the two
new forms; the generated native program shares these checked transitions.

Primary instruction provenance: Intel SDM Volume 2 ADD, CALL and RET entries
(https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
and Microsoft's x86 calling conventions
(https://learn.microsoft.com/en-us/cpp/cpp/argument-passing-and-naming-conventions).
Implementation and expectations are independently authored, not copied from Wine.

## Evidence gates

- Explicit arithmetic boundary expectations, third-word ownership/type negatives,
  protected/partial cleanup, unknown-flag branches, nested/shared call contexts
  and unchanged resource limits through production state transitions.
- Exact-byte policy negatives and native execution through the production CLI.
  The old mutation changing the second-argument offset to12 becomes a supported
  read of the original caller's descriptor word1, yielding7+1=8 and exit99.
  Preserve it as a positive; add an unaligned offset rejection instead.
- The four frozen SUB-519 C sources and compiler options remain unchanged. All
  four are now required to convert, including the three-argument program with
  Hello/empty stderr/exit0. Source and PE hashes, independent cross-host emission
  and Linux execution remain strict gates. No changes to the compiler's PE bytes.
- Baseline minimal compiler program and102 earlier authored comparisons remain
  separate. Windows Server2025 is not XP/7 or ordinary CRT/application evidence.

## Local verification

53 root Rust test functions (five added), nine deterministic native compiler-shaped
executions and48 CLI rejections (21 original slots,22 new cases,5 executable-range
truncations) pass. One of the21 original slots now rejects offset10 instead of12;
the offset12 case remains as the seventh native positive. Nested/shared helper
execution, untaken invalid paths and protected cleanup are production CLI checks,
not just independent model tests. The nine literal programs are not MSVC artifacts
or additional Windows/Linux pairs. Full unchanged-compiler acceptance requires CI.
