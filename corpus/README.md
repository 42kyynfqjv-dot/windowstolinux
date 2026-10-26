# SUB-513 independent bounded corpus v2

32 authored instances, four composition families with eight variants each. Do not
interpret that as32 independent instruction semantics or application compatibility.
Seed513 identifies a fixed enumerated corpus; no random generator/version-dependent
PRNG is used. Byte reproducibility is checked on every build and the concatenated
PE SHA256 is printed identically on both OS jobs. expected.json independently lists
exact stdout/stderr/exit observations; it is never generated from translator output.

The generator imports neither production code nor the previous fixture generators.
Its PE serializer and label fixups are newly authored MIT OR Apache-2.0. Primary
requirements remain Microsoft PE/COFF, _write/cdecl and Intel instruction contracts
linked in SUB511-OUTPUT-DESIGN.md. This is independent code/specification within the
same project, not an organizational clean-room or independent third-party review.

Grammar: three strictly mapped sections; one _write thunk; immutable byte buffers;
MOV/ADD/CMP/XOR, forward short JZ, direct forward CALL/RET, PUSH literal, exact stack
argument load and LEA cleanup, A1 immutable load and image-bound FF15. Four families:

- Eight arithmetic boundary tuples independently specify expected sums: 0,1,255,
  128,0x80000000,0,0,42. CMP checks EAX before output; mismatch exits97.
- Parameterized nested helpers return argument+5+3 for arguments0..7. CMP before
  output checks8..15; mismatch exits96. Return-address ownership and cleanup are
  exercised at both depths.
- Unaligned immutable words100..107 plus offsets0..7 produce100,102,..114;
  CMP checks those values before output; mismatch exits95.
- Alternative caller paths share one imported-output helper. XOR makes JZ taken;
  even variants bypass output, odd variants invoke the helper. Hypothetical paths
  still require safe arguments; native observations include four empty outputs.

Payload rules specified separately in expected.json: variant0='!', variant7=64 Z
bytes, variants1..6='C'+two decimal instance digits. Import ILT/IAT offsets vary by
4 bytes per variant, with constant separate names. Buffer starts shift by0..7; instance0 reads the last declared immutable byte.
These vary legal metadata placement and alignment; they are not a broad linker corpus.
A separate literal audit in check.py checks header, raw size and names before running.
Windows runs original PE. Linux runs the actual converter twice, checks source
identity, invokes standalone rustc and executes the ELF; both compare against the
same literal observation manifest. They print byte hex/exit and aggregate PE hash.
The earlier70 comparisons remain a separate baseline. Prototypes are not counted.

Linux additionally makes five single-field mutations per instance (160 calls):
ILT/IAT alias, DLL name tail overflow, IAT complete-span overflow with matching directory and descriptor, ordinal thunk,
and forbidden LF payload even on the untaken native path. These are mutations,
not160 distinct bug classes. Existing2048 truncations/40 malformed cases and
production prefix/unknown-flag/repetition/stack-limit tests remain in CI. Corpus v1
does not yet independently regenerate every failure class or fuzz arbitrary code.

Run cargo build --locked; python3 corpus/check.py (rustc on PATH). On Windows:
python corpus/check.py --windows. Each subprocess has a timeout. A mismatch reports
instance ID and observations or code bytes; deterministic build(ID) reproduces it.
Preserve/minimize any failing authored case before implementation changes. No
production semantic mismatch has been observed locally at this checkpoint.

Conditional legacy CRT initialization/byte mode, preferred base, valid stack and
full-success regular-file assumptions remain. No XP7/application/failure-path
compatibility claim. Next useful work is failure-driven corpus expansion and more
independent structural audits, with no feature expansion required. Medium effort
is appropriate; a reproduced semantic redesign would justify Astra High.

## Bounded independence review

All32 manifest IDs must occur exactly once. Arithmetic tuples were checked as
32-bit modular sums; nested helper outputs are variant+8 and immutable-load outputs
100+2*variant. Payload observations are literal manifest data rather than output
from a Rust evaluator. Family4 uses a constant-taken branch, so it validates
alternative contexts conservatively but not independent dynamic branch discovery.
The eight layouts/values within each family do not create eight new semantics.

Review found the prior IAT mutation changed only the descriptor, so rejection
occurred at directory mismatch before bounds validation. Version2 also changes the
directory to the same RVA, reaching the complete-span check. Mutation count remains
160. Instance0 now puts its one-byte buffer exactly at the declared virtual end;
its mutation targets that actual byte. No additional case/count is invented.
No production defect reproduced. This corpus still is not an independent oracle
for all call-state rejection rules, nor evidence about ordinary linked applications.
