# SUB-579 contract/model checkpoint results

At implementation head 33820eb1786b7cde426a9f73ab9f2361cdc0d5ec:
- Ten independent proof-state model tests and three inherited inventory tests pass.
- Dedicated workflow 40582654198 passes both static-inventory and original-Windows
  probe jobs. This establishes five authored Windows observations, zero new
  translated PE/ELF pairs, and no rcedit startup admission.
- Windows Server 2022 build 20348, MSVC 14.44.35207, compiler SHA256
  fc26dcba228dd91cd09429670f298f4608833c84841a4ceca8c4955b4d495a7b.
- Frozen source SHA256 db7deeb3153ef3d3540a192e3c6e7b7e6c5f6e7e70880a995b1932382899d086.
- Original probe PE SHA256 3283f9f772cdef49b9c844bc6153d072739f6852baab9958045f466374ba88ab.
- Artifact 12768709636 retains build output, original PE and report.

| Mode | Independent expected/observed stdout | Exit |
| --- | --- | --- |
| normal | BF | 0 |
| unwind | BFH | 0 |
| continue search | BH | 0 |
| continue execution | BC | 0 |
| ExitProcess | B | 23 |

All stderr streams were empty. Expectations were frozen before the first run;
source/configuration were not adjusted after observations. Direct WriteFile
eliminates CRT stdout-buffer flush as an explanation for missing F on ExitProcess.
These are behavior probes, not proof that rcedit uses identical handler graphs.

## Separate CI failure preserved

Push run 40582654028 failed in the existing authored Windows corpus, case 6,
PE SHA256 3ba276ec746e9b7f0492ebc321309018919a96359557634c36c3b952f01b3b69.
The original case.exe did not finish within the unchanged 15-second deadline.
Job 122465855656 retained corpus-launch-evidence artifact 12769938410.
The new probe workflow passed; the parallel PR run passed its authored fixture
job. Neither fact explains or fixes the original timeout. No retry or threshold
relaxation was used. This is distinct from the earlier SUB-578 cl.exe build timeout.

## Review boundary

CONTRACT.md specifies the shared owner/thread/cookie relation, invalidation and
failure obligations. Model registration is intentionally only necessary proof
state: it does not write a real SEH record, resolve a handler or dispatch unwind.
Medium review should challenge module/thread isolation, alias invalidation,
numeric encoded-pointer relations, lifetime and failed/unknown effects, and probe
independence. Production integration and original utility acceptance remain open.
Keep SUB-579 In Progress and PR #45 unmerged at this substantive contract boundary.


## Medium review correction

At the initial checkpoint an unresolved exception blocked restore but still allowed
ordinary loads/stores. A literal reproduction loaded 42 and overwrote it with 99
after dispatch-required. The review adds a process-wide ordinary-operation barrier
and an atomicity regression for load/store, encoding, mapping and thread creation.
Eleven model tests plus three inventory tests now pass locally. The existing ten
model tests are retained; this is one new regression, not fourteen new tests.
Production converter code is unchanged. No Windows probe source or expectation was
modified. The contract now explicitly lists missing stack/module/permission classes
and initial-state/initialized-record premises before production admission.
# Byte-backed component follow-through (SUB-579 still In Progress)

See BYTES.md for the new Rust checked-memory component and its fourteen independent
component tests. It validates actual record/guard bytes, module cookie versions,
stack ownership and explicit API output footprints. It does not translate startup,
execute handlers or admit rcedit; zero new PE/ELF pairs are claimed. Full local and
remote verification for the new head is recorded in PR #45 and SUB-579.

The previously pending eae1a44 full runs both failed in original Windows launches:

- PR run 40583601918: `output-probe.exe` exceeded the unchanged 15-second deadline
  before imported/corpus comparisons ran. Its old direct subprocess launcher did
  not retain process-state diagnostics. The current change routes it through the
  existing tested launch evidence helper and always uploads its evidence.
- Push run 40583591190: corpus case 8 timed out at 15 seconds, PE SHA256
  `960c94ad7ad94ae059c4ee177ea7dc7f3ad29c2cd1794a321b636d0e7d17fca5`;
  retained `corpus-launch-evidence` artifact 12771145283. Case 6 passed in this run.

All eight other jobs passed in each run; dedicated startup run 40583591034 passed.
These failures differ from earlier case 6 and the prior compiler-build timeout.
No root cause is established, no retries or threshold increases were introduced,
and improved diagnostics are not represented as fixing the timeout.
