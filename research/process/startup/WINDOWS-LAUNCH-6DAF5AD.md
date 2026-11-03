# Two original-Windows launch failures at 6daf5ad

These are failed original-process measurements, before any Linux conversion or
new REP execution. Their cause is **unresolved**. They are separate from retained
historical case 19 and earlier original-Windows/build/projection timeouts.

| Run / job | Original | Observed result |
| --- | --- | --- |
| [41274514852 /124753860802](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41274514852/job/124753860802) | independent corpus case1 | stdout C01; stderr empty; process still alive after 15 seconds |
| [41274512166 /124753852940](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/41274512166/job/124753852940) | output-probe.exe | stdout Hello; stderr empty; process still alive after 15 seconds |

Each retained Popen handle timed out in process.wait, with poll=None. The bounded
read-only observer verified its PID/creation identity and alive state. Each
reported one owned thread and a WCT chain with no reported cycle, node type 8 and
status 2. This supplies neither a call stack nor a demonstrated fault location.
Owned-child cleanup killed and reaped each process (exit-after-kill 1); that is not
an original successful exit. Output alone never satisfies the comparison gate.

Both runners reported ImageOS win25-vs2026, ImageVersion 20261021.278.1,
Windows-2025Server-10.0.26100-SP0 and Python3.12.10 x64. The output-probe process
included apphelp.dll; corpus1 did not. Module presence does not establish a cause.
No claim is made that a launcher defect, Windows loader/CRT behavior, runner
instrumentation, deadlock or regression in the converter has been established.

Both failed Rust workflows passed their other eight jobs, including compiler
Windows/native and other utility checks. Startup inventory 41274512180 passed all
13 jobs. Both failed jobs' fixed 18-sample diagnosis and two independent Python
process-exit controls passed. Those samples used different PE hashes from the two
failures; passing them does not explain or erase either failure.

[Durable evidence](evidence/windows-launch-6daf5ad.json) preserves both launch
records and raw observer output, immutable run/job/artifact IDs, archive SHA256s,
the passing control records and exact original-image hashes. Retained ZIPs remain
in the task evidence workspace. The three relevant originals were independently
checked byte-for-byte against the existing authored generators; no PE was run on
this Linux host. Source/generator changes cannot silently change the next test.

## One bounded experiment

[scripts/windows-original-contexts.json](../../../scripts/windows-original-contexts.json)
freezes nine mandatory samples: three repetitions of exact corpus0 then corpus1
in the same owned system-temp case.exe, followed by exact output-probe.exe in an
owned directory on the checkout volume. All inherit the original working directory
and launch redirection. This covers the missing image/basename/volume sequence;
it does not reconstruct the historical full path, VM or compatibility-cache state.

This is an additional fixed experiment, never a retry of a failed comparison.
Timeout remains 15 seconds; every failure retains its PE, stdout, stderr, observer and
launch.json and makes the final diagnosis fail. Tests independently reject
changed images, wrong output/exit/hash/stage and a timeout with expected output;
all nine predefined samples are counted. The existing 18 samples, two host controls and
original comparison gates remain mandatory. No timeout limit or host security
setting changes, and no passing rerun is described as a diagnosed fix.
