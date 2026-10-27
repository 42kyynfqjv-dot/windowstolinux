# Original incoming ownership is not an empty chain

The required original-entry experiment now has a concrete result. At commit
e3d98a74b9461fbd28e93ac447269aa8deff6c5e, dedicated workflow
[40595682305](https://github.com/42kyynfqjv-dot/windowstolinux/actions/runs/40595682305)
passed. Job122510872069 executed the retained original PE under an owned debugger
and stopped before its first original entry instruction. The exact original hash
remains ce252fb1eddd05c3ea6acd73871995b1badd32446d76c6df07abaf8fa44fd22f.
The observation and provenance are retained in `entry-observed.json` and the
`startup-entry-observation` workflow artifact.

Observed Windows Server2022 x86 state:

| Field | Observed numeric address |
| --- | --- |
| Image allocation / original entry | 0x00d30000 / 0x00d3688e |
| ESP / EBP | 0x006ffc9c / 0x006ffca8 |
| TEB | 0x0052d000 |
| Stack limit / base | 0x006fd000 / 0x00700000 |
| Incoming FS:[0] record | 0x006ffcf0 |
| Its predecessor | 0x006ffd08 |
| Its handler / image allocation | 0x76f0c630 / 0x76e90000 |

The first incoming record is nonempty and above entry ESP, with another
predecessor. Its handler lies in a MEM_IMAGE allocation different from the
application image. The module name, exact loaded-module hash and full chain have
not been established. Do not identify that handler from its sampled address or
infer its effects from a familiar symbol. Addresses may vary across executions.

## Why this blocks the proposed original startup composition

`Startup::bind_empty_thread` sets the chain to 0xffffffff with no incoming records.
That explicit component premise does not describe the observed original process.
The actual prolog pushes FS:[0] and installs its record, retaining the incoming
predecessor. Search that continues past the application record and global unwind
can therefore reach preexisting frames and externally owned handler code. Treating
them as an empty sentinel removes reachable effects; treating numeric addresses as
owned application handlers invents execution authority.

The newly integrated input continuation dispatcher preserves admitted helper-call
semantics, but its original root stack sentinel and six-register frame coordinates
do not supply these caller frames, thread state or external handler contracts.
This is now an observed mismatch with the original-entry premise, beyond the
earlier source-only finding that exception effects were missing.

The missing semantic fact is the contract of incoming loader-owned registrations:
which thread/module generations own their code and storage, what search/unwind/
failure effects they can produce, and how their lifetimes relate to the application
entry activation. No safe implementation can derive that contract from the
addresses in this report. Ordinary utility admission remains rejected until it
is established or a restricted domain soundly excludes every relevant effect.

Next cohesive work must model a process-entry boundary with borrowed incoming
activations and explicit external handler effects, then lower the original prolog,
handler and cleanup instructions through it. Preserve original predecessor links;
validate complete chain ranges and lifetime before use; reject unknown external
handler behavior before publishing an executable claiming equivalence. A native
replacement for the boundary requires documented or independently validated
behavior, not a fabricated empty chain, guessed main, or success-only path.

## Instrumentation and failures

This is a separately instrumented observation, not an ordinary Windows baseline
or a Windows/ELF comparison. The observer modifies one entry byte to INT3 in its
own child, validates the breakpoint address and EIP=entry+1, reads FS/TIB/record
metadata, restores the byte and terminates that child without running the utility
workload. Reported EIP is normalized to the original entry. The file hash is checked
before and after. No privileges, system security settings or unrelated processes
are changed. Source and commands are in observe_entry.c/measure_entry.py.

The earlier hardware-breakpoint route did not capture entry. Runs40595066054,
40595220768 and40595468390 are retained failures. Diagnostics on the last run show
the breakpoint was armed but the child exited0 without a captured single-step
event. Cause of that missed hardware observation is unresolved; the software
breakpoint observation does not explain it. No retry threshold was relaxed.
These observer failures are separate from the historical original-Windows timeouts.

A subsequent cleanup correction records byte-patched state independently of the
armed state so a successful write followed by FlushInstructionCache failure still
attempts restoration before owned-child termination. This changes failure cleanup,
not the reported successful observation or frozen original artifact.

SUB-579 and PR45 remain in progress and unmerged. Zero new startup translations.
