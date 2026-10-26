# Freestanding binary uppercase CLI: measurement and integrated design

Freeze443d0ea precedes compiler/converter evaluation. Original authored filter.c,
O1/O2 configurations and11 byte-exact vectors are hashed in frozen.json. This is
an explicit custom-entry/no-CRT experiment, not a replacement for the startup of
an ordinary CRT-linked program. No production converter change is included.

## Observable contract and primary sources

Transform only bytes0x61..0x7a to0x41..0x5a; preserve NUL, CR/LF, high bytes and all
other bytes exactly, independently of encoding/locale. Buffer size256. Each read
fills at most256 bytes, only returned bytes become initialized, and each write
consumes a prefix of the remaining initialized bytes. Continue partial writes;
zero progress or excessive progress fails. EOF with successful zero-byte ReadFile
returns0. Missing/invalid standard handles return10; read failure11; write
failure12; invalid write progress13; excessive read count14. No stderr writes.
Output before failure is retained; it is not rolled back. Exit codes are portable.

Microsoft primary contracts inspected2026-10-26:

- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
- https://learn.microsoft.com/en-us/windows/console/getstdhandle

Synchronous handles and NULL OVERLAPPED only. Count output pointers are writable
DWORDs; API calls invalidate volatile registers/flags and write only their declared
buffer/count effects. Standard handles may be NULL/INVALID_HANDLE_VALUE or lack
requested access; ownership is borrowed and they are not closed. No console text
translation is intended; initial executable domain is redirected regular files
and byte pipes. Device, message-pipe, console, asynchronous and concurrent handle
replacement behavior needs separate contracts. Last-error state is unobserved by
this frozen program, but cannot be omitted if future code reads it.

ReadFile documents FALSE/ERROR_BROKEN_PIPE after an anonymous pipe writer closes.
The frozen program therefore returns11 at pipe EOF, even after correct output.
This is a genuine useful-pipeline limitation, not converter failure. Keep this
artifact unchanged. A later explicitly versioned source can call GetLastError and
recognize only ERROR_BROKEN_PIPE as EOF if a pipeline-success policy is adopted.
Linux read()==0 would need handle-kind-aware result mapping to preserve this
original program's behavior; simply mapping every EOF to Windows TRUE/zero would
be incorrect. Linux writes to closed pipes must return the specified failure,
not terminate from SIGPIPE; any process-level signal policy requires explicit
runtime design. No system security setting change is proposed.

## Evidence boundaries

measure.py preserves source/PE hashes, full dumpbin disassembly/headers/imports,
compiler/linker versions/commands and exact original Windows outputs. Eleven file
inputs per configuration cover empty, all256 byte values,255/256/257 and511/512/513
boundaries and4097-byte multichunk input. Original pipe EOF and access-denied read/
write cases are separate observations. The8 scripted API cases compile the frozen
algorithm with substituted authored functions: partial reads1/2/1, writes1byte,
zero/oversized progress, bad handles, false read/write, oversized count and pipe
EOF. They are deterministic fault/short-I/O evidence, not unchanged-PE Windows
observations. No claim that normal OS writes necessarily exercise partial writes.
Timeout30seconds is a harness limit, never a claimed semantic bound or retry.
CI uploads diagnostics on failure. No proprietary binaries/source are imported.

## One cohesive implementation gate after measurement/review

Inventory every instruction, imported symbol, relocation and section in BOTH
unchanged artifacts before deciding the complete scope. Use iced operand metadata
and shared IR/state/emission where suitable; no whole-body hashes or per-fixture
recognizers. Unknown values remain unknown; unresolved effects reject.

The integrated design must cover: scalar byte aliases and flags; stack count cells
and bounded mutable byte buffer ownership; pointer owner+offset plus full ranges;
loop-carried state and runtime backedges; imported handle identities and synchronous
ReadFile/WriteFile effects; partial progress and failures; native runtime stream
access and cleanup. API result refinement must cover every admitted result, not
sampled lengths. Borrow counts and buffer ranges cannot alias protected returns,
saves, code, imports or one another. Write loops have decreasing remaining bytes
for each successful iteration; transform loops have increasing index below count.
The outer stream loop terminates only when the external source reaches EOF/error.
Do not impose an undisclosed finite-input bound, infer termination from samples,
or expand the old fixed-loop recognizer to fit this program. Choose a reviewed
runtime control-flow contract with constant live storage and checked guest ranges.
Host allocation/I/O/resource failures require explicit outcomes.

Acceptance: unchanged O1/O2 PEs independently convert to identical Rust on both
hosts, then actual Linux ELF stdout/stderr/exit equals Windows on the frozen
binary inputs, file/pipe EOF and real failure cases. Add independent unsafe alias,
unknown initialization, partial-byte/register, short-progress, error, loop and
resource tests. Scripted backend checks supplement actual executions. Preserve all
existing tests/comparisons. Report unsupported dependencies honestly. Do not enable
production until full proof/runtime correspondence and this evidence pass.

Architecture/core needs Astra High; substantive medium review before merge. Keep
this as a cohesive stream milestone, not a separate issue per opcode. Broader CRT,
x64, GUI and XP/7 compatibility remain unproved. Five recorded timeouts remain
unexplained; no retry or relaxed threshold is introduced.
