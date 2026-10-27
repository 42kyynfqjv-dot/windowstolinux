# Frozen stateful streaming composition measurement

Three independently authored custom-entry x86 programs share explicit synchronous
Win32 I/O boilerplate. Their application logic is independent of the converter.
Source and expectations freeze before evaluation; no converter support changes.

- fold: remove CR immediately followed by LF, preserve lone CR/LF and binary bytes,
  then uppercase ASCII a-z. Pending CR spans reads and flushes at successful EOF.
- tabs: expand each TAB to the next four-column stop. CR and LF each reset column
  to zero; every other byte, including NUL/high bytes, occupies one column.
- escape: discard unescaped |; backslash quotes the next byte and is removed.
  Preserve a lone final backslash. Quoting state spans reads.

Input capacity64/output256. Tab expansion can produce256 bytes from one read;
fold/escape produce at most65 including carried state. These are freestanding
programs, not ordinary CRT applications. Missing handles exit10, non-EOF read
failure11, write failure12, invalid progress13, oversized read count14. Successful
zero read/file EOF and broken byte-pipe error109 end input. Non-EOF read failure
returns immediately without flushing pending state; completed output stays visible.
Partial writes resume actual progress. CRLF state, tabs and escapes are binary
semantics; no locale/text-mode decoding applies.

Fourteen frozen binary inputs per program include all256 bytes, expansion-heavy
runs and boundary lengths63/64/65/127/128/129/4095/4096/4097. Both O1/O2 use the
same documented MSVC flags as earlier CLI experiments. Each build has28 real
file/pipe executions plus3 real failures:186 Windows observations total.

Separate authored backend probes run24 schedules/failure scenarios per program:
read chunks1/2/3/63/64, write chunks1/7, both EOF modes, initial read failure,
read failure after one byte, write failure after two bytes and zero write progress.
These72 scripted records are distinct from OS executions. Python expectations
use whole-sequence replacement/translation, built-in expandtabs and indexed escape
parsing. They are frozen in JSON; C probes record actual effects independently.

Compiler-produced PEs remain untouched. Every accepted conversion must match PE
hash, generated Rust and actual output/stderr/exit across Windows/Linux. Rejections
must preserve the output sentinel and match across hosts. Inventory all instructions
and sections before choosing one cohesive next architecture gate. Windows Server
2025 does not validate XP/7; six historical launch timeouts remain unexplained.

See [measured outcomes and integrated next gate](RESULTS.md). Accepted emitted
programs also run the24 frozen backend scenarios; these are separately counted.
