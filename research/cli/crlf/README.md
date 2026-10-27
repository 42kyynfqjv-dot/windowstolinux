# Stateful CRLF measurement contract

Binary transform: replace each adjacent CR LF pair by LF; preserve all other
bytes, including lone CR/LF, NUL and high bytes. A pending CR survives arbitrary
read boundaries. At successful EOF (regular-file zero read or byte-pipe error109),
flush a pending CR exactly once. A non-EOF read error returns11 immediately:
pending/unwritten data is not promised flushed; earlier successful writes remain.
Write failure returns12; successful zero/excessive progress returns13. Invalid
handles return10, excessive read count14. Partial writes resume at the actual count.
No encoding, text-mode, console/device or ordinary CRT equivalence is claimed.

Input128/output129 buffers are separate. Before each read, pending holds at most
one CR. Every produced chunk has at most n+1 bytes; output is generated before
writing. Total output equals the whole-byte replacement oracle independently of
chunking on successful completion. Frozen expectations use Python bytes.replace,
not converter logic. O1/O2 and fixed flags precede evaluation. Eighteen inputcases
on file and pipe plus three failures yield78 real Windows process observations.
Scripted chunk/error schedules are separate authored backend probes, not original
OS scheduling observations. Freeze and unmodified PE hashes must be retained.
