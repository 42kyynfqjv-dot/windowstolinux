# CLI source v2 freeze

This version calls GetLastError immediately after failed ReadFile and treats only
ERROR_BROKEN_PIPE as EOF. Other read failures still return 11. It preserves all
other byte/progress/exit semantics. The original parent filter.c and evidence are
unchanged: v1 exits 11 at pipe EOF even after correct output.

Source, 14 byte vectors, independent file/pipe/failure expectations and original
O1/O2 compiler flags are frozen before compiling or evaluating v2. Extra vectors
exercise 65535/65536/65537 bytes. Both file and anonymous-pipe input use the same
binary-exact expectation; a pipe writer close is normal EOF for this version.
Scripted outcomes supplement actual execution and are never PE translation.

Primary GetLastError contract: https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror
Only the failing ReadFile result's immediate last error is consumed. No claim is
made about successful calls preserving or resetting last-error state.
