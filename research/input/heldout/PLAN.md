# SUB-560 preregistration

Four authored source families, each built with both MSVC /O1 and /O2, are frozen
before compiler or converter evaluation. All other compiler/linker flags and14
literal input expectations per family are in frozen.json/cases.json. Source files
use LF bytes; hashes capture exact checkout bytes. No source/configuration changes
are permitted after observing acceptance to manufacture success.

Shared invokes the same helper with two different length facts; nested composes
helper calls and a shifted pointer; composed uses the helper return in subsequent
arithmetic and a sentinel check; larger uses a five-WCHAR buffer with up to four
initialized digit reads. These test call-context reuse, caller state/refinement,
register/layout optimization and a known buffer-capacity boundary. Compiler output
may optimize away apparent source structure; record actual disassembly and do not
claim nested/shared machine behavior without confirming it.

Eight source/configuration artifacts and112 original Windows scenarios are planned.
Count unique C sources separately from compiler artifacts and runtime scenarios.
Accepted artifacts must pass actual Windows/ELF comparisons with identical Rust;
rejections keep original-only outcomes and exact first diagnostics. No support
expansion or binary surgery in this measurement. This authored, freestanding,
x86/MSVC/O1/O2 sample is neither random applications nor ordinary CRT/XP7 evidence.
Existing16 programs/51 composition scenarios and earlier corpus remain required.
