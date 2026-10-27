# Converter dependency notices

The converter pins iced-x86 1.21.0 (MIT) and lazy_static 1.5.1
(MIT OR Apache-2.0; MIT selected here), with checksums in Cargo.lock.
Retain these notices when distributing the converter. Original WindowsToLinux
code remains MIT OR Apache-2.0. These dependencies are not embedded in generated
Rust or its native ELF; the emitter uses independently authored support code.
The optional evaluation workspace has additional notices in
[its notice bundle](tools/decoder-eval/THIRD-PARTY-NOTICES.md).

## iced-x86 1.21.0

Exact upstream v1.21.0 license (Git blob eff62de93f8d891cdd48b24cd4f995522d87de8e):

```text
https://github.com/icedland/iced
Copyright (C) 2018-present iced project and contributors

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

```

## lazy_static 1.5.1

Copyright from packaged src/lib.rs; license text from packaged LICENSE-MIT:

```text
Copyright 2016 lazy-static.rs Developers

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
```

## Z3 4.15.4 (optional local compiler dependency for streaming admission)

The stream verifier invokes the official Z3 4.15.4 executable. CI provisions
z3-solver 4.15.4.0 with platform wheel checksums in
`research/cli/v2/proof/requirements.txt`. No solver code or binary is embedded in
generated Rust/ELF. The exact upstream MIT license is retained in
[Z3-LICENSE.txt](research/cli/v2/proof/Z3-LICENSE.txt), from
https://github.com/Z3Prover/z3/blob/z3-4.15.4/LICENSE.txt.
Retain that notice if distributing Z3 with the compiler. Original implementation
and runtime support remain MIT OR Apache-2.0.
