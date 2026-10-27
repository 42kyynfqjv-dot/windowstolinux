# Heap effects measurement

Status: local component implementation; Windows CI pending. No heap PE translation
is claimed. Frozen sources/configuration/expectations are in frozen.json (f188f69).

Locally: ten new heap tests pass; 148 root test functions, formatting and Clippy
are being checked. Windows success/failure observations, cross-host conversion
rejections and native component comparisons will be recorded after exact-head CI.

## Preserved first measurement failure

Head c23cceb, push run40553692359 stopped before compilation/observation because
Windows checkout changed cases.json line endings. Its pinned SHA256 is
08e4dbf0a238df8f8bfc40805b8263c7f2e362a8ec3f2585cc112b521bbe5973. Added explicit LF
checkout attributes; source, flags, vector semantics and frozen hashes are unchanged.
This is a harness provenance fix, not a converter or original-program timeout fix.
