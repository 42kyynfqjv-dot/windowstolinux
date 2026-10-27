# Frozen streaming composition measurement

Sources and independent expectations are frozen before compiler/converter evaluation.
Three application transformations: four-way ASCII ROT13 selection, reverse-index XOR,
and in-place nonzero-byte compaction. Capacities128/384/257 deliberately differ.
Common synchronous I/O follows documented ReadFile/WriteFile contracts; it is authored
for this corpus using the established error/EOF convention. No production converter
or fixture generator supplies expected results. ROT13 uses a lookup translation
oracle; XOR uses direct byte mapping; compaction uses sequence filtering.

O1/O2 flags and custom entry are fixed in frozen.json. No ordinary CRT startup is
claimed. Thirteen binary vectors include all256 bytes and65537-byte multi-chunk input;
file and pipe observations plus three real failures yield174 Windows baselines.
These selected programs test composition, not statistical application compatibility.
Compiler outputs remain untouched; support will not be expanded during measurement.
