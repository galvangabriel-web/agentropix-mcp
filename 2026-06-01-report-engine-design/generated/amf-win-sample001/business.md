# Business / Risk Report — AMF-WIN-SAMPLE001

*Report ID:* `4159bc46eddc9b8adc32dbc84db51554b9e72524d0b44f63d2206affe235aa16`  ·  *Snapshot:* 2026-06-07T01:30:33.897125+00:00

> **Likelihood scale (FIRST 5-tier):** almost_certain > highly_likely > likely > unlikely > remote. Likelihood estimates the probability of the assessed activity; it is kept separate from analytic confidence.
>
> **Confidence (LCA):** high / moderate / low — the analyst's confidence in the assessment given evidence quality and corroboration. Distinct from likelihood.

## Risk Register

| Risk | Likelihood | Severity | Score | Business impact | Compliance | Owner | Analyst ref |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 RWX (PAGE_EXECUTE_READWRITE) malfind region in csrss.exe (PID 604) | unlikely | medium | 6 | 1 RWX (PAGE_EXECUTE_READWRITE) malfind region in csrss.exe (PID 604) | — | — | [F-AMF-S001-004](#1-rwx-page-execute-readwrite-malfind-region-in-csrss-exe-pid-604) |
| 9 RWX (PAGE_EXECUTE_READWRITE) malfind regions in winlogon.exe (PID 628, ppid 356) — dominant injected/unpacked-code concentration | unlikely | medium | 6 | 9 RWX (PAGE_EXECUTE_READWRITE) malfind regions in winlogon.exe (PID 628, ppid 356) — dominant injected/unpacked-code concentration | — | — | [F-AMF-S001-002](#9-rwx-page-execute-readwrite-malfind-regions-in-winlogon-exe-pid-628-ppid-356-dominant-injected-unpacked-code-concentration) |
| malfind recovered 15 executable VAD hits (11 PAGE_EXECUTE_READWRITE / RWX, 4 PAGE_EXECUTE_READ / RX) across 5 processes; RWX concentrated in winlogon.exe (PID 628, x9) | unlikely | medium | 6 | malfind recovered 15 executable VAD hits (11 PAGE_EXECUTE_READWRITE / RWX, 4 PAGE_EXECUTE_READ / RX) across 5 processes; RWX concentrated in winlogon.exe (PID 628, x9) | — | — | [F-AMF-S001-001](#malfind-recovered-15-executable-vad-hits-11-page-execute-readwrite-rwx-4-page-execute-read-rx-across-5-processes-rwx-concentrated-in-winlogon-exe-pid-628-x9) |
| 1 RWX (PAGE_EXECUTE_READWRITE) malfind region in msimn.exe (PID 1984); msmsgs.exe (PID 548) region is PAGE_EXECUTE_READ (RX, not RWX) | unlikely | low | 4 | 1 RWX (PAGE_EXECUTE_READWRITE) malfind region in msimn.exe (PID 1984); msmsgs.exe (PID 548) region is PAGE_EXECUTE_READ (RX, not RWX) | — | — | [F-AMF-S001-005](#1-rwx-page-execute-readwrite-malfind-region-in-msimn-exe-pid-1984-msmsgs-exe-pid-548-region-is-page-execute-read-rx-not-rwx) |
| 2 PAGE_EXECUTE_READ (RX, not RWX) malfind regions in lsass.exe (PID 692) — read-execute, no write permission | unlikely | low | 4 | 2 PAGE_EXECUTE_READ (RX, not RWX) malfind regions in lsass.exe (PID 692) — read-execute, no write permission | — | — | [F-AMF-S001-003](#2-page-execute-read-rx-not-rwx-malfind-regions-in-lsass-exe-pid-692-read-execute-no-write-permission) |
| Process inventory recovered: 21 running processes, coherent PPID forest (2 roots, 0 orphans, 0 LOLBin flags) | unlikely | low | 4 | Process inventory recovered: 21 running processes, coherent PPID forest (2 roots, 0 orphans, 0 LOLBin flags) | — | — | [F-AMF-S001-006](#process-inventory-recovered-21-running-processes-coherent-ppid-forest-2-roots-0-orphans-0-lolbin-flags) |
