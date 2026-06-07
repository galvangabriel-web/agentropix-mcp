# Business / Risk Report — CHALLENGE-NOTCHITUP

> **Likelihood scale (FIRST 5-tier):** almost_certain > highly_likely > likely > unlikely > remote. Likelihood estimates the probability of the assessed activity; it is kept separate from analytic confidence.
>
> **Confidence (LCA):** high / moderate / low — the analyst's confidence in the assessment given evidence quality and corroboration. Distinct from likelihood.

## Risk Register

| Risk | Likelihood | Severity | Score | Business impact | Compliance | Owner | Analyst ref |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Large PAGE_EXECUTE_READWRITE region in WmiPrvSE.exe (PID 2292) | unlikely | high | 8 | Large PAGE_EXECUTE_READWRITE region in WmiPrvSE.exe (PID 2292) | — | — | [F-NOTCH-004](#large-page-execute-readwrite-region-in-wmiprvse-exe-pid-2292) |
| PAGE_EXECUTE_READWRITE injected region in explorer.exe (PID 1944) | unlikely | high | 8 | PAGE_EXECUTE_READWRITE injected region in explorer.exe (PID 1944) | — | — | [F-NOTCH-001](#page-execute-readwrite-injected-region-in-explorer-exe-pid-1944) |
| PAGE_EXECUTE_READWRITE RWX region in chrome.exe (PID 2124) | unlikely | medium | 6 | PAGE_EXECUTE_READWRITE RWX region in chrome.exe (PID 2124) | — | — | [F-NOTCH-003](#page-execute-readwrite-rwx-region-in-chrome-exe-pid-2124) |
| PAGE_EXECUTE_READWRITE zeroed RWX region in explorer.exe (PID 1944) | unlikely | medium | 6 | PAGE_EXECUTE_READWRITE zeroed RWX region in explorer.exe (PID 1944) | — | — | [F-NOTCH-002](#page-execute-readwrite-zeroed-rwx-region-in-explorer-exe-pid-1944) |
| Evidence image registered (chain-of-custody hash) | unlikely | info | 0 | Evidence image registered (chain-of-custody hash) | — | — | [F-NOTCH-005](#evidence-image-registered-chain-of-custody-hash) |
