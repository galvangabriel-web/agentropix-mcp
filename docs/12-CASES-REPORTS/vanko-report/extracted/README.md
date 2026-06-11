# `extracted/` — (intentionally empty) original extraction destination

This folder was created as the intended destination for `extract_files` output (registry hives etc.)
at the start of the VANKO run — and is **empty by design**: the Agentropix **Thymus** policy layer
rejected it as an extraction destination because it is not under an allowed evidence/scratch prefix.
All artifact extraction for this case was therefore redirected to the sandbox scratch area
`/tmp/agentropix-sift-vanko/` (see `step_010_extract_hives.json` at the case root), and this folder
never received any files.

## Files

| File | Type | Size | What it is |
|---|---|---|---|
| *(none)* | — | — | Folder is empty; kept as the audit trail of a Thymus destination rejection |

## Why it is empty — the Thymus rejection (verbatim, trimmed)

From the case-root step log `step_009_extract_hives.json` (the attempted extraction into this
folder; the long allowlist of evidence prefixes is elided for brevity):

```json
{"tool":"extract_files","error":"Thymus REJECT: REJECT_OUTSIDE_ALLOWLIST:
 '/home/admin2/docu_agentro/docs/12-CASES-REPORTS/vanko-report/extracted'
 not under any allowed prefix: ...
 Allowed: /cases/, /mnt/, /media/, /evidence/, /tmp/agentropix-sift-,
 /usr/share/yara/rules/, /usr/share/yara-rules/, ... /cases/vanko/",
 "suggestion":"Choose a dest under /tmp/agentropix-sift-* or another Thymus-allowed prefix."}
```

The immediately following retry, `step_010_extract_hives.json`, used
`"dest_dir":"/tmp/agentropix-sift-vanko"` and succeeded — which is why every extracted-artifact
path cited in the reports lives under `/tmp/agentropix-sift-vanko/…`.

Full file: `step_009_extract_hives.json` at the case root *(local working artifact —
`step_*.json` raw logs are gitignored and not in the published repository)*.

> **Forensic note:** this is a deliberate guardrail demonstration — the platform refuses to write
> evidence derivatives outside the allowlisted evidence/scratch roots, even when the operator's own
> case folder is the requested destination. No raw-evidence content (and hence no personal data)
> was ever staged here.
