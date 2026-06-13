# SRL-2015 — raw per-host findings (the 2,233 aggregation, proven)

> The eight per-host/per-modality findings JSONs the autonomous DFIR swarm produced — one per
> evidence source. Their finding counts sum to the **2,233** headline used throughout the case
> report and the investigation video. Previously withheld by reference (case
> [`../README.md`](../README.md) §3.4); published here so the aggregation is verifiable from raw data.

## The 2,233 aggregation

| File | Host | Modality | Findings |
|---|---|---|---|
| [`win2008R2-controller.disk.json`](win2008R2-controller.disk.json) | win2008R2-controller (DC) | disk | 196 |
| [`win2008R2-controller.memory.json`](win2008R2-controller.memory.json) | win2008R2-controller (DC) | memory | 512 |
| [`win7-32-nromanoff.disk.json`](win7-32-nromanoff.disk.json) | win7-32-nromanoff | disk | 250 |
| [`win7-32-nromanoff.memory.json`](win7-32-nromanoff.memory.json) | win7-32-nromanoff | memory (baseline †) | 10 |
| [`win7-64-nfury.disk.json`](win7-64-nfury.disk.json) | win7-64-nfury | disk | 484 |
| [`win7-64-nfury.memory.json`](win7-64-nfury.memory.json) | win7-64-nfury | memory | 432 |
| [`xp-tdungan.disk.json`](xp-tdungan.disk.json) | xp-tdungan | disk | 339 |
| [`xp-tdungan.memory.json`](xp-tdungan.memory.json) | xp-tdungan | memory (baseline †) | 10 |
| | | **TOTAL** | **2,233** |

† Per-host RAM dumps existed only for the controller and nfury; the nromanoff/tdungan memory runs
executed against OS-matched **baseline** images (10 findings each) — which is why all 5 `malfind`
payloads come from the controller and nfury dumps. See [`../README.md`](../README.md) §3.1.

Each file carries `evidence_image_sha256` (matching the §3.1 hash table), the per-finding
`finding_id` / MITRE mapping / confidence, and the tool-call trace that produced it.

Cross-check the total yourself:
```bash
python3 -c "import json,glob; print(sum(len(json.load(open(f)).get('findings',[])) for f in glob.glob('*.json')))"
# -> 2233
```
This equals `aggregation.total_findings` in
[`../wazuh-push-receipts/pipeline_summary_FINAL.json`](../wazuh-push-receipts/pipeline_summary_FINAL.json).

## Sanitization

These files were **published unmodified** — they contain only `/cases/SRL-2015/...` evidence paths
(already documented in the case worked-examples), forensic evidence IP addresses and artifacts (the
fictional SHIELD/Stark network and the attacker C2 indicators — the same indicators in
[`../exports/iocs.json`](../exports/iocs.json)), and registry/account artifact names (e.g. the
`DefaultPassword` LSA-secret **finding name** with a hex value-preview — an artifact, not a usable
credential). They carry **no** Wazuh endpoint, internal analysis-host identifier, or credential.

Source: local pipeline working set `…/SRL2015-PIPELINE-V2/<host>/{disk,memory}.json`.
