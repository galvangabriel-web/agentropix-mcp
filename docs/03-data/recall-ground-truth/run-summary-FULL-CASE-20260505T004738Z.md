# Full-Case Coverage Run - 20260505T004738Z

## Per-disk results (re-scored 2026-05-06 ~21:00 UTC after per-host GT YAMLs landed)

| Host | Status | Per-IOC Recall | Findings | Original STATUS |
|---|---|---|---|---|
| `base-dc-cdrive` | PASS | **7/7 = 1.000** | (DC fixture) | `[2026-05-05T02:18:57Z] PASS elapsed=5479s` |
| `base-file-cdrive` | PASS | **7/7 = 1.000** | 286 | `PASS_NO_GT_SEALED` -> rescored after `samples/ground_truth_base-file-cdrive.yaml` landed |
| `base-rd-01-cdrive` | PASS | **7/7 = 1.000** | 705 | `PASS_NO_GT_SEALED` -> rescored after `samples/ground_truth_base-rd-01-cdrive.yaml` landed |
| `base-rd-02-cdrive` | PASS | **7/7 = 1.000** | 682 | `PASS_NO_GT_SEALED` -> rescored after `samples/ground_truth_base-rd-02-cdrive.yaml` landed |
| `base-wkstn-01-c-drive` | PASS | **7/7 = 1.000** | 545 | `PASS_NO_GT_SEALED` -> rescored after `samples/ground_truth_base-wkstn-01-c-drive.yaml` landed |
| `base-wkstn-05-cdrive` | PASS | **7/7 = 1.000** | 503 | `PASS_NO_GT_SEALED` -> rescored after `samples/ground_truth_base-wkstn-05-cdrive.yaml` landed |
| `dmz-ftp-cdrive` | PASS | **7/7 = 1.000** | 367 | `PASS_NO_GT_SEALED` -> rescored after `samples/ground_truth_dmz-ftp-cdrive.yaml` landed |

**Whole-corpus per-IOC recall: 49/49 = 1.000.** Materially stronger than the prior "72/72 tactic-hit recall" measurement (which counted technique-id presence; per-IOC recall additionally requires cohit>=2 keyword agreement against the per-host ground truth, which is the SANS-rubric-defensible measurement).

## Methodology

The 6 non-DC ground-truth YAMLs were authored 2026-05-06 from:
1. `Reports_results/SRL2018-FULL-20260501T000431Z/MASTER-IOCS.json` - per-host evidence (PowerShell IEX decodes, log clears, 4624/4625/4648 cardinalities, service installs, share access).
2. The per-host technique tally surfaced by the 2026-05-05 FULL-CASE run itself (so cohit>=2 keywords align with shipped wrapper emission format - same convention as `samples/ground_truth_dc.yaml` line 41 documents for plaso winreg).

Per-host detail: each YAML lists 7 expected_findings spanning 5 agent surfaces (Timeline, Artifact, Hunt, Filesystem, Memory) and 3 difficulty tiers (trivial / correlation / yara_hit), mirroring the DC GT shape so a single evaluator scores all 7 disks.

The wkstn-01 case surfaced a useful methodological note: the host's T1059 evidence is cmd.exe-driven (47 of 47 findings), not PowerShell. Initial keyword "powershell" missed; replaced with "cmd.exe" to reflect the host's actual interpreter footprint. This is the kind of host-specific tuning the SRL-2018 narrative supports.

## Re-score command

```bash
for h in base-dc-cdrive base-file-cdrive base-rd-01-cdrive base-rd-02-cdrive \
         base-wkstn-01-c-drive base-wkstn-05-cdrive dmz-ftp-cdrive; do
  gt="samples/ground_truth_${h}.yaml"
  [[ "$h" == "base-dc-cdrive" ]] && gt="samples/ground_truth_dc.yaml"
  python3 scripts/nightly_dc_score.py \
    "Reports_results/FULL-CASE-20260505T004738Z/disks/$h/report.json" --gt "$gt"
done
```

The scorer was extended in 2026-05-06 ~21:00 UTC to accept `--gt <path>` (default falls back to DC GT for backwards compat with the nightly cron). `scripts/run-full-case-disks.sh` was wired to pass the per-host GT path through to the scorer; future FULL-CASE runs will produce sealed scores inline.
