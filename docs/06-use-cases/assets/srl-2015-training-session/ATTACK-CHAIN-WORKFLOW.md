# SRL-2015 — Attack Chain & Recorded Workflow

**Case:** `SRL-2015-APT-ENTERPRISE` · SANS FOR508 Stark Research Labs APT · 4 Windows hosts
(disk E01 + raw memory each, 56 GB) · examiner `victor.galvan` ·
MCP `http://100.85.162.82:8765/mcp` (tool_count 72).

This is the curated companion to the recorded session
(`training-session-paged.mp4` / `.gif` / `.cast`, transcript in `training-session.transcript.txt`).
15 numbered actions: actions 1–11 backfill the initiation + first-pass memory phase (idempotent
re-runs live; immutable hashing / volatility replayed from captured output); actions 12–15 are the
live deeper-phase slice.

## Host map (image acquisition metadata)

| Host | OS | Role | IP | Disk E01 sha256 (custody) |
|---|---|---|---|---|
| xp-tdungan | Win XP SP3 x86 | workstation | 10.3.58.7 | `117511847d05cf3a…e402eb0` |
| win7-32-nromanoff | Win7 x86 SP1 | workstation | 10.3.58.5 | `f92662135db8d1a5…a5a1e5b6` |
| win7-64-nfury | Win7 x64 | workstation | 10.3.58.6 | `a5df0b38ec699656…6d1589c7` |
| win2008R2-controller | Win Server 2008 R2 | **domain controller** | 10.3.58.4 / .9 | `389ea6b4969cc132…d6db4e7e` |

## Attack chain (memory-derived, controller)

```
services.exe (556) ──▶ usboesrv.exe (27304)  "KernelPro USB over Ethernet Service"
                       AUTO_START · C:\Windows\system32\usboesrv.exe
                       └─▶ C2 beacon  10.3.58.4 ──▶ 96.255.98.154:29932  (3× ESTABLISHED)     [T1543.003 + T1071]
                       + fake driver suite usboebusdrv / usboeloaderdrv (AUTO_START kernel drivers)

explorer.exe (8512)  ── RWX injected (malfind 0x2280000,0x38e0000) ───────────────────────── [T1055]
   ├─▶ usboe.exe (27144)  second-stage (created 2012-03-20 18:54:16)
   └─▶ cmd.exe (attacker interactive)

System (4) ──▶ 173.173.88.154:443  ESTABLISHED   (anomalous; System never originates 443)     [T1071.001]

win7-32-nromanoff (10.3.58.5) ──SMB 445──▶ controller   ESTABLISHED                            [T1021.002]
```

## DRAFT findings (4 · awaiting examiner HMAC approval at portal :8443)

| ID | MITRE | Sev | Conf | IOC |
|---|---|---|---|---|
| srl2015-controller-c2-usboesrv-001 | T1543.003 | critical | 0.90 | 96.255.98.154 |
| srl2015-controller-injection-explorer-002 | T1055 | high | 0.80 | usboe.exe |
| srl2015-controller-c2-system443-003 | T1071.001 | high | 0.75 | 173.173.88.154 |
| srl2015-lateral-nromanoff-to-dc-004 | T1021.002 | medium | 0.60 | 10.3.58.5 |

## IOCs

- **C2 IPs:** `96.255.98.154:29932` (usboesrv) · `173.173.88.154:443` (System pid 4)
- **Files/services:** `C:\Windows\system32\usboesrv.exe` · `usboe.exe` · services `usboesrv`,
  `usboebusdrv`, `usboeloaderdrv`
- **Cross-host pivot:** `pivot_on_ioc 96.255.98.154` → total_hits 3, **isolated to the controller**
  (the other 3 hosts are clean of this IOC).

## Defender/IR infrastructure (NOT attacker — excluded)

- `f-response-ent` → `10.3.16.5:3260` (F-Response iSCSI) on controller + nfury; analyst RDP from
  `10.3.16.5`. The `.mans` (Redline), `baseline-memory/`, and `precooked/` trees are SANS reference.

## Engineering notes surfaced by the run

- **All 4 disks are single-volume logical NTFS** (no partition table) → `fls offset=0`; the activation
  guide's "mmls-derived offset" does not apply to these images.
- **win7-32-nromanoff memory** fails volatility3 kernel auto-detection (pslist = 11× `pid=0/unknown`);
  the wrapper's `run_volatility` does not expose `windows.info`. Remediation (offline symbol set) is
  queued — that host's memory leg is degraded until resolved.
- **XP** netscan is unsupported by volatility3 `windows.netscan` (use `netstat`/connscan); xp-tdungan
  returned 0 sockets for that reason, not because it was idle.
- **controller deleted-file sweep:** `fls deleted_only` → **54,523** deleted entries.

## Gates (held — by design)

- **Examiner approval** DRAFT→APPROVED is human-only HMAC at `:8443`; the assistant cannot self-approve.
- **Wazuh CDB IOC push** (SOC-facing egress) was **not** performed — that requires operator authorization.

## Deeper phase — results (actions 16–33, recorded live)

- **Disk↔memory corroboration (the key result):** controller `System.evtx` **7045** service-installs on
  `Controller.shieldbase.local` — `usboedrv` 17:57:59 → `usboeloaderdrv` 17:57:59 → `usboebusdrv`
  17:58:08 → **`usboesrv` 2012-03-20 17:58:12** — exactly matches the memory `usboesrv.exe` (pid 27304)
  create_time 17:58:12. The disk event log independently confirms the memory C2-service finding.
- **Cross-host `correlate_timeline`:** **900 events unified across all 4 hosts** (Security+System;
  4624/4625/4672/4688/7045/7036/1102). e.g. win7-32 4624×287, win7-64 7036×263.
- **`run_bulk_extractor` (controller):** **7,543,400** features — domain 4.42M, url 994,877, email
  45,043, ip 130, ccn 226, aes_keys 142, evtx_carved 243,984, httplogs 27,340.
- **shimcache:** 962 AppCompatCache entries/host (execution evidence; TEMP/ProgramData installers).
- **`report_generate {full}`** sealed the case (`report_id 61376af3…`); `approved_finding_count 0`,
  all sections empty by design — DRAFT findings are excluded until examiner HMAC approval.

### OS/role-correct gaps surfaced (not tool faults)

- **win7-32-nromanoff memory** still unresolved: both `pslist` and `psscan` fail to recover processes →
  the image needs an **offline symbol table** (vol3 PDB auto-detect can't resolve this build). Remains
  the one degraded leg; queued for offline symbol work.
- **Controller (Server 2008 R2)** has **no Prefetch (disabled on Server) and no Amcache.hve** by
  default — the parsers correctly found nothing to parse.
- **XP** memory has no vol3 `netscan` (Vista+ only); `get_evtx` needs a **single .evtx file** target
  (a directory target returns 0 — corrected mid-run).

## Still queued (require approval / offline work)

win7-32 offline symbol remediation · per-host registry persistence deep-dive (NTUSER run-keys) ·
examiner approval of the 4 DRAFT findings → re-run `report_generate {full}` to populate sections ·
optional operator-authorized Wazuh CDB IOC push.
