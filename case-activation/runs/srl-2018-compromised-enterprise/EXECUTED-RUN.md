# SRL-2018 — Case Activation + Full Investigation (EXECUTED)

> **LOCAL / OPERATIONAL — review before publishing.** Contains real case inventory +
> evidence custody hashes. Executed live against the running MCP server
> (`http://100.85.162.82:8765/mcp`) via `drivers/mcp_call.py`.
> **Activated:** 2026-06-07 · **Investigation completed:** 2026-06-08 · **Examiner:** victor.galvan.

## Phase 0 — Activation: SRL-2018 is the ACTIVE case

`~/.agentropix/active_case`: `MEMDUMP-RAW-2014` → **`SRL-2018-COMPROMISED-ENTERPRISE`**

| Step | Tool | Outcome |
|---|---|---|
| 1 | `case_init` | case_id **SRL-2018-COMPROMISED-ENTERPRISE**, status `active`, severity high, scope `/cases/SRL-2018` |
| 2 | `case_activate` | pointer written to `~/.agentropix/active_case` |
| 3 | `case_status` | **active: true · indexer_reachable: true** |
| 4 | `evidence_register` (DC disk) | `base-dc-cdrive.E01` → SHA-256 `e2b9cf0cb6759fd079f45fa903d80bde602160ff969c969c6f0cd704965b31b1`, 12,325,692,793 B, indexed → `agentropix-evidence-2026.06.07` |
| 5 | `evidence_register` (DC memory) | `base-dc-memory.img` → SHA-256 `9679193c2b7852817006c55481124666422fea67ba63c872cf5e4203c6fa629a`, 5,368,709,120 B, indexed |
| 6 | `get_image_info` (DC) | MD5 `e18b450127de04afb3211faa456ada27`, media 33 GiB (36,110,860,288 B) — matches `ewfinfo` |

Per-step JSON responses: `step1_case_init.json` … `step6_get_image_info_dc.json` (this dir).

## Phase 1+ — Full investigation (subsequently executed, 2026-06-07/08)

The activation above was followed by a complete, recorded investigation across the whole
estate — **254 agentropix MCP actions**, captured verbatim under
`docs/06-use-cases/assets/srl-2018-training-session/` (session log + per-step JSON; large/raw,
**kept local, not committed**). The published write-up of that investigation is the sealed case
report: [SRL-2018 Forensic Report](../../../docs/12-CASES-REPORTS/srl-2018-report/SRL-2018-FORENSIC-REPORT.md)
· [Technical Appendix](../../../docs/12-CASES-REPORTS/srl-2018-report/TECHNICAL-APPENDIX.md).

**Reconstructed attack chain:** external RDP foothold (`nfury` from 192.168.30.10/.11 → wkstn-05)
→ dual C2 — Metasploit/Meterpreter (`p.exe`, MSSE named pipe, hub 172.16.4.10:8080) + PowerShell
Empire (`squirreldirectory.com`) → service persistence (`perfmonsvc64.exe`) → credential theft
(SAM-from-VSS on the DC; 692-NTLM brute-force of `tdungan`) → RD-01⇄FILE lateral hub
(WinRM/RDP/SMB) → collection of user `nfury`'s **Carbonadium** IP → DMZ-FTP exfil; anti-forensics
via `csrss.exe` timestomping + secure deletion.

- **12 findings** recorded as DRAFT and **examiner-approved** (HMAC-sealed).
- **9 malware samples** recovered (SHA-256 in the report) — quarantined **outside** the repo.
- **Wazuh** (operator-authorized egress): 12 findings indexed + IOC CDB lists published.
- **Report:** [`docs/12-CASES-REPORTS/srl-2018-report/`](../../../docs/12-CASES-REPORTS/srl-2018-report/)
  — `SRL-2018-FORENSIC-REPORT.md`, `TECHNICAL-APPENDIX.md`, `WAZUH-IOC-GALLERY.md`; decision ledger seq 137–138.

## Caveats / honest scope

- The `42.112.153.164` "C2 IP" was an **operator eval injection**, not a real lead — excluded.
- Several memory images were **smeared** (non-atomic acquisition) → in-memory `svcscan`/`malfind`
  degraded; disk SYSTEM-hive fallback + YARA used instead. Full caveats in the report.
- DRAFT → APPROVED remained a **human-only HMAC Hard-Stop** (examiner sign-off); the agent never
  self-approved. Wazuh egress was a Hard-Stop released only on explicit operator authorization.
