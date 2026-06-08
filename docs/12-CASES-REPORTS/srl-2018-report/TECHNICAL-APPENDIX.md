# SRL-2018 — Technical Appendix

> Machine-extracted detail behind [SRL-2018-FORENSIC-REPORT.md](SRL-2018-FORENSIC-REPORT.md), pulled verbatim from the recorded agentropix MCP outputs. Internal RFC1918 addresses are the SRL estate; **external** addresses are flagged ⚠ for adjudication. Memory artifacts come from the per-host `.img` (several were acquisition-smeared — see the report's caveats).

## 1. Network sockets — foreign connections (memory `get_netscan`)

### base-file — 145 sockets, 37 distinct foreign

| foreign addr:port | proto | state | owning process |
|---|---|---|---|
| `10.10.0.200:80` | TCPv4 | CLOSED | ncpa_passive.e (pid 2868) |
| `10.10.150.181:445` | TCPv4 | ESTABLISHED | System (pid 4) |
| `10.10.254.1:61613` | TCPv4 | ESTABLISHED | rubyw.exe (pid 1156) |
| `10.10.4.4:445` | TCPv4 | CLOSED | System (pid 4) |
| `172.16.4.10:8080` | TCPv4 | CLOSED | ngentask.exe (pid 7092) |
| `172.16.4.10:8080` | TCPv4 | CLOSE_WAIT | powershell.exe (pid 3164) |
| `172.16.4.4:135` | TCPv4 | CLOSED | lsass.exe (pid 544) |
| `172.16.4.4:389` | TCPv4 | CLOSED | lsass.exe (pid 544) |
| `172.16.4.4:445` | TCPv4 | CLOSED | System (pid 4) |
| `172.16.4.4:49666` | TCPv4 | CLOSED | mmc.exe (pid 1332) |
| `172.16.4.4:49670` | TCPv4 | CLOSED | lsass.exe (pid 544) |
| `172.16.4.4:50155` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.4.6:52129` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.4.7:56481` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.5.20:443` | TCPv4 | CLOSED | masvc.exe (pid 1140) |
| `172.16.5.20:55582` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.5.21:5985` | TCPv4 | CLOSED | svchost.exe (pid 928) |
| `172.16.5.21:53384` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.5.25:5682` | TCPv4 | CLOSED | subject_srv.ex (pid 6160) |
| `172.16.5.25:63064` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.5.25:63329` | TCPv4 | CLOSED | System (pid 4) |
| `172.16.5.25:63330` | TCPv4 | CLOSED | svchost.exe (pid 632) |
| `172.16.5.26:52182` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.5.27:49737` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.5.50:44262` | TCPv4 | ESTABLISHED | subject_srv.ex (pid 6160) |
| `172.16.6.11:49763` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.6.13:49889` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.6.14:445` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.6.14:50333` | TCPv4 | CLOSED | svchost.exe (pid 1808) |
| `172.16.6.14:51841` | TCPv4 | CLOSED | svchost.exe (pid 1808) |
| `172.16.6.14:54993` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.6.14:60880` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.7.12:135` | TCPv4 | CLOSED | Uninstall.exe (pid 2340) |
| `172.16.7.12:60360` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.7.13:54369` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.7.14:445` | TCPv4 | ESTABLISHED | System (pid 4) |
| `172.16.7.16:49236` | TCPv4 | ESTABLISHED | System (pid 4) |

### base-rd-01 — 129 sockets, 11 distinct foreign

| foreign addr:port | proto | state | owning process |
|---|---|---|---|
| `13.89.220.65:443` ⚠ | TCPv4 | CLOSED | - (pid 0) |
| `172.16.4.10:8080` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.4.4:389` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.4.5:445` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.4.5:3389` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.20:443` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.21:5985` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.50:39372` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.6.14:65368` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.7.15:445` | TCPv4 | ESTABLISHED | - (pid 0) |
| `52.16.55.11:443` ⚠ | TCPv4 | CLOSED | - (pid 0) |

### base-rd-02 — 130 sockets, 8 distinct foreign

| foreign addr:port | proto | state | owning process |
|---|---|---|---|
| `10.10.200.207:5672` | TCPv4 | ESTABLISHED | - (pid 0) |
| `10.10.254.1:61613` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.4.10:8080` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.4.4:49670` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.20:443` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.21:5985` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.50:50146` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.6.11:64855` | TCPv4 | CLOSED | - (pid 0) |

### base-wkstn-01 — 148 sockets, 6 distinct foreign

| foreign addr:port | proto | state | owning process |
|---|---|---|---|
| `172.16.4.10:8080` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.4.4:135` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.20:443` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.21:5985` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.25:5682` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.5.50:56722` | TCPv4 | ESTABLISHED | - (pid 0) |

### base-wkstn-05 — 112 sockets, 5 distinct foreign

| foreign addr:port | proto | state | owning process |
|---|---|---|---|
| `172.16.4.10:8080` | TCPv4 | CLOSED | - (pid 0) |
| `172.16.4.6:443` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.5.21:5985` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.5.50:56012` | TCPv4 | ESTABLISHED | - (pid 0) |
| `172.16.6.11:59352` | TCPv4 | ESTABLISHED | - (pid 0) |

## 2. Injected-code regions — `base-rd-01` (memory `get_malfind`)

rd-01 is the one cleanly-acquired memory image; `malfind` flagged **7** RWX (`PAGE_EXECUTE_READWRITE`) regions. malfind has a high false-positive rate (JIT/.NET look identical), so this is an **adjudication list**, not asserted injection — but note the two implant processes appear here:

| PID | process | address | note |
|---|---|---|---|
| 8128 | `OUTLOOK.EXE` | `0x363a0000` | likely benign JIT/packed — verify |
| 8128 | `OUTLOOK.EXE` | `0x6f2f0000` | likely benign JIT/packed — verify |
| 6036 | `UpdaterUI.exe` | `0x5070000` | likely benign JIT/packed — verify |
| 8712 | `powershell.exe` | `0x1b4ce1a0000` | ⮕ consistent with PowerShell Empire in-memory stager |
| 8712 | `powershell.exe` | `0x1b4ce300000` | ⮕ consistent with PowerShell Empire in-memory stager |
| 8712 | `powershell.exe` | `0x1b4ce530000` | ⮕ consistent with PowerShell Empire in-memory stager |
| 8260 | `p.exe` | `0x2be0000` | ⮕ Meterpreter implant — consistent with injected shellcode |

## 3. Lateral-movement events — host `Security.evtx` (disk `get_evtx`)

Per-host counts of logon / share / service-install event IDs. _Kerberos TGT/TGS/NTLM (4768/4769/4776) are validated on the **Domain Controller's** log, not these member-host logs, so they're omitted here._

| host | 4624<br/>logon | 4625<br/>failed logon | 4648<br/>explicit-cred | 5140<br/>share access | 5145<br/>share detail | 7045<br/>service install | 4697<br/>service (sec) |
|---|---|---|---|---|---|---|---|
| dmz-ftp | 213 | 728 | 25 | 34 | 0 | 0 | 0 |
| file | 520 | 1 | 55 | 61 | 0 | 0 | 0 |
| rd-01 | 633 | 2 | 328 | 16 | 0 | 0 | 21 |
| rd-02 | 683 | 0 | 15 | 299 | 0 | 0 | 3 |
| wkstn-01 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| wkstn-05 | 861 | 1 | 90 | 48 | 0 | 0 | 0 |

> Reading it: **dmz-ftp** shows a burst of **4625** (failed logons → external brute-force surface); **rd-01** carries the most **4648** explicit-cred logons + **7045** service installs (the persistence + lateral hub); **rd-02** shows heavy **5140** share access. `wkstn-01`'s host log did not parse cleanly (XML-schema variance) — use the raw `ps_evtx_wkstn-01.json` for that host.

## 4. Further raw artifacts (kept local, not committed)

The full 254-step corpus in `docs/06-use-cases/assets/srl-2018-training-session/` also holds, per host: `get_pslist`/`build_process_tree` (process ancestry), `get_svcscan` + disk SYSTEM-hive services, `get_mftecmd` (MFT, 100k+ records — DC hive parsed here), `get_amcache`, `get_recmd` (registry: Run keys, network config), `get_bstrings`/`bulk_extractor` carved features, and `correlate_timeline` (fused UTC sequence). These were not committed (size + raw case data); request a specific extract and it can be added here.

---

_Generated verbatim from the recorded agentropix MCP tool outputs._