# SRL-2018 — Full Attack-Chain Reconstruction Workflow

> **Goal:** correlate **every** process, network connection, host, account, and event across the
> whole estate to build one defensible **chain of attack** — initial access → execution → injection →
> persistence → lateral movement → C2 → (exfil). All agents default to **Opus 4.8**; all steps
> recorded in `session-actions.log`; **stop before approval/Wazuh (Hard-Stops).**
>
> **Anchor finding:** the `p.exe` DNS-tunneling C2 implant on **rd-01, file, wkstn-01, wkstn-05**
> (`C:\Windows\Temp\perfmon\p.exe`). The chain explains how it got there and spread.

## Hosts & evidence (the board)
| Host | disk E01 | memory | implant? | role |
|---|:--:|:--:|:--:|---|
| base-dc | ✓ | ✓ (smeared) | no | Domain Controller (likely lateral hub) |
| base-file | ✓ | ✓ (smeared) | **yes** | file server |
| base-rd-01 | ✓ | ✓ (clean) | **yes** | RD/terminal server (malfind source) |
| base-rd-02 | ✓ | ✓ (smeared) | no | RD/terminal server |
| base-wkstn-01 | ✓ | ✓ (smeared) | **yes** | workstation |
| base-wkstn-05 | ✓ | ✓ (smeared) | **yes** | workstation |
| dmz-ftp | ✓ | — | ? | DMZ FTP (exfil candidate) |

## Phases

### Phase 1 — Process & network correlation (memory)  ← per-host, parallelizable
For every host: `build_process_tree` (roots/orphans, **find the parent that launched/injected p.exe & powershell**) + `get_netscan` (every socket: proto, local, **foreign_addr:port**, state, owning PID). Output: a **per-host process→socket table** and the **remote-address inventory** (C2 candidates, inter-host connections, listeners). netscan is pool-tag based → works on the smeared images.

### Phase 2 — Lateral-movement events (disk evtx)  ← per-host
Extract `Security.evtx` + `System.evtx` per host; `get_evtx` filtered to:
- **4624 / 4625** logons (type **3**=network, **10**=RDP) + **4648** explicit-cred logons → who authenticated to whom.
- **5140 / 5145** SMB share access → file movement / tool staging.
- **7045 / 4697** service install, **4698** scheduled task → persistence & remote exec.
Build the directed **host→host authentication/SMB graph** (source IP/account → target host, timestamp).

### Phase 3 — Host & network topology
Per host: network config (IP, gateway, NICs, DNS servers) from the **SOFTWARE/SYSTEM registry**
(`Tcpip\Parameters\Interfaces`) + ARP/routing from memory (`run_volatility netstat`). Map the subnet,
the gateways, and the **DNS server** the implant would tunnel through.

### Phase 4 — Timeline fusion
`correlate_timeline` across the compromised hosts + the implant first-seen times → one UTC sequence:
order of host compromise, injection times, lateral hops.

### Phase 5 — Synthesis (Opus 4.8 analyst)
Assemble the chain → **MITRE ATT&CK** mapping, a **host-graph diagram** (who→who), the **IOC set**
(p.exe path/hash, DNS-tunnel signature, injected PIDs, accounts, remote addrs), confidence per link,
and the **gaps** (what's unproven). Stage DRAFT findings (dry-run); **do not approve**.

## Execution order
Phase 1 (have most netscan/process_tree already) → Phase 2 (extract+parse evtx per host) →
Phase 3 (registry network config) → Phase 4 (timeline) → Phase 5 (synthesize). Heavy steps run as
recorded background batches; per-step JSON saved verbatim.
