# `diagrams/` — VANKO case diagrams (Mermaid sources + rendered PNGs)

The five case diagrams embedded by [`../VANKO-FORENSIC-REPORT.md`](../VANKO-FORENSIC-REPORT.md):
each `dN.mmd` is the Mermaid source, each `dN.png` is its committed high-resolution render
(GitHub/GitLab-safe — the report embeds the PNGs, not client-rendered Mermaid).

> **Sanitization note:** in the excerpts below, evidence-network IPs from the 2016 disk image
> (`192.168.x.x` file-server addresses) are replaced with `<FILESERVER-IP-1>` / `<FILESERVER-IP-2>`
> per publication policy. The on-disk `.mmd` sources contain the literal values.

## Files

| File | Type | Size | What it is |
|---|---|---|---|
| `d1.mmd` | Mermaid source | 832 B | Attack-lifecycle flowchart: insider access → collection → staging → archive/disguise → dual-cloud exfil → handler coordination → anti-forensics (MITRE-tagged) |
| `d1.png` | PNG render | 308 KB | 1104×5400 vertical render of `d1.mmd` (report §"Attack lifecycle") |
| `d2.mmd` | Mermaid source | 844 B | Exfiltration & buyer-channel architecture: file server → STARKSURFACE staging → Dropbox/OneDrive/USB → RU + CN channels |
| `d2.png` | PNG render | 162 KB | 3136×1052 render of `d2.mmd` |
| `d3.mmd` | Mermaid source | 496 B | 2016 exfiltration timeline (Apr 30 → Nov 4, UTC) |
| `d3.png` | PNG render | 172 KB | 3136×1368 render of `d3.mmd` |
| `d4.mmd` | Mermaid source | 559 B | IOC mindmap: network / host / accounts / USB indicators |
| `d4.png` | PNG render | 287 KB | 3136×1332 render of `d4.mmd` |
| `d5.mmd` | Mermaid source | 370 B | Findings pipeline: 19 findings → 10 confirmed / 9 refuted → DRAFT → APPROVED (examiner HMAC) → Wazuh egress |
| `d5.png` | PNG render | 86 KB | 3136×756 render of `d5.mmd` |

> The `.mmd` sources are local working files; only the `.png` renders are tracked in the published
> repository.

## d1 — Attack lifecycle (full source, IPs sanitized)

```mermaid
flowchart TD
  A["Initial Access — Authorized Insider<br/>Valid Accounts · T1078"] --> B["Collection — StarkResearch file server<br/>STARK-FILESERVE / <FILESERVER-IP-1> / <FILESERVER-IP-2> · T1039"]
  B --> C["Persistence / Evasion<br/>Masquerade account 'defaultprinter'<br/>Sec 4720 / 4724 · T1136.001"]
  C --> D["Local Staging<br/>defaultprinter Desktop temp.zip · T1074.001"]
  D --> E["Archive & Disguise<br/>vacation photos.7z (7-Zip)<br/>T1560.001 · T1036"]
  E --> F["Exfiltration to Cloud<br/>Dropbox 984347879 + OneDrive · SRUM<br/>T1567.002"]
  F --> G["Handler Coordination<br/>RU: Merrick to Bulgakov · CN: QQ / CAS<br/>T1567"]
  G --> H["Anti-Forensics<br/>SDelete + prefetch / cache purge<br/>defeated by VSS · T1070.004"]
  style A fill:#1f4e79,color:#fff
  style F fill:#7a1f1f,color:#fff
  style H fill:#5a3a1f,color:#fff
```

Full source: `d1.mmd` *(local-only)* · render: [`d1.png`](d1.png)

## d2 — Exfiltration & buyer-channel architecture (full source, IPs sanitized)

```mermaid
flowchart LR
  FS["StarkResearch File Server<br/>STARK-FILESERVE<br/><FILESERVER-IP-1> / <FILESERVER-IP-2>"] -->|"T1039 copy"| H
  subgraph H["STARKSURFACE — user 'PC User'"]
    DP["defaultprinter mule<br/>temp.zip (2.6 MB)"]
    ARC["vacation photos.7z<br/>SHA-256 b210bcd8..."]
  end
  H -->|"T1567.002"| DBX["Dropbox<br/>account 984347879"]
  H -->|"T1567.002"| OD["OneDrive<br/>cid CBDFA76592A9F765"]
  H -.->|"artifact-level"| USB["USB volumes<br/>5650959F · C83A6C7B · 8C059ED1"]
  DBX --> CN["China channel<br/>nina_kwai qq.com<br/>im.cas.cn — CAS Institute"]
  H -->|"email · 3 attachments"| RU["Russia channel<br/>Merrick mmerr001 gmail.com<br/>to recruiter V. Bulgakov"]
```

Full source: `d2.mmd` *(local-only)* · render: [`d2.png`](d2.png)

## d3 — Exfiltration timeline (full source)

```mermaid
timeline
  title VANKO Exfiltration Timeline (UTC, 2016)
  2016-04-30 : Classified corpus copied server to OneDrive (MFT copy-signature)
  2016-06-18 : Masquerade 'defaultprinter' created (4720/4724) : temp.zip staged
  2016-06-27 : Merrick recruitment + reply with 3 attachments
  2016-06-29 : 7-Zip archiving (last run 20:26)
  2016-06-30 : 01:28 vacation photos.7z : 01:30 SDelete x10 : 01:46 Dropbox upload : 01:48 Dropbox folder deleted
  2016-11-04 : VSS snapshot + physical image acquired
```

Full source: `d3.mmd` *(local-only)* · render: [`d3.png`](d3.png)

## d4 — IOC mindmap (full source, IPs sanitized)

```mermaid
mindmap
  root((VANKO IOCs))
    Network
      STARK-FILESERVE share
      <FILESERVER-IP-1> and <FILESERVER-IP-2>
      Dropbox acct 984347879
      OneDrive CBDFA76592A9F765
      nina_kwai qq.com
      mmerr001 gmail.com
      im.cas.cn
    Host
      vacation photos.7z b210bcd8
      sdelete.exe / sdelete64.exe
      defaultprinter temp.zip
      SDELETE prefetch deleted
      Level 12 Project Nehemiah
    Accounts
      PC User anthony.vanko
      defaultprinter masquerade
    USB artifact-level
      5650959F StarkResrch
      C83A6C7B Stark-IR
      8C059ED1 drive W
```

Full source: `d4.mmd` *(local-only)* · render: [`d4.png`](d4.png)

## d5 — Findings approval pipeline (full source)

```mermaid
flowchart LR
  R["19 findings<br/>(5 phases)"] --> C["10 CONFIRMED"]
  R --> X["9 REFUTED<br/>FP gate"]
  C --> D["DRAFT<br/>record_finding"]
  D --> A["APPROVED<br/>10x examiner HMAC"]
  A --> W["Wazuh egress<br/>ledger seq 139"]
  A --> RPT["Finalized DFIR report"]
  style C fill:#1f5f3a,color:#fff
  style X fill:#5a5a5a,color:#fff
  style A fill:#1f4e79,color:#fff
```

Full source: `d5.mmd` *(local-only)* · render: [`d5.png`](d5.png)
