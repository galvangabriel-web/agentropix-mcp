# Evidence Dataset Documentation

> Scope: this document inventories every **evidence / dataset** artifact tracked in the
> Agentropix-SIFT documentation portal (`/home/admin2/docu_agentro`). Ground truth is the set of
> git-tracked files (`git ls-files`). Recovered malware/live samples are **withheld by design** —
> only their SHA-256 (from quarantine manifests and in-report hash tables) is published, never their
> bytes. Internal IPs, Wazuh endpoints, and credentials are kept as placeholders.
> Canonical numbers (72 MCP tools, 16 SIFT forensic tools, 4464 tests, 72/72 disk recall,
> 108/118 memory recall, Python 3.12+) follow `docs/08-reference/canonical-facts.md`.

---

## 1. Overview & Scope

The portal carries three classes of evidence-derived data:

1. **Fictional DFIR case sets (sealed)** — staged, *fictional* APT / insider-threat scenarios run end
   to end through the Agentropix-SIFT autonomous engine. Three cases are represented:
   - **SRL-2018** (`docs/12-CASES-REPORTS/srl-2018-report/`) — "Compromised Enterprise Network"
     multi-host APT IP-theft over the Stark Research Labs estate (`shieldbase.lan`), incident window
     2018-08-16 → 2018-09-05. Ships the flagship sealed engine run (`base-dc`) plus a raw-memory
     cross-corroboration run (`notch`), the examiner-facing narrative report, technical appendix, and
     Wazuh IOC gallery.
   - **SRL-2015** (`docs/12-CASES-REPORTS/srl-2015-report/`) — "Stark Research Labs 2015" SANS APT
     enterprise case (`SRL-2015-APT-ENTERPRISE`). The most data-rich case folder: per-host pipeline
     finding sets (8 disk/memory runs), IOC + entity-attribute-relationship (EAR) exports, a STIX 2.x
     bundle, a threat-intel enrichment report, a reverse-engineering deep-analysis dataset (YARA rule,
     disassembly, strings, deep findings), a quarantine hash manifest, Wazuh push receipts, and sealed
     engine payloads/reports.
   - **VANKO** (`docs/12-CASES-REPORTS/vanko-report/`) — "Abducted Zebrafish" *insider* IP-theft
     (explicitly **not** a malware intrusion). Ships the sealed findings ledger (`FINDINGS.jsonl` /
     `confirmed-findings.json`, 10 confirmed of 19), case-init/evidence-register tool arguments, the
     OST mailbox carve datasets (fictional FOR500 persona), and a presentation storyboard.

2. **Public / reference datasets and fixtures** — committed under `docs/03-data/`:
   recall ground-truth fixtures (`ground_truth_*.yaml`) and the FULL-CASE recall run summary that
   anchor the 72/72 disk and 108/118 memory recall numbers; a network-evidence verified-inventory /
   claims-reconciliation dataset; and `docs/07-sdlc-ops/assets/sample-sealed-run/` (a committed
   sealed-trace exemplar).

3. **MCP ingestion schemas & signature data** — the engine's canonical JSON Schemas
   (`master_iocs.schema.json`, `report.schema.json`), the committed YARA signature dataset
   (Cobalt Strike family rules + the SRL-2015 mem-inject rule), the Wazuh/OpenSearch saved-objects
   dashboard import (`agentropix-findings.ndjson`), and the Wazuh tag schema — the contracts that
   every case dataset above is validated and indexed against.

**Domain.** All cases are staged DFIR teaching scenarios over Windows estates (domain controllers,
workstations, mail/file servers) sourced from / modelled on the SANS DFIR challenge corpus. Evidence
images live outside the repo under `/cases/<CASE>/…` (E01 disk images and raw memory images); the
portal publishes the *derived, sealed* outputs — findings, traces, audit logs, IOCs, and reports —
plus the verification material to re-check their integrity.

---

## 2. Evidence Inventory & Provenance

SHA-256 values are file digests computed with `sha256sum` over the tracked file (not the secret/key
value, where the file is a key). Large prose/markdown and MP4/binary media are listed by reference
("compute on demand" / "by reference"). Withheld-malware rows carry the **quarantine manifest /
in-report** hash with bytes intentionally absent from the repo.

### 2.1 SRL-2018 case (`docs/12-CASES-REPORTS/srl-2018-report/`)

| Asset Name | File Path | Format | Hash / Checksum | Collection Source / Provenance |
|---|---|---|---|---|
| base-dc sealed engine report (flagship) | `submission/base-dc-report.json` | JSON object, 165,955 B | `1005ae083dadb3bf760dd227c37fa09495b2b93ffeb21270c2369979127ab882` | Real agentropix-sift engine run (v0.2.0-dev) 2026-06-11 14:22→15:56 UTC over `/cases/SRL-2018/base-dc-cdrive.E01`; Trinity Reflexion-lite loop, 13-agent swarm, 5 iterations; `inference_constraint=high`; HMAC-sealed; copied verbatim from `agentropix-sift/submission/`. |
| base-dc sealed audit-log companion | `submission/base-dc-report.audit-log.json` | JSON object, 32,802 B | `ca981d6e71a2fbefffea37b3b74c3c109cb87ba2e23bef1300d9e265f477964d` | Sealed audit-log for the base-dc run from live Thymus trail `/tmp/thymus-audit-basedc.jsonl`; `audit_log_seal` cross-binds the report; 146 entries. |
| base-dc Thymus access trail | `submission/base-dc-thymus-audit.jsonl` | JSONL, 146 lines, 27,439 B | `c574345e0cacfd8be880392787a1a63c52e0e42b49ba84682ef4278894a03810` | Engine's own live read-only-boundary trail, one JSON line per evidence-path access decision; the inline `thymus_audit` (145) and the sealed audit-log (146) derive from it. |
| base-dc live engine console log | `submission/base-dc-run.log` | plain text, 13,936 B | `1f7461b609e5b9e495f0d847786cdc1fe8884fa561613b90e256ecf715395f84` | Live stdout/stderr of the base-dc run (agent starts, tool durations, wrapper timeouts, Thymus REJECTs, Critic verdicts). |
| base-dc HMAC session-key | `submission/base-dc-report.session-key` | binary, raw 32 B (mode 0600 at origin) | `cfc72b6bd59b735a565515f5a06c3e48ffd31e5fa08e1a6fad5eb3b0411d44bb` (file digest, **not** key value) | Per-run 32-byte HMAC key that produced the base-dc seals; published under the standing burned-key policy; key bytes never printed. |
| notch sealed engine report | `submission/notch-report.json` | JSON object, 42,295 B | `8a69f39b90213a4b851418af1cd7ca99daf13bdb911a817333bc7e8d61d14178` | Second engine run (same v0.2.0-dev, same 13-agent roster) 2026-06-11 12:42→12:44 UTC over `/cases/Challenge_NotchItUp/Challenge.raw` (raw memory) as determinism cross-corroboration. NOT an SRL-2018 image. |
| notch sealed audit-log companion | `submission/notch-report.audit-log.json` | JSON object, 4,937 B | `e79c74704382fc055ef33146bd92c05859d3e9a4f6032c8d17c967f5fb251a42` | Sealed audit-log for notch; cross-bound via `audit_log_seal`; 26 entries. |
| notch Thymus access trail | `submission/notch-thymus-audit.jsonl` | JSONL, 26 lines, 3,776 B | `59477a79e2a1307f14ba73d0d5378dcd0b3ca59b82aadda987fb25cf62eb0aa0` | Live Thymus boundary trail for the notch run. |
| notch live engine console log | `submission/notch-run.log` | plain text, 1,380 B | `cce8e165d25232b94e6a8edcfc349c7b5beeababb13c2fd7bdd34b7dd7e6bfea` | notch run console stream; shows `evtx_dump` deserialize failures on raw memory + final summary. |
| notch HMAC session-key | `submission/notch-report.session-key` | binary, raw 32 B (mode 0600 at origin) | `2117fd1529a3bdcf68fc9f8d1422f9930a20ffbcc4ddd7b377710c229e43b5a4` (file digest) | Per-run HMAC key that sealed the notch report/audit-log; burned-key policy. |
| SRL-2018 forensic report (narrative) | `SRL-2018-FORENSIC-REPORT.md` | Markdown + PNG diagram refs + hash tables | withheld — large prose (compute on demand) | Examiner-facing narrative for case `SRL-2018-COMPROMISED-ENTERPRISE` (examiner `victor.galvan`); 10 findings APPROVED (examiner-signed HMAC chain). Publishes 9 recovered-malware SHA-256 (bytes out of repo). |
| SRL-2018 technical appendix | `TECHNICAL-APPENDIX.md` | Markdown | withheld — prose (on demand) | Supporting evidentiary detail (netscan/malfind/evtx depth) grounded in the SRL-2018 sealed findings. |
| Wazuh IOC gallery (SRL-2018) | `WAZUH-IOC-GALLERY.md` (+ `wazuh/*.png`) | Markdown + 13 PNG dashboard captures | withheld — prose (on demand) | Maps confirmed findings/IOCs to their Wazuh SIEM surfacing (10 finding rules + CDB IOC lists). |
| **Recovered malware (SRL-2018)** | bytes WITHHELD (quarantine, gitignored) | — | 9 in-report SHA-256 (see §3.1) | Hashes published in `SRL-2018-FORENSIC-REPORT.md`; sample bytes kept out of the repo by design. |

### 2.2 SRL-2015 case (`docs/12-CASES-REPORTS/srl-2015-report/`)

| Asset Name | File Path | Format | Hash / Checksum | Collection Source / Provenance |
|---|---|---|---|---|
| Quarantine hash manifest | `quarantine/MANIFEST.csv` | CSV, 22 rows + header, 7 columns | `a00ef77360fe2b3ce6fcb536cce1e76904b82fe10c3337c8df46ca15cb673c0c` | Withheld-malware quarantine manifest: per-carved-sample `expected_hash` vs `carved_sha256` verification table (bytes correctly NOT in repo). |
| Per-host pipeline findings — controller (disk) | `pipeline-findings/win2008R2-controller.disk.json` | JSON (report schema), 196 findings | `1cecf7e5cda…` → `1cecf7e5e4d91207e88143182a7234d02ff9f6ec8f60b27ff054ac9f6a0799b6` | Engine pipeline run over the win2008R2 controller C-drive E01. |
| Per-host pipeline findings — controller (memory) | `pipeline-findings/win2008R2-controller.memory.json` | JSON (report schema), 512 findings | `ce3f57c84297e48df2a63ebfe73474c5b7f70274163368c789894754e4c63260` | Engine run over the controller memory image. |
| Per-host pipeline findings — nromanoff (disk) | `pipeline-findings/win7-32-nromanoff.disk.json` | JSON, 250 findings | `86250ae8d920b4f482b0eb4988a1146db7a53a3cb0344ce02c36b1fc1b7655ed` | Win7-32 nromanoff disk run. |
| Per-host pipeline findings — nromanoff (memory) | `pipeline-findings/win7-32-nromanoff.memory.json` | JSON, 10 findings | `dc255642c517b522f215ae682d18fb5cc2ce24059f27ed9054835b868719097f` | Win7-32 nromanoff memory run. |
| Per-host pipeline findings — nfury (disk) | `pipeline-findings/win7-64-nfury.disk.json` | JSON, 484 findings; `evidence_image_sha256=a5df0b38ec699656e8c9925ffa515945288aaa32cd29c284fb519cf06d1589c7` | `0a776f9a1f7ae458a1c93e07e4f8ec42aff0833e0a7711c06ad6c407a7cdac12` | Win7-64 nfury C-drive `/cases/SRL-2015/win7-64-nfury-c-drive/…E01`. |
| Per-host pipeline findings — nfury (memory) | `pipeline-findings/win7-64-nfury.memory.json` | JSON, 432 findings | `5db831d599742568a3492b3ddbf9c5be73407b41a43c8182adce5bfe06640095` | Win7-64 nfury memory run. |
| Per-host pipeline findings — tdungan (disk) | `pipeline-findings/xp-tdungan.disk.json` | JSON, 339 findings | `0d140cb1ca30237fccff089f9f47dca465f68909cc98e4d6818813f3be8410d7` | WinXP tdungan disk run. |
| Per-host pipeline findings — tdungan (memory) | `pipeline-findings/xp-tdungan.memory.json` | JSON, 10 findings | `f1045eccab77f0c9393b7c0f81d6112001463dda4395109e08efd1454fc06c6d` | WinXP tdungan memory run. |
| IOC export (JSON) | `exports/iocs.json` | JSON object, 91 IOCs | `56b01190c6b5ef89b65d1d1781acbce164533a3b99062ba3601f66f101f0439f` | Enriched IOC corpus for `SRL-2015-APT-ENTERPRISE`; tally `{malicious:12, clean:37, unknown:42, suspicious:0}`. |
| IOC export (CSV) | `exports/iocs.csv` | CSV | by reference (text) | Flat-file twin of `iocs.json`. |
| IOC export (STIX bundle) | `exports/iocs-stix.json` | STIX 2.x `bundle`, 92 objects | `51a1d046b96a6fecdeb8e71a3fd2d656285e418b662a057a42fe496f48b4be72` | STIX bundle of `indicator` + `identity` objects derived from the IOC corpus. |
| Entity-Attribute-Relationship export (JSON) | `exports/ear.json` | JSON object, 17 executables / 1 suspect | `b06a917e7968a708db88e70bbe02f69d2b959a4f250f568aedd93e2470e8b57c` | Executable EAR derivation (path/name/host/sha256/signer/verdict/suspect). |
| Entity-Attribute-Relationship export (CSV) | `exports/ear.csv` | CSV | by reference (text) | Flat-file twin of `ear.json`. |
| Threat-intel enrichment report | `enrichment/ti-report.json` | JSON object | `8d69acf5590304d26937e88a1b8f8ab927e250f104c1c5a47feae530eb683c98` | VirusTotal + OTX enrichment (egress operator-authorized); tally selected=40 / enriched_ok=39 / malicious=8. |
| Deep-RE findings dataset | `deep-analysis/deep-findings.json` | JSON object, 10 findings | `71d65b4291a624caaf66f2756fb4e1e0aa353b28a02b9f75085daca7a46382c7` | Manual `manual.deep_re` reverse-engineering findings for the SRL-2015 mem-inject family. |
| SRL-2015 mem-inject YARA rule | `deep-analysis/srl2015_meminject.yar` | YARA source (`rule SRL2015_MemInject_VB_Family`) | `dc92259894a8c7db721dbafdfd5952693e9ba24bc12084d836f18c8d656f376e` | Hand-authored detection rule for the recovered VB injector family. |
| Disassembly — variant A | `deep-analysis/disasm-variantA.txt` | text | by reference (text) | Disassembly listing of a recovered variant (RE artifact). |
| Disassembly — variant B | `deep-analysis/disasm-variantB.txt` | text | by reference (text) | Disassembly listing of a second variant. |
| Strings dump | `deep-analysis/strings-all.txt` | text | by reference (text) | Extracted strings across the recovered samples. |
| IOC config summary | `deep-analysis/ioc-config-summary.txt` | text | by reference (text) | Decoded C2/config summary from the RE pass. |
| Sealed engine payload — exec tier | `exec_payload.json` | JSON-RPC envelope (`jsonrpc/id/result`) | `3c1f5b59b844a217984ddaba803233ad298bfe9d27e477b777479ebfae483f28` | Raw MCP `report_generate` JSON-RPC payload (executive profile). |
| Sealed engine report — exec tier | `exec_report.json` | JSON (report-snapshot schema) | `2d825f5a38f219c79569e529343f344e519e0f3800503b9dd020cba97c35a3c3` | Unwrapped executive-profile report snapshot. |
| Sealed engine payload — full tier | `full_payload.json` | JSON-RPC envelope | `c8e96834e92d2c1f7ed8fff309df01eb10db9752b623ca671017fe7e960fa333` | Raw MCP payload (full profile). |
| Sealed engine report — full tier | `full_report.json` | JSON (report-snapshot schema), 17 approved findings | `c4693ade55cfe3362d4bd268e313245817455f68a6cfad16e118fd2bf112aea1` | Full-profile report snapshot; sections `[executive_summary, findings, timeline, iocs]`. |
| Wazuh push receipt — dry-run index | `wazuh-push-receipts/dryrun_index.json` | JSON | `57da574daca8750342a575d877f9ce4e4ead93e7b8a4f4fdff5c3233be6ca5e0` | `wazuh_index_findings` dry-run receipt. |
| Wazuh push receipt — live index | `wazuh-push-receipts/live_index.json` | JSON-RPC result envelope | `ab54d6ba009d369c1c5f45d1be497e735c4ab68097ade1d290fa1660323997f6` | Live-index attempt receipt. |
| Wazuh pipeline summary | `wazuh-push-receipts/pipeline_summary.json` | JSON | `21dddb7be6a9cf0f15952489518a88543d4a38792b3b353e423999ebf8428dca` | Aggregation + index summary (intermediate). |
| Wazuh pipeline summary (FINAL) | `wazuh-push-receipts/pipeline_summary_FINAL.json` | JSON | `b1da39250d526b1099ffd729b8b244544a4b4be684cc0e93792aadc52ed19b19` | Final pipeline summary: 2233 total findings aggregated across 8 reports; dry-run OK, live blocked by evidence gate. |
| **Recovered malware (SRL-2015)** | bytes WITHHELD (`quarantine/`, gitignored) | — | per-sample `expected_hash`/`carved_sha256` in `MANIFEST.csv` (e.g. controller `usboesrv.exe` `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec`; nromanoff `a.exe` `598e53b69c71643db559c197db757363c48a30bb26b6486db2153bd417701dec`) | Carved samples whose bytes are kept out of the repo; manifest publishes the verification hashes only. |

### 2.3 VANKO case (`docs/12-CASES-REPORTS/vanko-report/`)

| Asset Name | File Path | Format | Hash / Checksum | Collection Source / Provenance |
|---|---|---|---|---|
| Sealed findings ledger (full) | `FINDINGS.jsonl` | JSONL, 19 lines | `3c836d20231ba86c4dce373fe77756dc4974bfdd807f7f24fd328e294847d047` | All 19 hypotheses for the "Abducted Zebrafish" insider IP-theft (10 confirmed, 9 refuted by the FP gate). |
| Confirmed findings | `confirmed-findings.json` | JSON array, 10 objects | `def19fea447695f3de282caa3f812fe385662b346e801150e4034f2f9cbebfb9` | The 10 confirmed findings (subset of `FINDINGS.jsonl`) that survived disconfirming checks. |
| Case-init tool arguments | `args_case_init.json` | JSON | by reference (text) | Captured `case_init` MCP-call arguments for the VANKO run. |
| Evidence-register tool arguments | `args_evidence_register.json` | JSON | by reference (text) | Captured `evidence_register` MCP-call arguments. |
| Presentation storyboard | `findings-presentation-storyboard.json` | JSON | by reference (text) | Storyboard emitted by the Opus 4.8 `findings_presentation_workflow.js` (key facts + cross-source correlations). |
| OST mailbox carve — icloud persona | `ost-results/anthony.vanko@icloud.com.ost.carve.json` | JSON object | by reference (text) | Fictional FOR500 persona mailbox carve (`tool/source_pst/messages/iocs/ioc_index/summary/warnings`). |
| OST mailbox carve — gmail persona | `ost-results/anthony.vanko@gmail.com (1).ost.carve.json` | JSON object | by reference (text) | Second persona mailbox carve. |
| OST extra-extract record | `ost-results/_extra_extract.json` | JSON | by reference (text) | Supplemental carve/extract metadata. |

### 2.4 Reference datasets & fixtures (`docs/03-data/`, `docs/07-sdlc-ops/`)

| Asset Name | File Path | Format | Hash / Checksum | Collection Source / Provenance |
|---|---|---|---|---|
| Recall ground-truth — DC | `docs/03-data/recall-ground-truth/ground_truth_dc.yaml` | YAML | `9290a5e91d0a71659099e2f3b2a1d8ec00adf94fc73a1a8abe003e85c1c0ae9f` | Expected MITRE tactics for `base-dc-cdrive.E01` (case `SANS-APT-DC-2018`); feeds Critic gaps + `test_e2e_dc_recall.py`. |
| Recall ground-truth — file C-drive | `docs/03-data/recall-ground-truth/ground_truth_base-file-cdrive.yaml` | YAML | `731b3d52cda8877fec5f3bf1a1cd17110b84875698c611c14f2acca47715fc12` | Expected-tactics fixture for the base file-server C-drive. |
| Recall ground-truth — mail memory | `docs/03-data/recall-ground-truth/ground_truth_base-mail-memory.yaml` | YAML | `bfa44a3f28ea4b6b7cf935623ff877fdfef034eefc21726efc9d19711c9e4eb5` | Expected-tactics fixture for the mail-server memory image. |
| Recall ground-truth — wkstn-06 memory | `docs/03-data/recall-ground-truth/ground_truth_base-wkstn-06-memory.yaml` | YAML | `5e6083d80d96098bed922e6dc509b91223598b6adbb92a4a3be1eb756169c2f0` | Expected-tactics fixture for workstation-06 memory. |
| FULL-CASE recall run summary | `docs/03-data/recall-ground-truth/run-summary-FULL-CASE-20260505T004738Z.md` | Markdown | by reference (prose) | The recall run summary anchoring 72/72 disk + 108/118 memory recall (canonical-facts source `FULL-CASE-20260505T004738Z`). |
| Network-evidence verified inventory | `docs/03-data/network-evidence-verification/verified-inventory.md` | Markdown | by reference (prose) | Verified network-evidence inventory (distinct from data-dictionary/schema). |
| Network-evidence claims reconciliation | `docs/03-data/network-evidence-verification/claims-reconciliation.md` | Markdown | by reference (prose) | Reconciles documented claims against the raw verification capture. |
| Network-evidence raw verification capture | `docs/03-data/network-evidence-verification/raw-verification-capture.md` | Markdown | by reference (prose) | Raw capture transcript underpinning the inventory. |
| Sample sealed-run trace (report) | `docs/07-sdlc-ops/assets/sample-sealed-run/report.json` | JSON (report schema) | `0855dc327e65ac744602900ac4c2fe65e6d6d16998c4a2b3977240fee148dd53` | Committed sealed-trace exemplar (report-schema instance) for observability/integrity docs. |
| Sample sealed-run trace (audit-log) | `docs/07-sdlc-ops/assets/sample-sealed-run/report.audit-log.json` | JSON | by reference | Audit-log companion to the sample sealed run. |

### 2.5 MCP schemas & signature data (`agentropix_mcp/src/agentropix_mcp/`)

| Asset Name | File Path | Format | Hash / Checksum | Collection Source / Provenance |
|---|---|---|---|---|
| Master-IOCs JSON Schema | `schema/master_iocs.schema.json` | JSON Schema (`MASTER-IOCS.json schema (additive v2)`) | `71b5281ea231ee738d76a8cf9da95c1ba8650a7737b9816e545d00b21c09234f` | Canonical contract for the consolidated IOC corpus (`schema_version/case_id/generated_at_utc/generator_id/corpus_root_id/iocs/...`). |
| Triage-report JSON Schema | `schema/report.schema.json` | JSON Schema (`Agentropix-SIFT Triage Report`) | `eb3d7715697bd272bdfe0db34527a473b88749db414a00198a38a8a8259ababc` | Canonical contract every sealed engine report validates against (version/image/findings/trace/thymus_audit/seals/...). |
| YARA — CS artifacts | `detectors/yara_rules/cobalt_strike/cobalt_strike_artifacts.yar` | YARA (`CS_Auxiliary_NamedPipe`, `CS_PostEx_Toolkit`, `CS_Beaconing_Sleep_Mask`) | `27a0fad1e698fad80087629d9e7f4e1d022e4c237128fa0340d60654980d36cd` | Committed Cobalt Strike artifact signatures driving the malware detectors. |
| YARA — CS beacon gen3 | `detectors/yara_rules/cobalt_strike/cobalt_strike_beacon_gen3.yar` | YARA (`CS_Beacon_Gen3_XOR_Config`, `CS_Beacon_Gen3_Stager_RUNDLL32`) | `936a129024f55b3b3fa60dc5c25ff9de0f8bc3cc782f1cec196fb182f9cd201b` | Gen-3 beacon signatures. |
| YARA — CS beacon gen4 | `detectors/yara_rules/cobalt_strike/cobalt_strike_beacon_gen4.yar` | YARA (`CS_Beacon_Gen4_AES_HTTPS`, `CS_Beacon_Gen4_HTTP_Profile`) | `6e6305995db4fb46979015b1e4662f35edccda2f7f01279a50ce9c97e6560fb8` | Gen-4 beacon signatures. |
| YARA — CS loader | `detectors/yara_rules/cobalt_strike/cobalt_strike_loader.yar` | YARA (`CS_Loader_ReflectivePE`, `CS_Loader_PowerShell_Stager`) | `856efabaf41f0cdafac26215e72409df5d53d92c6793843cb4a3f4df576b8e84` | Reflective-PE / PS-stager loader signatures. |
| Wazuh dashboard import | `wazuh/dashboards/agentropix-findings.ndjson` | NDJSON (OpenSearch saved-objects) | `e313aa2c86b3da6469490e8e4e08e383456a108b06c89466d69b5a7f5d2eaa83` | Wazuh/OpenSearch dashboard + index-pattern saved-objects import for the `agentropix-findings` index. |
| Wazuh tag schema | `wazuh/tag_schema.py` | Python (tag taxonomy) | by reference (source) | Tag taxonomy applied to indexed findings. |

---

## 3. Data Dictionary & Artifact Schemas

### 3.1 Sealed engine report (`report.schema.json` — used by `base-dc-report.json`, `notch-report.json`, SRL-2015 `pipeline-findings/*.json`, `sample-sealed-run/report.json`)

Description: the engine's terminal triage artifact for one evidence image, produced by the Trinity
Reflexion-lite loop and HMAC-sealed. One JSON object per run.

Fields/Keys:
- `version`: str — engine version (e.g. `"0.2.0-dev"`).
- `image`: str — evidence image path (`/cases/SRL-2018/base-dc-cdrive.E01`, `/cases/Challenge_NotchItUp/Challenge.raw`, `/cases/SRL-2015/win7-64-nfury-c-drive/…E01`).
- `max_iterations`: int — Reflexion budget (5).
- `iterations_completed`: int — iterations run (5).
- `status`: str — terminal state (`"budget_exhausted"`).
- `findings`: list[obj] — each `{_source, confidence:float, description, evidence, timestamp:ISO8601+TZ, mitre_attack:str, related_findings:list, agent}`. base-dc=22, notch=10; SRL-2015 per-host 10–512 (FINAL aggregate 2233).
- `trace`: obj — `{tool_calls:list of {tool, timestamp, duration_ms:float, result_summary}; counters (timeline.counters: jsonl_rows_read, priority_hits_by_family{4624,winreg_run,mft_timestomp,lolbin}, detectors_fired_by_id{…}); start_time; end_time; total_duration_ms:float}`. base-dc `tool_calls`=176, total≈5,642,464 ms; notch `tool_calls`=60.
- `thymus_audit`: list[obj] — inline copy of access decisions `{timestamp, action(ALLOW/REJECT), path, reason}` (base-dc 145).
- `critic_score`: float — coverage-guard score (base-dc 1.0).
- `critic_feedback`: str — Critic verdict text.
- `iterations`: list[obj] — per-iteration `{iteration:int, plan:list[agent names], stable_agents:list, dropped_agents:list, gaps:list, critic_score, critic_feedback, should_halt:bool}`.
- `inference_constraint`: str — `"high"` (LLM is Layer-1 orchestrator only; facts come from deterministic MCP tool calls).
- `evidence_image_sha256`: str — SHA-256 binding the evidence image (base-dc `e2b9cf0cb6759fd079f45fa903d80bde602160ff969c969c6f0cd704965b31b1`; notch `80366d7ec64a5529c95c2f523f4281a5f11efbad33ecb19f73525470c1407b23`; nfury-disk `a5df0b38ec699656e8c9925ffa515945288aaa32cd29c284fb519cf06d1589c7`).
- `report_seal`: str — 64-hex HMAC of the report (base-dc `151c9e888210db8287bb69833f58d8e77ca15d55e98883d0a4b19826e453b8c1`; notch `f5e525a0d50451ec3ecf6e66c508dc02073f6dc1b1c10d468a48ac90d1bbb04c`).
- `completion_proofs`: list[str] — proof tokens (base-dc 10: ARTIFACTS_PARSED, CROSS_AGENT_CORRELATION_DONE, FILESYSTEM_WALKED, INJECTION_DETECTION_COMPLETE, NULL_SESSION_BASELINE_COMPLETE, T1059_001_IEX_LOOPBACK_SCAN_COMPLETE, T1071_001_SVCHOST_OUTBOUND_HTTP_COMPLETE, T1546_008_ACCESSIBILITY_IFEO_HIJACK_COMPLETE, TIMELINE_GENERATED, YARA_HUNT_COMPLETE; notch 8 — no ARTIFACTS_PARSED/TIMELINE_GENERATED since disk-only proofs are absent on raw memory).
- `audit_log_seal`: str — 64-hex HMAC cross-binding the audit-log companion (base-dc `1085b493329c06080e0d3552e54b4432edcf5ba007e17054ae8b18743e6b5927`).

### 3.2 Sealed audit-log companion (`*-report.audit-log.json`)

Description: the sealed, tamper-evident copy of the run's Thymus access trail.

Fields/Keys:
- `metadata`: obj — `{audit_log_enabled:bool, entry_count:int (base-dc 146, notch 26), audit_log_source_path:str (/tmp/thymus-audit-basedc.jsonl)}`.
- `audit_entries`: list[obj] — `{timestamp:ISO8601+TZ, action:str(ALLOW/REJECT), path:str, reason:str}`.
- `audit_log_seal`: str — 64-hex HMAC equal to the parent report's `audit_log_seal` (cross-binding).

### 3.3 Thymus access trail (`*-thymus-audit.jsonl`)

Description: the live read-only-boundary trail, one JSON line per evidence-path access decision.

Fields/Keys (per line):
- `timestamp`: str — ISO8601+TZ of the decision.
- `action`: str — `ALLOW` or `REJECT` (base-dc inline 145-entry copy = 84 ALLOW / 61 REJECT).
- `path`: str — evidence or temp path evaluated.
- `reason`: str — e.g. `"within read-only zone"` / `"REJECT_OUTSIDE_ALLOWLIST: … not under any allowed prefix"`.

### 3.4 Quarantine manifest (`srl-2015-report/quarantine/MANIFEST.csv`)

Description: withheld-malware verification table — proves each carved sample matched its expected hash.
Columns (7): `in_zip_name`, `original_path`, `host`, `expected_hash` (SHA-256), `carved_sha256` (SHA-256), `verified` (Y/N), `size_bytes`. 22 rows; e.g. `controller usboesrv.exe` expected==carved `5420d06d802ce015301578347c529405f7015a59a47097af26616a8ab57b39ec` (Y, 571392 B). **Sample bytes are not in the repo.**

### 3.5 IOC export (`srl-2015-report/exports/iocs.json`)

Description: enriched IOC corpus for `SRL-2015-APT-ENTERPRISE`.
- `case_id`, `generated_at`, `source_ti_report`, `source_es_index`: str.
- `ioc_count`: int (91).
- `tally`: obj — `{malicious:12, clean:37, unknown:42, suspicious:0}`.
- `iocs`: list[obj] — each `{ioc, ioc_type, verdict, vt_malicious:int, vt_total:int, otx_pulses:int, providers:list, first_host, source, checked_at}`.

### 3.6 STIX bundle (`srl-2015-report/exports/iocs-stix.json`)

Description: STIX 2.x export of the IOC corpus.
- `type`: str (`"bundle"`); `id`: str (bundle id).
- `objects`: list[obj] (92) — `indicator` + `identity` SDOs (standard STIX fields per object type).

### 3.7 Entity-Attribute-Relationship export (`srl-2015-report/exports/ear.json`)

Description: executable EAR derivation across hosts.
- `case_id`, `generated_at`, `derivation`: str.
- `ear_count`: int (17); `suspect_count`: int (1).
- `executables`: list[obj] — `{path, name, host, sha256, signer, signed:bool, verdict, suspect:bool, all_names:list, all_paths:list}`.

### 3.8 Threat-intel enrichment report (`srl-2015-report/enrichment/ti-report.json`)

Description: VT/OTX enrichment output (egress operator-authorized).
- `case_id`, `generated_at`, `run_id`, `tool`: str.
- `providers`: list (`["virustotal","otx"]`); `providers_ok`: list; `egress_authorized`: bool (true).
- `sources`, `selection_policy`, `exclusions`: enrichment policy fields.
- `tally`: obj — `{selected_for_enrichment:40, enriched_ok:39, errors:1, malicious:8, suspicious:0, clean:22, unknown:9, dropped_for_cap:38}`.
- `dropped_for_cap`, `sample`, `iocs`, `enrich_remaining_run`, `tally_full`: enrichment-detail fields.

### 3.9 Deep-RE findings (`srl-2015-report/deep-analysis/deep-findings.json`)

Description: manual reverse-engineering findings for the recovered injector family.
- `case_id`, `source_run_id`, `agent` (`"deep-analysis"`), `detector_source` (`"manual.deep_re"`), `generated`, `methodology`: top-level metadata.
- `findings`: list[obj] (10) — `{finding_id, case_id, host, agent, confidence, description, mitre_attack, detector_source, evidence, event_time, source_run_id}`.

### 3.10 VANKO findings (`FINDINGS.jsonl` / `confirmed-findings.json`)

Description: the insider-IP-theft hypothesis ledger; `FINDINGS.jsonl` holds all 19, `confirmed-findings.json` the 10 that passed disconfirming checks.
Fields/Keys (per object/line):
- `finding_id`: str.
- `phase`: str — investigation phase.
- `technique`: str — MITRE technique id.
- `title`: str.
- `status`: str — confirmed / refuted.
- `confidence`: float/str.
- `evidence`: obj/list — cross-source artifacts.
- `disconfirming_checked`: bool — whether the false-positive gate ran.
- `disconfirming_notes`: str — why a hypothesis was confirmed or refuted (honest negatives).

### 3.11 Report-snapshot artifacts (`srl-2015-report/{exec,full}_report.json`, `{exec,full}_payload.json`)

Description: `*_payload.json` is the raw MCP `report_generate` JSON-RPC envelope (`jsonrpc`, `id`,
`result`); `*_report.json` is the unwrapped report snapshot.
Snapshot fields: `case_id`, `profile` (`exec`/`full`), `report_id`, `snapshot_at`,
`approved_finding_count` (full=17), `sections` (`[executive_summary, findings, timeline, iocs]`),
`truncated`, `result_bytes`, `error`, `warning`.

### 3.12 Wazuh pipeline summary (`srl-2015-report/wazuh-push-receipts/pipeline_summary_FINAL.json`)

Description: the aggregation + indexing receipt across all per-host runs.
- `case_id`: str (`SRL-2015-APT-ENTERPRISE`).
- `aggregation`: obj — `{total_findings:2233, per_report:{<host>/<disk|memory>:int…}, collisions_prehandled:["_source->detector_source","timestamp->event_time(text)"]}`.
- `findings_index`: obj — `{dry_run_ok:true, dry_run_outcome:"dry_run", dry_run_findings:2233, live_indexed:0, live_blocked:true, block_reason:"wazuh_index_findings/bulk_… (evidence gate)"}`.
- `iocs`, `ledger`: obj — IOC-push and decision-ledger references.
(`dryrun_index.json` / `live_index.json` are the corresponding per-step receipts; `live_index.json`
is a JSON-RPC `result` envelope.)

### 3.13 MCP schemas (`schema/master_iocs.schema.json`, `schema/report.schema.json`)

- **`master_iocs.schema.json`** (`title: "MASTER-IOCS.json schema (additive v2)"`) — properties:
  `schema_version`, `case_id`, `generated_at_utc`, `generator_id`, `corpus_root_id`, `iocs`,
  `process_tree_findings_skipped`.
- **`report.schema.json`** (`title: "Agentropix-SIFT Triage Report"`) — properties mirror §3.1:
  `version`, `image`, `max_iterations`, `iterations_completed`, `status`, `inference_constraint`,
  `evidence_image_sha256`, `report_seal`, `completion_proofs`, `findings`, `trace`, `thymus_audit`,
  `critic_score`, `critic_feedback`, `iterations`.

### 3.14 Recall ground-truth fixtures (`docs/03-data/recall-ground-truth/ground_truth_*.yaml`)

Description: per-image expected-tactics fixtures that feed `Critic.gaps` and the recall e2e tests.
Fields/Keys:
- `case_id`: str (e.g. `"SANS-APT-DC-2018"`).
- `image`: str (e.g. `"base-dc-cdrive.E01"`).
- `filesystem`: str (e.g. `"ntfs"`).
- `description`: str — scenario summary.
- `expected_tactics`: list[str] — MITRE technique ids the Trinity loop must cover (e.g. `T1105`,
  `T1547.001`, `T1053.005`, `T1003.002`, `T1055`, `T1078`). Any id NOT confirmed by the swarm appears
  in `Critic.gaps`.

### 3.15 SRL-2018 recovered-malware hashes (in `SRL-2018-FORENSIC-REPORT.md`)

Nine recovered-malware SHA-256 are published in-report; **bytes are withheld** (gitignored
quarantine):
`027fef173a71142cf1616e32290b9c52cbb425bfdeac1babd2a57e260c27c70e`,
`0a040d6f452063f5bef500972f83429f3654ada88eff13c2883e8eb06b519e05`,
`27d4968716a095a15956f1fb9e247b32dd7765b2e67149e17469908750280568`,
`42477dd9317c739043d4516e04221743e00b737d1234f914a0e7608202758972`,
`7fa4f6cc4e1bb27da7d9af7a2a533e72751b025b063e1df4359ebe127fd2892c`,
`b3a70d388488c34dd5c767692eccc9effed36b8e7c1ee03ace1bd27123a2e6d6`,
`d391ede758b6c769f89addb35ee9ec74eb0ae3a23831dbd6f7d932851265eee7`,
`e722dd429510c83485bb276c559015df9bd4931e7e4339eb90683cc3efd9beaa`,
`ebb75bbae3e1298cecbed3c5b1b0ca0a2a8d4d17836f672546218bc47da8dc03`.

---

## 4. Ingestion & Transformation Pipeline

Pipeline order: **acquire → examine → enrich → quarantine → deep-RE → report → SIEM.** Each stage is
deterministic where it matters (facts come from MCP tool calls, not model inference —
`inference_constraint=high`).

1. **Acquire (case intake & evidence binding).** `case_init` (see `vanko-report/args_case_init.json`)
   opens the case; `evidence_register` (`args_evidence_register.json`) registers each image and binds
   `evidence_image_sha256`. Images stay under the read-only `/cases/<CASE>/…` zone.

2. **Examine (the Trinity loop + 7/13-agent swarm).** The **Trinity Reflexion-lite loop** runs the
   swarm under a coverage-guard **Critic** for up to 5 iterations (`status: budget_exhausted`). The
   swarm dispatches forensic-wrapper MCP tools — among them `get_pslist`/`run_volatility` plugins,
   `fls`, `evtx_dump`, `log2timeline`(plaso), `srum_extract`, the YARA hunt (`yara_hunt`), the
   injection detector, null-session baseline, and the technique-specific agents
   (`t1059_001_iex_loopback_c2`, `t1071_001_svchost_outbound_http`,
   `t1546_008_accessibility_ifeo_hijack`, artifact, filesystem, hunt, memory, timeline). Every
   evidence-path access is gated by **Thymus** (read-only allowlist) and streamed to the live
   `*-thymus-audit.jsonl` trail. Each per-host run emits a report-schema artifact
   (`pipeline-findings/<host>.<disk|memory>.json`).

3. **Enrich (threat intel).** `threat_intel_lookup` queries VirusTotal + OTX (egress
   operator-authorized) and writes `enrichment/ti-report.json`; the consolidated, verdict-tagged IOC
   corpus is exported to `exports/iocs.json` / `iocs.csv` and the STIX bundle `iocs-stix.json`, and
   executables to the EAR export `exports/ear.json` / `ear.csv` (built by `exports/_build_exports.py`
   / `build_exports.py`). IOC exports validate against `schema/master_iocs.schema.json`.

4. **Quarantine (sample carving & verification).** Carved suspect binaries are written to a
   gitignored quarantine and recorded in `quarantine/MANIFEST.csv` with `expected_hash` vs
   `carved_sha256` and a `verified` (Y/N) flag — the **expected == carved** check is the integrity
   gate. Bytes never enter the repo.

5. **Deep-RE (reverse engineering).** The recovered family is disassembled
   (`deep-analysis/disasm-variant{A,B}.txt`), strings-dumped (`strings-all.txt`), config-decoded
   (`ioc-config-summary.txt`), turned into a detection rule (`srl2015_meminject.yar`, alongside the
   committed Cobalt Strike YARA family), and the conclusions recorded in
   `deep-analysis/deep-findings.json` (`detector_source: manual.deep_re`).

6. **Report (sealed report generation).** Findings are gated and approved through the human-in-the-loop
   approval loop — `index_findings` mints an evidence-gate token → `record_finding`/`approve_finding`
   (the HMAC hard-stop; demo approvals are labelled SIMULATED) → `report_generate` emits the
   report snapshot. The autonomous engine seals the full run into `report.json` +
   `report.audit-log.json` (validated against `schema/report.schema.json`), with the DFIR-report
   narrative synthesized by an Opus 4.8 multi-agent workflow grounded strictly in
   `confirmed-findings.json` / `FINDINGS.jsonl`. SRL-2015 ships both `exec_*` and `full_*` tiers; the
   evidence/presentation video is built by `findings_presentation_workflow.js` from
   `findings-presentation-storyboard.json`.

7. **SIEM (Wazuh indexing).** `wazuh_index_findings` first dry-runs the aggregated findings
   (`wazuh-push-receipts/dryrun_index.json`), then attempts a live index
   (`live_index.json`), with the aggregation + block decision captured in
   `pipeline_summary.json` → `pipeline_summary_FINAL.json` (2233 findings aggregated; live blocked by
   the evidence gate). Dashboards/index-patterns are imported from
   `wazuh/dashboards/agentropix-findings.ndjson`; tags follow `wazuh/tag_schema.py`. Confirmed
   findings/IOCs are then mapped to Wazuh rules in the per-case `WAZUH-*-GALLERY.md`.

Supporting workflows (session-local, per CLAUDE.md): `case-run-to-video.js`,
`complete-approval-loop.js`, `findings_presentation_workflow.js`.

---

## 5. Integrity & Validation Protocols

Every link in the chain is independently verifiable; nothing relies on trusting the model.

- **Acquisition SHA-256 baseline.** Each report binds its image via `evidence_image_sha256`
  (base-dc `e2b9cf0c…`, notch `80366d7e…`, nfury-disk `a5df0b38…`); the same digest is echoed in the
  run log (`Evidence SHA-256: 80366d7e…`), so the report provably pertains to that exact image.

- **Read-only evidence boundary (Thymus).** Evidence lives under a read-only allowlist; the Thymus
  policy ALLOWs only paths "within read-only zone" and REJECTs everything else
  (`REJECT_OUTSIDE_ALLOWLIST` — e.g. the `/tmp/claude-1001/agentropix-sift-*` extract/tasks temp
  paths). Every decision is streamed to `*-thymus-audit.jsonl` (base-dc 146 / notch 26 lines) and
  sealed into the audit-log companion. The evidence is never written to.

- **Quarantine expected == carved hash verification.** `MANIFEST.csv` records, per carved sample,
  the `expected_hash` and the `carved_sha256`; a `verified: Y` row means the carve reproduced the
  expected bytes exactly. Sample bytes stay out of the repo — the hash is the proof.

- **HMAC-SHA256 sealing (reports + audit logs).** Each run is sealed with a per-run 32-byte HMAC
  session-key (`*-report.session-key`, mode 0600, bytes never printed). The key produces the
  `report_seal` (64-hex HMAC over the report) and the `audit_log_seal` (64-hex HMAC over the
  audit log). The audit-log companion's `audit_log_seal` equals the report's `audit_log_seal`
  (cross-binding), and `metadata.entry_count` equals the JSONL line count — so report, audit log,
  and trail are mutually pinned. An evaluator with the session-key can independently re-verify both
  seals.

- **Coverage Critic + ground-truth recall.** The Critic scores coverage each iteration
  (`critic_score`, base-dc `1.0`) and emits `gaps`; the `ground_truth_*.yaml` `expected_tactics`
  feed the recall e2e tests and the gap channel — the canonical recall numbers are 72/72 (100%) disk
  and 108/118 (91.5%) memory (`run-summary-FULL-CASE-20260505T004738Z.md`).

- **Evidence gates (SIEM egress).** `wazuh_index_findings` will dry-run freely but **blocks the live
  index** absent a valid evidence-gate token (`pipeline_summary_FINAL.json`:
  `live_blocked: true, block_reason: wazuh_index_findings/bulk_…`); IOC pushes to shared
  `agentropix_*` CDB lists are additive-union (never replace-wipe other cases' IOCs).

- **Human-in-the-loop approval.** `record_finding`/`approve_finding` is the human HMAC hard-stop;
  SRL-2018 has 10 examiner-APPROVED findings on a signed HMAC chain, and any auto-approval in a
  recorded demo is labelled "SIMULATED examiner approval (demo only)."

- **Decision ledger.** Autonomous adopt/block decisions are appended to a hash-chained,
  tamper-evident ledger (`ledger verify` / `ledger chain`); `pipeline_summary_FINAL.json.ledger`
  references the relevant entries. A nightly cron `ledger verify` alerts on chain breaks.

- **Honest negatives.** Refuted hypotheses are retained, not deleted — VANKO keeps 9 refuted of 19
  in `FINDINGS.jsonl` with `disconfirming_notes`; the SRL-2018 report flags the operator-injected
  non-indicator IP `42.112.153.164` as having zero evidentiary presence. Evidence-type gating is
  recorded honestly too (e.g. `evtx_dump` failing on the raw `Challenge.raw` memory image — "Invalid
  EVTX file header magic").

- **Sealed-hash provenance lists.** Per-case `INDEX.md` files publish the sealed file-hash lists; the
  `sample-sealed-run/` exemplar (`report.json`) lets the integrity docs demonstrate the scheme on a
  small committed trace.
