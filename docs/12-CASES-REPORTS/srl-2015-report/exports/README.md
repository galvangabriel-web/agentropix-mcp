# exports/ — machine-readable IOC & executable inventory

Tool-ingestible exports of the SRL-2015 indicators and executables, derived from the case findings
plus VirusTotal/OTX enrichment. Load these into a SIEM/TIP or correlate against the other cases.

| File | What it is | Size |
|---|---|---|
| `iocs.csv` | Flat IOC table — 91 indicators, with VT/OTX verdicts | 12 KB |
| `iocs.json` | Structured: case meta + verdict tally + per-IOC records | 32 KB |
| `iocs-stix.json` | **STIX 2.1** bundle (Indicator SDOs) for TIP import | 84 KB |
| `ear.csv` / `ear.json` | Executable Activity Registry — executables observed, hash + verdict | 2–6 KB |
| `_build_exports.py` | The generator script (provenance: exactly how these were produced) |  |

## `iocs.csv` — schema + sample rows
```
ioc,ioc_type,verdict,vt_malicious,vt_total,otx_pulses,providers,first_host,source,checked_at
bit.ly,domain,malicious,1,91,0,otx|virustotal,,ti-report+ES,2026-06-10T18:39:55Z
SHIELDBASE\vibranium,account,unknown,,,,,,ES-bundle,
0d830142-…-51bb06d321ba,dpapi_masterkey,unknown,,,,,,ES-bundle,
```
Verdict tally across the 91 IOCs: **12 malicious · 37 clean · 42 unknown** (`vt_*` columns hold the
VirusTotal detection ratio; `otx_pulses` = AlienVault OTX pulse hits).

## `ear.csv` — executables, hash-attributed
```
path,name,host,sha256,signer,signed,verdict,suspect
femc.exe,femc.exe,win2008R2-controller,dd8ac01d…203ebd,,,malicious,True
SMSvcHost.exe,SMSvcHost.exe,win2008R2-controller,58ef8b10…24bcd,,,clean,False
```

## Provenance
Every IOC traces evidence image → SHA-256 → finding → enrichment verdict; see the case
[provenance map](../README.md). The narrative reports are in [`../reports/`](../reports/); the carved
binaries behind the malicious hashes are catalogued in [`../quarantine/`](../quarantine/) (samples
withheld). Related cases: [SRL-2018](../../srl-2018-report/) · [VANKO](../../vanko-report/).
