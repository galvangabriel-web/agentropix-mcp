# quarantine/ — carved malware sample catalogue (samples withheld)

Chain-of-custody record for the malicious/suspect binaries recovered during the SRL-2015
investigation. **The samples themselves are NOT published** — the password-protected archive
(`srl2015-samples.zip`, 21 live-malware binaries) is withheld from this public repo. What's here is
the **manifest** proving what was carved and that each carve hash-matched its IOC.

| File | What it is |
|---|---|
| `MANIFEST.csv` | One row per carved sample: source path, host, expected vs carved SHA-256, verified flag, size |
| `README.txt` | Handling note (the withheld archive's password + live-malware warning) |

## `MANIFEST.csv` — schema + sample rows
```
in_zip_name,original_path,host,expected_hash,carved_sha256,verified,size_bytes
01_controller_usboesrv.exe,"/Program Files/USB over Ethernet/usboesrv.exe",controller,5420d06d…,5420d06d…,Y,…
02_controller_usboesrv.exe,"/Windows/System32/usboesrv.exe",controller,5420d06d…,5420d06d…,Y,…
03_win7-32-nromanoff_a.exe,"/Users/vibranium/AppData/Local/Temp/a.exe",win7-32-nromanoff,598e53b6…,598e53b6…,Y,…
```

## What's in the archive (catalogued, not shipped)
**21 entries**, all `verified=Y` (carved SHA-256 == the IOC hash, 0 mismatches):
- **16 on-disk binaries** — 4 distinct malicious executables (`usboesrv.exe`, `a.exe`, `spinlock.exe`,
  `svchost.exe`) plus duplicate copies, carved read-only from the host E01s.
- **5 memory-injection payloads** — RWX `malfind` regions (MITRE **T1055**) extracted from the RAM
  dumps; analyzed in [`../deep-analysis/`](../deep-analysis/).

## Provenance
The `expected_hash` column is the malicious-IOC hash from [`../exports/`](../exports/); `carved_sha256`
is recomputed from the bytes pulled out of the evidence — equality is the integrity proof. Full
chain: [case provenance map](../README.md). Related cases:
[SRL-2018](../../srl-2018-report/) · [VANKO](../../vanko-report/).
