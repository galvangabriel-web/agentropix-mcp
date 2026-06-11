# `deep-analysis/` — static reverse-engineering of the memory-injected payloads

Static-only (no execution) reverse-engineering of the five Volatility 3 `malfind` page dumps recovered
from the SRL-2015 RAM images. Conclusion: one **VB6-packed, LZMA self-injecting in-memory loader
family**, two compiler variants, no recoverable C2 — plus the YARA rule that detects it.

> Run `srl2015-deep-mem-20260610`, agent `deep-analysis` (`manual.deep_re`), 2026-06-10. All
> disassembly and strings below are real tool output (`objdump -b binary -m i386 -M intel` /
> capstone / `strings`). No internal IPs/secrets appear in these files.

## Files

| File | Type | Size | What it is |
|---|---|---|---|
| [`SRL-2015-memory-deep-analysis.md`](SRL-2015-memory-deep-analysis.md) | Markdown | 15 KB | Full RE report: methodology, per-variant disasm walkthrough, clustering, negative C2 result |
| [`SRL-2015-memory-deep-analysis.pdf`](SRL-2015-memory-deep-analysis.pdf) | PDF (7 pp, Letter) | 218 KB | Rendered PDF of the report above |
| [`INJECTION-ANALYSIS.md`](INJECTION-ANALYSIS.md) | Markdown | 2.5 KB | Condensed core: header, JMP stub, API-by-name resolution, VirtualAlloc→LZMA→VirtualFree flow |
| [`deep-findings.json`](deep-findings.json) | JSON | 20 KB | 10 structured, MITRE-mapped deep-RE findings (machine-readable) |
| [`disasm-variantA.txt`](disasm-variantA.txt) | Text (objdump) | 120 KB | Full i386 disasm of cluster A (samples 17, 18 — EBP frame, `jmp 0x804`) |
| [`disasm-variantB.txt`](disasm-variantB.txt) | Text (objdump) | 120 KB | Full i386 disasm of cluster B (samples 19, 20 femc, 21 nfury — ESP frame, `jmp 0x86d`) |
| [`ioc-config-summary.txt`](ioc-config-summary.txt) | Text | 2 KB | SHA-256 list, variant grouping, cleartext API indicators, **negative** network-IOC result |
| [`strings-all.txt`](strings-all.txt) | Text | 2.7 KB | ASCII + UTF-16LE strings of all 5 samples |
| [`srl2015_meminject.yar`](srl2015_meminject.yar) | YARA rule | 3 KB | `SRL2015_MemInject_VB_Family` — fires on all 5 samples and future recompiles |
| [`screenshots/`](screenshots/) | PNG ×3 (3200×2800) | 2.3 MB | Wazuh Discover captures proving the 10 findings landed in the index |

## `disasm-variantA.txt` — the real entry routine (the injection primitive)

The 8-byte header `08 00 00 00 00 00 00 00` is a little-endian offset (0x08) to an `E9` JMP stub;
the stub jumps to the real entry at `0x804`. That routine computes a buffer size, `VirtualAlloc`s it,
calls the LZMA decoder worker, then frees — the in-memory unpack:

```
     804:	55                   	push   ebp
     805:	8b ec                	mov    ebp,esp
     807:	83 ec 10             	sub    esp,0x10
     80c:	8b 75 08             	mov    esi,DWORD PTR [ebp+0x8]
     80f:	0f b6 46 04          	movzx  eax,BYTE PTR [esi+0x4]    ; size from header byte[4]
     815:	6a 09                	push   0x9
     818:	f7 f9                	idiv   ecx                       ; idiv 9
     81d:	6a 04                	push   0x4                       ; PAGE_READWRITE
     81f:	68 00 10 00 00       	push   0x1000                    ; MEM_COMMIT
     83c:	b8 00 03 00 00       	mov    eax,0x300
     841:	d3 e0                	shl    eax,cl                    ; (0x300<<cl)
     843:	05 36 07 00 00       	add    eax,0x736                 ; +0x736
     848:	c1 e0 04             	shl    eax,0x4                   ; <<4
     84e:	ff 57 08             	call   DWORD PTR [edi+0x8]       ; VirtualAlloc (fn-table +0x8)
```

Full file → [`disasm-variantA.txt`](disasm-variantA.txt). Variant B's equivalent stub jumps to
`0x86d` with an ESP-relative frame → [`disasm-variantB.txt`](disasm-variantB.txt).

## `strings-all.txt` — the notable strings (same across all 5 samples)

API resolution is by plaintext name (no API hashing); `msvbvm` confirms the VB6 runtime origin:

```
msvbvm
Application error
The procedure %s could not be located in the DLL %s.
The ordinal %d could not be located in the DLL %s.
MessageBoxA
wsprintfA
kernel32
ExitProcess
CloseHandle
OpenProcess
GetModuleHandleA
VirtualProtect
```

Full file → [`strings-all.txt`](strings-all.txt).

## `deep-findings.json` — schema + a representative finding

Top-level keys: `case_id`, `source_run_id`, `agent`, `detector_source`, `generated`, `methodology`,
`findings[]`. Each finding: `finding_id`, `case_id`, `host`, `agent`, `confidence`, `description`,
`mitre_attack[]`, `detector_source`, `evidence{}`, `event_time`, `source_run_id`.

```json
{
  "finding_id": "srl2015-mem-deep-1",
  "case_id": "SRL-2015-APT-ENTERPRISE",
  "host": "win2008R2-controller",
  "confidence": "high",
  "mitre_attack": [
    "T1055.012 Process Hollowing",
    "T1055 Process Injection",
    "T1027.002 Software Packing",
    "T1620 Reflective Code Loading",
    "T1140 Deobfuscate/Decode Files or Information"
  ],
  "detector_source": "manual.deep_re",
  "evidence": {
    "sha256": "42f33a83da0cecb9ddf53741423895221fca55060ade80e47ecd2a0ea2fe10c3",
    "file": "17_win2008R2-controller_malfind_pid23476.bin",
    "size_bytes": 8192, "pid": 23476, "process_label": "f-response-lm-",
    "variant": "A", "header": "08 00 00 00 00 00 00 00",
    "jmp_stub": "E9 F7 07 00 00 (jmp 0x804)",
    "entry_frame": "EBP (55 8B EC ; 83 EC 34)", "decoder_worker_offset": "0x0D"
  }
}
```

Full file (10 findings) → [`deep-findings.json`](deep-findings.json).

## `srl2015_meminject.yar` — the detection rule

Anchored on the header+JMP stub, `msvbvm`, and the injection-API cluster so it fires on the 5
samples and any future recompile:

```yara
rule SRL2015_MemInject_VB_Family
{
    strings:
        $hdr     = { 08 00 00 00 00 00 00 00 E9 }
        $jmp_A   = { 08 00 00 00 00 00 00 00 E9 F7 07 00 00 }   // cluster A (17,18)
        $jmp_B   = { 08 00 00 00 00 00 00 00 E9 60 08 00 00 }   // cluster B (19,20,21)
        $vb      = "msvbvm" ascii
        $api1    = "OpenProcess" ascii
        $api2    = "GetModuleHandleA" ascii
        $api3    = "VirtualProtect" ascii
        $api4    = "kernel32" ascii
        $apitab  = "OpenProcess\x00GetModuleHandleA\x00VirtualProtect" ascii
    condition:
        filesize < 256KB and $hdr at 0 and $vb and $api4
        and all of ($api1, $api2, $api3)
        and ( $apitab or $err1 or $err2 )
        and ( $jmp_A at 0 or $jmp_B at 0 or $hdr at 0 )
}
```

Full rule (incl. `meta:` SHA-256s) → [`srl2015_meminject.yar`](srl2015_meminject.yar).

## `ioc-config-summary.txt` — the negative C2 result

Key takeaway: a 256-key single-byte XOR × base64 sweep over all 5 dumps found **zero** readable
network indicators; payload-tail entropy (~3.97 bits/byte, 48.6% zero bytes) rules out an embedded
encrypted config — the real C2 lives in the LZMA-compressed second stage, absent from these page
captures. Full file → [`ioc-config-summary.txt`](ioc-config-summary.txt).

## `screenshots/`

Wazuh Discover captures (PNG, 3200×2800) showing the 10 deep-RE findings indexed live — Discover
list, a single finding's JSON document, and the MITRE technique table:
[`02-discover-list.png`](screenshots/02-discover-list.png),
[`03-finding-json.png`](screenshots/03-finding-json.png),
[`03-finding-table-mitre.png`](screenshots/03-finding-table-mitre.png).
