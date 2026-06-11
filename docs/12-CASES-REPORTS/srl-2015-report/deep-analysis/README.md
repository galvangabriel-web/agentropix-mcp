# `deep-analysis/` — static reverse-engineering of the memory-injected payloads

Static-only (no execution) reverse-engineering of the five Volatility 3 `malfind` page dumps recovered
from the SRL-2015 RAM images. Conclusion: one **VB6-packed, LZMA self-injecting in-memory loader
family**, two compiler variants, no recoverable C2 — plus the YARA rule that detects it.

> Run `srl2015-deep-mem-20260610`, agent `deep-analysis` (`manual.deep_re`), 2026-06-10. All
> disassembly and strings below are real tool output (`objdump -b binary -m i386 -M intel` / capstone
> / `strings`); objdump temp-path headers stripped. No internal IPs/secrets/C2 appear in these files.
> This is **defensive forensic documentation of training-corpus malware** — analysis of *what was
> found and how to detect it*, not operational guidance.

## Files

| File | Type | Size | What it is |
|---|---|---|---|
| [`SRL-2015-memory-deep-analysis.md`](SRL-2015-memory-deep-analysis.md) | Markdown | 15 KB | Full RE report: methodology, per-variant walkthrough, clustering, negative C2 |
| [`SRL-2015-memory-deep-analysis.pdf`](SRL-2015-memory-deep-analysis.pdf) | PDF (7 pp) | 218 KB | Rendered report |
| [`INJECTION-ANALYSIS.md`](INJECTION-ANALYSIS.md) | Markdown | 2.5 KB | Condensed core of the loader chain |
| [`deep-findings.json`](deep-findings.json) | JSON | 20 KB | 10 structured MITRE-mapped findings |
| [`disasm-variantA.txt`](disasm-variantA.txt) | objdump | 120 KB | **Full** i386 disasm of cluster A (17, 18 — EBP frame, `jmp 0x804`) |
| [`disasm-variantB.txt`](disasm-variantB.txt) | objdump | 120 KB | **Full** i386 disasm of cluster B (19, 20 femc, 21 nfury — ESP frame, `jmp 0x86d`) |
| [`strings-all.txt`](strings-all.txt) | Text | 2.7 KB | ASCII + UTF-16LE strings of all 5 |
| [`ioc-config-summary.txt`](ioc-config-summary.txt) | Text | 2 KB | SHA-256s, variant grouping, **negative** C2 result |
| [`srl2015_meminject.yar`](srl2015_meminject.yar) | YARA | 3 KB | `SRL2015_MemInject_VB_Family` detection rule |
| [`screenshots/`](screenshots/) | PNG ×3 | 2.3 MB | Wazuh Discover proof the 10 findings indexed |

## The 5 samples

| # | sample (sha256) | host / pid | variant |
|---|---|---|---|
| 17 | `42f33a83…` | win2008R2-controller / 23476 (f-response-lm-) | A |
| 18 | `73cb9ad7…` | win2008R2-controller / 26340 (f-response-lm-) | A |
| 19 | `e855864a…` | win2008R2-controller / 145896 (f-response-ent) | B |
| 20 | `dd8ac01d…` (femc) | win2008R2-controller / 151132 | B |
| 21 | `a8f9a210…` | win7-64-nfury / 328 (f-response-ent) | B |

Each is an 8192-byte RWX VAD page (MITRE **T1055** process injection) carved by `malfind`.

---

## The malware in code (annotated)

### Memory layout / header
All 5 begin with an 8-byte little-endian header = `0x08`, the offset to an `E9` JMP stub; the byte at
`0x0D` is the decoder worker. Code starts at `0x08`, not `0x00`:
```
0:  08 00 00 00 00 00 00 00      ; header = 0x08 (offset of entry stub)
8:  e9 f7 07 00 00               ; jmp 0x804   (Variant A; Variant B: e9 60 08 00 00 -> jmp 0x86d)
d:  55 8b ec ...                 ; LZMA decoder worker (see below)
```

### 1. Loader entry `0x804` (Variant A) — the injection primitive
Computes an output size from a header byte, `VirtualAlloc`s an RW buffer, calls the decoder worker,
then `VirtualFree`s — a classic in-memory unpack. API pointers arrive in a caller-supplied table
(`[edi+0x8]`=VirtualAlloc, `[edi+0xc]`=VirtualFree):
```asm
804: push ebp ; mov ebp,esp ; sub esp,0x10
80c: mov  esi,[ebp+8]            ; arg1 = control struct
80f: movzx eax,byte [esi+4]      ; size seed = header byte[4]
815: push 9 ; pop ecx ; idiv ecx ; /9
81d: push 4                      ; PAGE_READWRITE
81f: push 0x1000                 ; MEM_COMMIT
82a: idiv edi                    ; /5
83c: mov  eax,0x300 ; shl eax,cl ; add eax,0x736 ; shl eax,4   ; size=((0x300<<cl)+0x736)<<4
84c: push 0                      ; addr = NULL
84e: call [edi+0x8]              ; VirtualAlloc(NULL,size,MEM_COMMIT,PAGE_RW)
853: mov  [ebp-4],eax            ; save decode buffer
867: call 0xd                    ; -> LZMA decoder worker (decompress 2nd stage into buffer)
86c: push 0x8000                 ; MEM_RELEASE
876: call [edi+0xc]              ; VirtualFree(buf,0,MEM_RELEASE)
87f: ret  0xc                    ; stdcall, 3 args
```

### 2. LZMA decoder worker `0x0d`
The second stage is **LZMA-compressed**; this worker is a range decoder (range `shr 0xB`, kTopValue
`0x800`, probability tables) that inflates the real payload in memory — which is why no plaintext PE
or C2 is present in the 8 KB page:
```asm
d:  push ebp ; mov ebp,esp ; sub esp,0x34
13: mov  eax,[ebp+8]             ; decoder context
2c: shl  ebx,cl                  ; range / probability setup
3c: mov  eax,0x300 ; shl eax,cl ; add eax,0x736   ; (matches the entry's size math)
…   ; range-coder renormalization loop (LZMA)
```

### 3. Position-independent API resolver — **resolve-by-name** (no API hashing)
Self-locates via `call $+5 / pop / sub`, then walks an embedded import-name list calling
`GetProcAddress` for each. Imports are plaintext (`OpenProcess`, `VirtualProtect`, `GetModuleHandleA`):
```asm
10e3: call 0x10e8
10e8: pop  ebx                   ; ebx = current EIP
10e9: sub  ebx,0x10001ac7        ; ebx -> image base (self-relocation delta)
1104: mov  edx,[ebx+0x10001eef]  ; resolved GetProcAddress ptr
110d: call edx                   ; GetProcAddress(module, name)
110f: mov  [ebp-4],eax           ; store into IAT
111d: jne  0x110a                ; loop over the import-name table
```
On failure it formats `"The procedure %s could not be located in the DLL %s."` — the MSVBVM6 runtime
error string, confirming the VB6 origin.

### 4. Variant B entry `0x86d` — same logic, ESP-frame recompile
Functionally identical (same `/9`, `/5`, `((0x300<<cl)+0x736)<<4` size math, same `MEM_COMMIT`/
`PAGE_RW`) but compiled with an ESP-relative frame and register-based API calls — clusters 19/20/21:
```asm
86d: sub  esp,0x10 ; push ebx/ebp/esi/edi
874: mov  edi,[esp+0x24]         ; control struct
878: movzx eax,byte [edi+4]      ; size seed
882: idiv ecx (=9)               ; /9
88d: push 4 ; push 0x1000        ; PAGE_RW, MEM_COMMIT
89a: idiv esi (=5)               ; /5
8a6: mov  edx,0x300              ; …same size math…
```
Cluster A and B share the loader byte-for-byte within a cluster; members differ only in the
LZMA-compressed payload region (19 vs 21 differ by just 17 bytes).

### Notable strings (identical across all 5)
```
msvbvm
The procedure %s could not be located in the DLL %s.
The ordinal %d could not be located in the DLL %s.
kernel32 · OpenProcess · GetModuleHandleA · VirtualProtect · ExitProcess · CloseHandle · MessageBoxA · wsprintfA
```
Full disasm → [`disasm-variantA.txt`](disasm-variantA.txt) / [`disasm-variantB.txt`](disasm-variantB.txt);
strings → [`strings-all.txt`](strings-all.txt).

---

## Detection — YARA
```yara
rule SRL2015_MemInject_VB_Family
{
    strings:
        $hdr    = { 08 00 00 00 00 00 00 00 E9 }
        $jmp_A  = { 08 00 00 00 00 00 00 00 E9 F7 07 00 00 }   // cluster A (17,18)
        $jmp_B  = { 08 00 00 00 00 00 00 00 E9 60 08 00 00 }   // cluster B (19,20,21)
        $vb     = "msvbvm" ascii
        $apitab = "OpenProcess\x00GetModuleHandleA\x00VirtualProtect" ascii
    condition:
        filesize < 256KB and $hdr at 0 and $vb
        and ( $jmp_A at 0 or $jmp_B at 0 ) and $apitab
}
```
Full rule (with sample SHA-256s) → [`srl2015_meminject.yar`](srl2015_meminject.yar). Fires on all 5
samples and future recompiles of the family.

## Findings (machine-readable)
10 MITRE-mapped findings in [`deep-findings.json`](deep-findings.json) — keys `finding_id, case_id,
host, confidence, mitre_attack[], detector_source, evidence{}, …`. Example evidence block:
`{sha256, file, pid, variant, header, jmp_stub, decoder_worker_offset}`. Techniques: T1055/.012,
T1620, T1027.002, T1140.

## Negative C2 result
A 256-key single-byte-XOR × base64 sweep over all 5 dumps found **zero** network indicators;
payload-tail entropy ~3.97 bits/byte (48.6% zero) rules out an embedded encrypted config — the real
C2 lives in the LZMA second stage, absent from these page captures. → [`ioc-config-summary.txt`](ioc-config-summary.txt).

## Proof in Wazuh
Discover captures showing the 10 findings indexed live:
[`02-discover-list.png`](screenshots/02-discover-list.png) ·
[`03-finding-json.png`](screenshots/03-finding-json.png) ·
[`03-finding-table-mitre.png`](screenshots/03-finding-table-mitre.png).

---
Sample catalogue (withheld binaries) → [`../quarantine/`](../quarantine/) · case provenance →
[`../README.md`](../README.md) · related: [SRL-2018](../../srl-2018-report/) · [VANKO](../../vanko-report/).
