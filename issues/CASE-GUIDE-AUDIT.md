# Case-Guide Audit — MCP Tool / Volatility3 Allowlist Sweep

**Scope:** Audited all 13 case-activation guides under `case-activation/` against the
**live MCP tool list** and the **run_volatility plugin allowlist** (short alias OR full
canonical `windows.<mod>.<Class>` id only). Goal: every `🖥️` MCP call must name a real
tool, every `run_volatility` plugin must be allowlisted, and `get_image_info` /
`windows.info` / `banners` must never be used to identify the OS of a **raw memory** image.

## Summary table

| Guide | Evidence kind | Issues found | Issues fixed | Status |
|---|---|---:|---:|---|
| amf-memory-samples.md | Memory (raw .bin) | 6 | 6 | PATCHED |
| cfreds-hacking-case-4dell.md | Disk | 1 | 1 | PATCHED (post-audit verification catch — `mmls {…}` MCP slot → `get_partitions`) |
| challenge-notch-it-up.md | Memory | 2 | 2 | PATCHED |
| contact-me-memory.md | Memory | 4 | 4 | PATCHED |
| dfrws-2005-rodeo-usb.md | Disk / USB | 0 | 0 | CLEAN |
| jimmy-wilson-study-case.md | Disk | 0 | 0 | CLEAN |
| memdump-mem.md | Memory (raw .mem) | 1 | 1 | PATCHED |
| memlabs-dumps.md | Memory | 9 | 9 | PATCHED |
| rocba-hackathon-2026.md | Disk + Memory | 3 | 3 | PATCHED |
| srl-2015-apt-enterprise.md | Disk (E01) + Memory (.001) | 1 | 1 | PATCHED |
| srl-2018-compromised-enterprise.md | Disk (E01) | 4 | 4 | PATCHED |
| techhive-chad-lt-laptop.md | Disk (E01) | 1 | 1 | PATCHED |
| win-xp-laptop-2005.md | Memory | 5 | 5 | PATCHED |
| **Total** | | **37** | **37** | 2 CLEAN / 11 PATCHED |

All patched guides were mirrored to `/home/admin2/agentropix-sift/docs/portal/case-activation/`.

> **Post-audit verification (main loop):** the audit's consequential removals were re-checked against
> a fresh `tools/list` of the live MCP (71 tools): `get_hashdump`, `get_srum`, and `mmls` are confirmed
> **not** MCP tools; `srum_extract`, `get_partitions`, `parse_gpt`, `get_image_info` confirmed present.
> One guide the per-file audit marked CLEAN (`cfreds`) still had `mmls {…}` as a primary 🖥️ MCP slot —
> caught here and fixed (`fls` is a real MCP tool, so `fls {…}` calls were correctly left intact).

## Bug classes (overview)

1. **`os_id_misuse`** — `get_image_info` (or `windows.info`/`banners`) used as an
   OS/size/profile-confirm step on a **raw memory** image. `get_image_info` drives
   `ewfinfo` and reads **EWF/E01 metadata only**; on a raw `.mem/.raw/.bin/.001` dump it
   returns all-empty. Vol3 is profile-less — the kernel symbol table is **auto-detected on
   the first `windows.*` plugin** (`get_pslist`).
2. **`plugin_format`** — `run_volatility` plugin named in the rejected bare-middle form
   (`windows.cmdline`) instead of a short alias (`cmdline`) or full canonical id
   (`windows.cmdline.CmdLine`).
3. **`unknown_plugin`** — non-allowlisted Volatility plugin / alias (`hashdump`,
   `windows.hashdump`, `windows.registry.*` wildcard, `windows.amcache` on memory).
4. **`unknown_tool`** — a `🖥️` MCP slot naming a tool that does not exist
   (`get_hashdump`, `mmls`, `get_srum`) — replaced with the real MCP wrapper where one
   exists, or dropped.

## Per-guide changes

### amf-memory-samples.md (6 edits)
Raw `.bin` RAM dumps. Removed `get_image_info` everywhere it served as an OS/size-confirm
step (`os_id_misuse`): §1.1 tool-chain bullet replaced with an "use `ls`/`du`, anchor on
the `evidence_register` SHA-256" explainer; custody-step list, Step 4 optional call, §3.A
manual step 5 (deleted, steps 6–10 renumbered to 5–9 with the report cross-ref fixed to
"Step 8"), and §3.B autonomous prompt all updated. Remaining `get_image_info` mentions are
deliberate "not used / EWF-only" explainers.

### challenge-notch-it-up.md (2 edits)
Memory. `unknown_plugin`: removed `hashdump` from two `run_volatility` example lists
(chain diagram comment and manual step 7). The guide already correctly notes
`windows.info`/`banners`/`get_image_info` are EWF-only / auto-detected — those explainers
were left intact.

### contact-me-memory.md (4 edits)
Memory. `unknown_tool`: removed all 4 `get_hashdump`/`hashdump` references (recommended
tool chain, expert MCP-call block, autonomous prompt → swapped to `cmdline/netstat`, and
the verified tool-surface list). Credential-hash dumping is not exposed by this MCP, so the
step was dropped, not rewritten.

### memdump-mem.md (1 edit)
Raw `.mem`. `plugin_format`+`unknown_plugin`: the bare-form list
`windows.cmdline`/`windows.dlllist`/`windows.hashdump` rewritten to short-alias/canonical
form (`cmdline`/`windows.cmdline.CmdLine`), with `windows.hashdump` dropped and noted as
not exposed.

### memlabs-dumps.md (9 edits)
Memory. Broadest sweep: chain diagram (dropped `get_image_info`, annotated `get_pslist` as
the auto-detect step), "why these tools" prose, the **incorrect GOTCHA** claiming
`get_image_info` "still runs and reports size/metadata" on raw memory (corrected to
all-empty → use SHA-256 + `ls`/`du`), Step 4, Step 5 plugin block (alias form, dropped
`windows.hashdump`), `windows.registry.*` wildcard → concrete `printkey/hivelist/userassist`,
manual sequence (deleted `get_image_info` step 5, renumbered 6–12 → 5–11, fixed cross-ref),
autonomous driver chain, and the gotchas table.

### rocba-hackathon-2026.md (3 edits)
Disk **+** memory. Memory sub-chain: dropped `get_image_info`, made `get_pslist` the
OS/profile-confirm step, fixed plugin form, dropped invalid memory `windows.amcache` (noted
disk Amcache → `get_amcache`). Step-5 memory block: removed `get_image_info`. Autonomous
driver: scoped `get_image_info` to the disk/E01 run only. **`get_image_info` preserved in
its correct disk/E01 spots.**

### srl-2015-apt-enterprise.md (1 edit)
Disk (E01) **+** memory (.001). `os_id_misuse`: autonomous chain applied `get_image_info`
to all 8 images; reworded to "`get_image_info` (4 disk E01s only)" with an explainer that
the 4 raw memory images auto-detect via `get_pslist`.

### srl-2018-compromised-enterprise.md (4 edits)
Disk (E01). `unknown_tool`: `mmls` removed from `🖥️` MCP slots (Step 5 disk block and
manual step 9) → `get_partitions` / `parse_gpt`, with `mmls` demoted to an
"underlying binary" annotation. Two consistency edits: chain bullet and GOTCHA B2 offset
wording. `get_image_info` correctly retained on the DC disk E01.

### techhive-chad-lt-laptop.md (1 edit)
Disk (E01). `unknown_tool`: `get_srum` → `srum_extract` (the live MCP tool, verified in
`.crew/tool-list.md` and `wrappers/srum.py`). Both audit items resolved to the single
line-67 occurrence. The three `get_image_info` references all operate on the E01 — correct,
left intact.

### win-xp-laptop-2005.md (5 edits)
Memory. `os_id_misuse`+`plugin_format`: primary chain starts at `get_pslist` (dropped
`get_image_info`); Step 4 block drops `get_image_info` and rewrites the
`run_volatility` escape-hatch example to alias form; manual step 6 (`get_image_info`
falsely expecting "Windows XP / x86") replaced with `get_pslist`, steps reflowed; autonomous
step 1 and the gotcha table row updated.

## Needs human review

**None blocking.** No residual `unknown_tool` flags remain — every non-existent tool was
either mapped to a real MCP wrapper (`get_srum` → `srum_extract`, `mmls` →
`get_partitions`/`parse_gpt`) or dropped because no equivalent is exposed (`get_hashdump`,
`hashdump`, `windows.hashdump` — credential-hash dumping is not in the MCP surface). No
`PATCH RULE 4` "(NOTE: not in current MCP tool list)" markers were left pending. The only
items a reviewer may wish to confirm are **product decisions, not bugs**: this MCP exposes
no credential-hash-dump capability, so guides that previously promised one now omit that
step.

## Root cause

Two recurring authoring misconceptions, now corrected portal-wide:

1. **OS identification on memory images.** Authors treated `get_image_info` (and imagined
   `windows.info`/`banners` plugins) as a "what OS/build is this?" step for memory dumps.
   In reality `get_image_info` is **EWF/E01-only** (drives `ewfinfo`) and returns all-empty
   on raw memory, and there is **no OS/kernel-info plugin** exposed. Volatility3 is
   profile-less: the kernel symbol table is **auto-detected on the first `windows.*`
   plugin** — a populated `get_pslist` is the real confirmation; an empty result plus
   `Unable to validate ... kernel.symbol_table_name` means no profile resolved. All memory
   guides now anchor custody on SHA-256 + size and use `get_pslist` as the OS/profile signal.

2. **Volatility plugin name format.** Authors used the rejected bare-middle form
   (`windows.cmdline`). `run_volatility` accepts only a **short alias** (`cmdline`) or the
   **full canonical id** (`windows.cmdline.CmdLine`). All offending lists were normalized,
   and non-allowlisted plugins (`hashdump`, `windows.registry.*` wildcard,
   `windows.amcache` on memory) were removed.
