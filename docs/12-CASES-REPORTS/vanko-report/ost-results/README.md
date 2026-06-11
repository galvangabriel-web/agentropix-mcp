# `ost-results/` — Outlook OST mailbox carve output (`carve_pst_iocs`)

Output of the Agentropix `carve_pst_iocs` tool against the two Outlook OST mailbox stores
extracted from the STARKSURFACE image (`/Users/PC User/AppData/Local/Microsoft/Outlook/`).
This is the artifact source behind confirmed finding **VANKO-P3-003** (foreign-handler
coordination: the 2016-06-27 "RE: Potential Opportunity?" reply carrying 3 attachments).

> **PII policy (read first).** These JSON files are **raw-mailbox-derived** and contain personal
> data (senders, recipients, subjects). They are deliberately **kept local-only / unpublished**.
> In every excerpt below, personal values are replaced with `<REDACTED-PII>` — only structure,
> field names, counts, dates, and attachment hashes are shown. The mailbox file names themselves
> identify the case subject's accounts, as already named in the published
> [DFIR report](../VANKO-DFIR-REPORT.md).

## Files

| File | Type | Size | What it is |
|---|---|---|---|
| `_extra_extract.json` | JSON (tool result) | 312 B | `sleuthkit.icat` follow-up extraction attempt for a third OST path — `entry_count: 0`, path reported `missing` (clean negative) |
| `anthony.vanko@gmail.com (1).ost.carve.json` | JSON (carve result) | 683 KB | Full carve of the 127 MiB Gmail OST: **1,592 messages** (79 via pypff + 1,513 deep-recovered), **218 attachments / 50 unique SHA-256**, per-attachment IOC index |
| `anthony.vanko@icloud.com.ost.carve.json` | JSON (carve result) | 11 KB | Carve of the 16 MiB iCloud OST: **36 messages** (35 deep-recovered, 1 `empty_message_store` deferral), **0 attachments** |

## Gmail OST carve — schema + summary (real bytes, PII redacted)

Top-level keys: `tool`, `source_pst`, `messages[]`, `iocs[]`, `ioc_index{}`, `summary`, `warnings[]`.

```json
"tool": "carve_pst_iocs",
"source_pst": "/tmp/agentropix-sift-vanko/outlook/<REDACTED-PII>.ost",
"summary": {
  "n_messages_total": 1592,
  "n_messages_pypff": 79,
  "n_messages_recovered": 1513,
  "n_messages_recovery_failed": 0,
  "n_messages_deferral": 0,
  "n_attachments_total": 218,
  "n_unique_hashes": 50,
  "pst_size_bytes": 133570560,
  "truncated": false
}
```

Representative `messages[]` record — this is the case-pivotal **VANKO-P3-003** message (the
3-attachment reply to the recruiter, 2016-06-28 01:22 local / 2016-06-27 21:22 UTC in the report):

```json
{
  "subject": "<REDACTED-PII>",
  "sender": "<REDACTED-PII>",
  "date": "2016-06-28T01:22:46",
  "recipients": [
    "<REDACTED-PII>"
  ],
  "n_attachments": 3,
  "engine": "pypff",
  "parser_note": ""
}
```

Representative `iocs[]` record (one of 218; `ioc_index` groups the same records under the 50
unique attachment SHA-256 values — largest group: `75b9e4d5…` × 20 occurrences):

```json
{
  "sha256": "75b9e4d593946f2059406e742e91ab3e86d3b515aa5255fea04a4251d8d1b0cd",
  "filename": "ReadNotify_Logo.gif",
  "size": 1551,
  "mime_type": null,
  "source_subject": "<REDACTED-PII>",
  "source_sender": "<REDACTED-PII>",
  "source_date": "2015-10-04T20:05:51",
  "source_engine": "pypff",
  "source_parser_note": "",
  "source_pst": "/tmp/agentropix-sift-vanko/outlook/<REDACTED-PII>.ost"
}
```

Full file: `anthony.vanko@gmail.com (1).ost.carve.json`
*(local-only; not published — raw mailbox PII)*.

## iCloud OST carve — summary (real bytes)

```json
"summary": {
  "n_messages_total": 36,
  "n_messages_pypff": 0,
  "n_messages_recovered": 35,
  "n_messages_recovery_failed": 0,
  "n_messages_deferral": 1,
  "n_attachments_total": 0,
  "n_unique_hashes": 0,
  "pst_size_bytes": 16818176,
  "truncated": false
}
```

The single deferral record is structural, not personal (the OST's live message store is empty —
all 35 recovered messages came from `pffexport` deep recovery, engine
`pffexport_recovered:synthesized_eml:v20180714`):

```json
{
  "subject": "",
  "sender": "",
  "date": "",
  "recipients": [],
  "n_attachments": 0,
  "engine": "deferral",
  "parser_note": "empty_message_store"
}
```

Full file: `anthony.vanko@icloud.com.ost.carve.json`
*(local-only; not published — raw mailbox PII)*.

## `_extra_extract.json` — full content (real bytes, PII redacted)

```json
{"image_path":"/cases/vanko/surface_physical.E01","offset":1411072,"fstype":"",
 "dest_dir":"/tmp/agentropix-sift-vanko/outlook","entry_count":0,"extracted":[],
 "missing":["/Users/PC User/AppData/Local/Microsoft/Outlook/<REDACTED-PII>"],
 "rejected":[],"tool":"sleuthkit.icat","raw_stderr":"","hints":[]}
```

A third OST path (the non-`(1)` Gmail store) was probed and does **not** exist on the volume —
recorded as a clean negative. Full file: `_extra_extract.json` *(local-only; not published)*.
