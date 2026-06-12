# `screenshots/` — Wazuh Discover proof captures (SRL-2015 deep analysis)

Three dashboard captures proving the SRL-2015 deep-analysis findings were really indexed into the
live Wazuh/OpenSearch cluster — the visual chain-of-custody backing the claims in
[`../README.md`](../README.md) (which inventories this folder and walks the analysis itself).

| File | What it proves |
|---|---|
| [`02-discover-list.png`](02-discover-list.png) | the Discover view listing the indexed SRL-2015 findings (counts + index pattern visible) |
| [`03-finding-json.png`](03-finding-json.png) | one finding expanded as its full JSON document — the exact payload the MCP pushed, as stored |
| [`03-finding-table-mitre.png`](03-finding-table-mitre.png) | the finding table with its MITRE ATT&CK technique columns — the mapping survived indexing |

**How produced:** Playwright captures of the authenticated dashboard after the operator-authorized
Wazuh push (same egress discipline as the other cases — findings metadata only, no raw evidence
content in any capture). The cross-case correlation note in the parent README applies: all three
cases share one evidence cluster, filterable by `case_id`.
