# Wazuh Integration — Operator Guide

> **Section 09 · Integrations**
>
> **Audience:** DFIR examiners / SOC operators who consume Agentropix‑SIFT findings
> inside the Wazuh Dashboard. This guide is read‑only and view‑centric — it tells you
> how to *reach and read* the dashboards, not how the data is pushed.
>
> **Related:**
> - [Use Case — Push a Finding to Wazuh as an Alert](../06-use-cases/uc-wazuh-push.md)
>   (the push internals: kill switches, mutation tokens, dry‑run defaults — not duplicated here).

---

## 1. What the integration exposes to you

Agentropix‑SIFT publishes its case output into a dedicated set of `agentropix-*`
OpenSearch indices on the Wazuh Indexer, then surfaces them through pre‑built saved
objects in the **Wazuh Dashboard (OpenSearch Dashboards 2.19.5)**. As an end‑user you get
three dashboards (the **Findings Tab**, the **Timeline Tab**, and the original
**Findings overview**), two Discover saved searches, and an **Examiner Approval Portal**
deep‑link off every finding. The primary surface is the **Agentropix Findings Tab**:
metric stat tiles (total / DRAFT / APPROVED findings, distinct hosts, distinct MITRE
techniques), a searchable findings list, a severity donut, a MITRE‑technique bar chart,
and a workflow‑notes panel. Findings live in `agentropix-findings-*` (daily indices,
90‑day default retention) and timeline events in `agentropix-timeline-*`.

**How the data gets there (brief):** an examiner runs the Agentropix‑SIFT MCP tools
(`wazuh_index_findings`, `wazuh_publish_iocs`) which seal each document (HMAC‑SHA256) and
bulk‑index it into the `agentropix-*` indices. The write path is **fail‑closed and
dry‑run‑by‑default** and is gated by kill switches plus a one‑shot mutation token. You do
**not** need to understand any of that to read the dashboards — see
[uc-wazuh-push.md](../06-use-cases/uc-wazuh-push.md) for the push mechanics. The dashboard
saved‑object bundle itself is *operator‑imported* (Saved Objects Import), not pushed by the
runtime.

---

## 2. Accessing the dashboard

1. Open the Wazuh Dashboard at **<https://192.168.2.178/>** (the Wazuh Indexer/Dashboard
   host, OSD 2.19.5).
2. **Self‑signed certificate:** the host presents a self‑signed TLS certificate, so your
   browser will show a certificate warning on first visit. This is expected for this
   internal host — proceed/accept the exception to continue.
3. **Log in** with the Wazuh Dashboard `admin` account. **The password is not recorded in
   this document** — it lives in `gitlab.txt` alongside the deployment. Never paste the
   password into tickets, chat, or docs.
4. After login you land on the Wazuh home page (`/app/wz-home`). Use the left‑hand menu
   **Dashboards** entry (or paste the direct `/app/dashboards#/view/...` URLs below) to open
   each Agentropix view.

> All Agentropix dashboards default to a **`now-30d`** (Last 30 days) time window.

---

## 3. Agentropix Findings Tab (primary view)

**Saved‑object id:** `agentropix-findings-tab`
**Direct URL:** <https://192.168.2.178/app/dashboards#/view/agentropix-findings-tab>
**Navigate:** Dashboards → **Agentropix Findings Tab**

This is the main examiner workspace. Across the top sit **five metric stat tiles** —
*Findings · total*, *Findings · DRAFT*, *Findings · APPROVED*, *Hosts (distinct)*, and
*MITRE techniques (distinct)*. Below them, the left two‑thirds is the **findings list**
(a Discover‑style saved search with columns *Time*, *finding_id*, *severity*,
*approval.status*, *mitre_techniques*, *host.name*); the right side carries the
**severity donut** (top) and the **findings‑by‑MITRE‑technique bar chart** (below). A
full‑width **workflow‑notes** markdown panel sits at the bottom.

![Agentropix Findings Tab — stat tiles across the top, findings list with the approval.status column highlighted, severity donut and MITRE bar to the right](assets/wz-01-findings-tab-overview.png)

In the capture above the tiles read **774** total findings, **746** DRAFT, **1** APPROVED,
and **32** distinct MITRE techniques; the findings list shows `finding_id`, `severity`, and
the highlighted **`approval.status`** column (mostly `DRAFT`). The `finding_id` cells are
clickable deep‑links into the **Examiner Approval Portal** (see §6).

---

## 4. Agentropix Timeline Tab

**Saved‑object id:** `agentropix-timeline-tab`
**Direct URL:** <https://192.168.2.178/app/dashboards#/view/agentropix-timeline-tab>
**Navigate:** Dashboards → **Agentropix Timeline Tab**

The timeline workspace, backed by the `agentropix-timeline-*` index pattern. It has two
metric tiles (*Timeline events · total* and *Timeline events · APPROVED*), a
findings/timeline **line chart**, and a **timeline saved‑search list** with columns
*event_id*, *event_type*, *summary*, *host*, and *linked_finding_ids* (sorted by
`@timestamp` ascending).

![Agentropix Timeline Tab — two metric tiles (events total / APPROVED) and the line chart on top, the timeline events list below](assets/wz-07-timeline-tab.png)

In this capture the tiles read **3** total timeline events and **0** APPROVED; the events
list shows the per‑event rows linking back to findings via `linked_finding_ids`.

---

## 5. Agentropix findings overview

**Saved‑object id:** `agentropix-findings-overview`
**Direct URL:** <https://192.168.2.178/app/dashboards#/view/agentropix-findings-overview>
**Navigate:** Dashboards → **Agentropix findings overview**

The original pre‑canned three‑panel dashboard. The **severity donut** is top‑left, the
**MITRE‑technique bar chart** is top‑right, and a full‑width **findings timeline line chart**
runs along the bottom. Time window defaults to `now-30d`.

![Agentropix findings overview — severity donut top-left, MITRE technique bar top-right, full-width findings timeline line chart along the bottom](assets/wz-08-findings-overview.png)

> The two Discover saved searches — **Agentropix findings - all**
> (`agentropix-findings-search`) and **Agentropix timeline - all events**
> (`agentropix-timeline-search`) — are embedded as the list panels of the Findings Tab and
> Timeline Tab respectively. To open one standalone, go to **Discover → Open** and pick it
> by name.

---

## 6. Drilling into a finding

Every row in the findings list is a single sealed finding document. The same document can
be viewed two ways — a **Table** (field/value) view and a raw **JSON** view. They are the
*same document*, just two renderings.

### Step 1 — Expand the row

Click the **expand caret** in the first column of any finding row (ringed in red below).

![Findings Tab with the first-column expand caret of a DRAFT finding row ringed in red — this is the click target to open the document](assets/wz-03-findings-expand-row.png)

### Step 2 — Read the Table view (default)

The row expands into an **Expanded document** panel showing every field as a name/value
pair — `finding_id`, `severity`, `approval.status`, `mitre_techniques`, the `host.*`
fields, and the rest of the finding metadata. A **Table | JSON** toggle sits at the
top‑left of the expanded panel.

![Expanded finding document rendered as a field/value Table, with the Table | JSON toggle at the top-left of the panel](assets/wz-04-findings-detail-table.png)

### Step 3 — Switch between Table and JSON

The **Table** and **JSON** tabs render the *same* finding in two formats — pick whichever
is easier to read. Table is best for scanning individual fields; JSON is best for copying
the full source document.

![The Table / JSON view toggles inside the expanded finding document, annotated to show one document in two formats](assets/wz-05-findings-detail-toggles.png)

### Step 4 — Read the JSON view

Clicking **JSON** shows the full raw source document, including `approval.status` (e.g.
`DRAFT`), `mitre_techniques`, `host`, and the finding metadata — the exact bytes that were
sealed and indexed.

![The same finding document rendered as raw JSON after clicking the JSON toggle — full source including approval.status, mitre_techniques, and host](assets/wz-06-findings-detail-json.png)

---

## 7. Setting the time range and filtering with KQL

To find specific data, scope the dashboard with the **time‑range picker** and the
**KQL query / filter bar**.

![Findings Tab annotated with the global KQL query/filter bar (left) and the top-right time-range picker showing the default Last 30 days window](assets/wz-02-findings-tab-timerange-kql.png)

- **Time range** — use the **superDatePicker** at the top‑right (shows **Last 30 days** by
  default). Pick a quick range (Today, Last 24 hours, Last 7 days…), an absolute
  from/to window, or a relative window, then click **Update/Refresh**. All panels and the
  embedded list re‑query for the selected window.
- **KQL filters** — type a query in the search bar at the top‑left, e.g.:
  - `approval.status : "DRAFT"` — only un‑approved findings
  - `approval.status : "APPROVED"` — only signed‑off findings
  - `severity : "high"` — high‑severity findings
  - `host.name : "host-004"` — findings for one host
  - `mitre_techniques : "T1059"` — findings tagged with a technique
  - Combine with `and` / `or`, e.g. `severity : "high" and approval.status : "DRAFT"`.
- You can also click any value in a panel or the **+ / −** add/remove‑filter pills to pin a
  structured filter without typing KQL.

---

## 8. What each finding status means

The **`approval.status`** field tracks a finding through the examiner approval state
machine. Status transitions are written to `agentropix-approvals-*` via the **Examiner
Approval Portal** (deep‑linked from every `finding_id` cell):

| Status | Meaning |
| --- | --- |
| **DRAFT** | Default state. The finding has been indexed but **not yet reviewed/signed** by an examiner. Most findings start here. |
| **APPROVED** | An examiner reviewed the DRAFT and **signed an APPROVE** in the Approval Portal. Only APPROVED findings should drive downstream SOC action. |
| **REJECTED** | An examiner reviewed the finding and **declined** it — it should not be acted on. |
| **REVOKED** | A previously‑APPROVED finding was **withdrawn** after the fact. The approvals index is tamper‑evident (read‑only historical rows), so a revocation is recorded as a new state row rather than an edit. |

**Approving a finding:** click a `finding_id` cell in the Findings Tab — it opens the
**Examiner Approval Portal** sidecar in a new tab
(`http://127.0.0.1:8800/?target_id=<finding_id>` on the loopback default, or its tailnet
URL). There you review the DRAFT and sign **APPROVE** locally via an HMAC
challenge‑response (your password never leaves the browser); the portal writes the
`DRAFT → APPROVED` row to `agentropix-approvals-*`, after which the *Findings · APPROVED*
tile and the `approval.status` column update on refresh.

> The Approval Portal is a separate FastAPI app reached through the finding deep‑link; it is
> not part of the dashboard bundle and is not screenshotted in this guide.

---

## Privacy note

The screenshots in this guide were captured from the **live internal Wazuh deployment** and
show:

- An **internal IP address** (`192.168.2.178`) for the Wazuh Indexer/Dashboard host.
- **Live alert / finding data** — real `finding_id`s, host names, severities, and MITRE
  techniques from the running environment.

Treat this document and its `assets/` images as **internal‑only**. Do not publish them
externally, and never add the Wazuh Dashboard password (kept in `gitlab.txt`) to this or any
other shared document.
