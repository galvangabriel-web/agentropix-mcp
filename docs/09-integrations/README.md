# 09 · Integrations

Connecting Agentropix-SIFT to external systems: a SOC (Wazuh) and a remote client.

## Read in this order

1. [client-setup.md](client-setup.md) — point Claude Code CLI or Claude Desktop at an already-running MCP server over a Tailscale tailnet (connect first).
2. [wazuh-portal.md](wazuh-portal.md) — drive the Wazuh integration day to day: connect the SOC, preview a push, confirm alerts landed, and read the dashboards.

> The push *mechanics* (MCP-tool internals) live in the use case [docs/06-use-cases/uc-wazuh-push.md](../06-use-cases/uc-wazuh-push.md).

## Assets

Screenshots embedded in [wazuh-portal.md](wazuh-portal.md):

- [assets/wz-01-findings-tab-overview.png](assets/wz-01-findings-tab-overview.png) — Findings tab overview: stat tiles, findings list with the approval.status column, severity donut, and MITRE bar.
- [assets/wz-02-findings-tab-timerange-kql.png](assets/wz-02-findings-tab-timerange-kql.png) — Findings tab with the global KQL query/filter bar and the time-range picker (default Last 30 days) annotated.
- [assets/wz-03-findings-expand-row.png](assets/wz-03-findings-expand-row.png) — Findings tab with a DRAFT finding row's expand caret ringed in red to show the click target.
- [assets/wz-04-findings-detail-table.png](assets/wz-04-findings-detail-table.png) — Expanded finding document rendered as a field/value table with the Table|JSON toggle.
- [assets/wz-05-findings-detail-toggles.png](assets/wz-05-findings-detail-toggles.png) — Table/JSON view toggles inside an expanded finding document (one document in two formats).
- [assets/wz-06-findings-detail-json.png](assets/wz-06-findings-detail-json.png) — Finding document rendered as raw JSON (including approval.status, mitre_techniques, host).
- [assets/wz-07-timeline-tab.png](assets/wz-07-timeline-tab.png) — Timeline tab: events-total/APPROVED metric tiles, line chart, and timeline events list.
- [assets/wz-08-findings-overview.png](assets/wz-08-findings-overview.png) — Findings overview: severity donut, MITRE technique bar, and full-width findings timeline line chart.
