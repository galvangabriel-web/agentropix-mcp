#!/usr/bin/env python3
"""Build IOC + EAR exports for case SRL-2015-APT-ENTERPRISE.

Aggregates the distinct IOC set from the TI report (enrichment/ti-report.json,
76 records) UNION the agentropix-iocs-* ES bundle (raw IOC bundle), attributes
each to a first_host from the per-host disk/memory findings, and writes:
  iocs.csv, iocs.json, iocs-stix.json (STIX 2.1)
Derives the Executable Registry from per-host findings (sha256 + PE name/path)
since the MCP EAR is empty for this case, and writes ear.csv, ear.json.
"""
import json, re, csv, uuid, hashlib, datetime
from pathlib import Path

PIPE = Path("/home/admin2/agentropix-sift/Reports_results/SRL2015-PIPELINE-V2")
ES_DUMP = Path("/tmp/es_iocs.json")
OUT = Path("/home/admin2/agentropix-sift/Reports_results/SRL2015-DELIVERABLE/exports")
OUT.mkdir(parents=True, exist_ok=True)
CASE = "SRL-2015-APT-ENTERPRISE"
HOSTS = ["win2008R2-controller", "win7-32-nromanoff", "win7-64-nfury", "xp-tdungan"]

ti = json.loads((PIPE / "enrichment" / "ti-report.json").read_text())
es = json.loads(ES_DUMP.read_text())
es_hits = [h["_source"] for h in es["hits"]["hits"]]

# ---- index ES per-IOC metadata (providers, checked_at) keyed by ioc string ----
es_meta = {}
for s in es_hits:
    val = s.get("ioc") or s.get("ioc_value")
    if not val:
        continue
    rec = es_meta.setdefault(val, {})
    if "threat_intel" in s:
        ti_blk = s["threat_intel"]
        rec["providers"] = ti_blk.get("providers", [])
        rec["checked_at"] = ti_blk.get("checked_at")
        rec["es_verdict"] = ti_blk.get("verdict")
        rec["es_vt_mal"] = ti_blk.get("vt_malicious")
        rec["es_vt_total"] = ti_blk.get("vt_total")
        rec["es_otx"] = ti_blk.get("otx_pulses")
    rec.setdefault("ioc_type", s.get("ioc_type"))
    rec.setdefault("finding_refs", set()).update(s.get("finding_refs", []))

# ---- pre-load all per-host findings text for host attribution ----
host_blobs = {}  # host -> list of (source, lowered_blob, raw_blob)
for host in HOSTS:
    blobs = []
    for img in ("disk.json", "memory.json"):
        p = PIPE / host / img
        if not p.exists():
            continue
        d = json.loads(p.read_text())
        for f in d.get("findings", []):
            raw = (f.get("description", "") + " " + f.get("evidence", "") + " "
                   + json.dumps(f.get("evidence_dict", {})))
            blobs.append((f.get("_source", ""), raw.lower(), raw))
    host_blobs[host] = blobs

PE_WIN = re.compile(r"([A-Za-z]:\\[^\s\"',]*?\.(?:exe|dll|sys|scr|job))", re.I)
PE_UNX = re.compile(r"(/[^\s\"',]*?\.(?:exe|dll|sys|scr|job))", re.I)
NAME = re.compile(r"\b([\w.\-]+\.(?:exe|dll|sys|scr))\b", re.I)


def attribute_host(ioc_lower):
    """Return (first_host, names, paths, sources) for an IOC string."""
    for host in HOSTS:  # deterministic order = controller, nromanoff, nfury, xp
        for src, low, raw in host_blobs[host]:
            if ioc_lower in low:
                names = set(NAME.findall(raw))
                paths = set(PE_WIN.findall(raw)) | set(PE_UNX.findall(raw))
                return host, names, paths, src
    return "", set(), set(), ""


# ---- build the canonical distinct IOC rows ----
# Start from TI report (authoritative verdicts), then add ES-bundle-only IOCs.
rows = {}  # ioc -> row dict

TYPE_MAP = {"sha256": "sha256", "sha1": "sha1", "md5": "md5", "ip": "ipv4-addr",
            "ipv4": "ipv4-addr", "domain": "domain-name", "url": "url",
            "email": "email-addr", "account": "user-account", "filename": "file",
            "filepath": "file", "regkey": "windows-registry-key",
            "usb_serial": "usb-serial", "dpapi_masterkey": "dpapi-masterkey",
            "geolocation": "geolocation"}


def es_lookup(ioc):
    return es_meta.get(ioc, {})


for r in ti["iocs"]:
    ioc = r["ioc"]
    itype = r.get("indicator_type") or r.get("kind") or "unknown"
    meta = es_lookup(ioc)
    host, names, paths, src = attribute_host(ioc.lower())
    rows[ioc] = {
        "ioc": ioc,
        "ioc_type": itype,
        "verdict": r.get("verdict") or "unknown",
        "vt_malicious": r.get("vt_malicious", ""),
        "vt_total": r.get("vt_total", ""),
        "otx_pulses": r.get("otx_pulses", ""),
        "providers": "|".join(meta.get("providers", []) or (ti.get("providers", []) if r.get("status") == "enriched" else [])),
        "first_host": host,
        "source": "ti-report+ES" if meta else "ti-report",
        "checked_at": meta.get("checked_at") or (ti.get("generated_at") if r.get("status") == "enriched" else ""),
        "_names": names, "_paths": paths,
    }

# Add ES-bundle IOCs that are NOT already in the TI set (accounts, urls, regkeys, ...)
for val, meta in es_meta.items():
    if val in rows:
        continue
    itype = meta.get("ioc_type") or "unknown"
    host, names, paths, src = attribute_host(val.lower())
    rows[val] = {
        "ioc": val,
        "ioc_type": itype,
        "verdict": meta.get("es_verdict") or "unknown",
        "vt_malicious": meta.get("es_vt_mal", ""),
        "vt_total": meta.get("es_vt_total", ""),
        "otx_pulses": meta.get("es_otx", ""),
        "providers": "|".join(meta.get("providers", [])),
        "first_host": host,
        "source": "ES-bundle",
        "checked_at": meta.get("checked_at") or "",
        "_names": names, "_paths": paths,
    }

ioc_rows = sorted(rows.values(), key=lambda x: (x["ioc_type"], x["ioc"]))

# ---- iocs.csv ----
csv_fields = ["ioc", "ioc_type", "verdict", "vt_malicious", "vt_total",
              "otx_pulses", "providers", "first_host", "source", "checked_at"]
with (OUT / "iocs.csv").open("w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=csv_fields, extrasaction="ignore")
    w.writeheader()
    for row in ioc_rows:
        w.writerow(row)

# ---- iocs.json ----
ioc_json = {
    "case_id": CASE,
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "source_ti_report": str(PIPE / "enrichment" / "ti-report.json"),
    "source_es_index": "agentropix-iocs-* @ https://<WAZUH-INDEXER>:9200 (case_id=" + CASE + ")",
    "ioc_count": len(ioc_rows),
    "tally": {
        "malicious": sum(1 for r in ioc_rows if r["verdict"] == "malicious"),
        "clean": sum(1 for r in ioc_rows if r["verdict"] == "clean"),
        "unknown": sum(1 for r in ioc_rows if r["verdict"] == "unknown"),
        "suspicious": sum(1 for r in ioc_rows if r["verdict"] == "suspicious"),
    },
    "iocs": [{k: r[k] for k in csv_fields} for r in ioc_rows],
}
(OUT / "iocs.json").write_text(json.dumps(ioc_json, indent=2))

# ---- STIX 2.1 bundle ----
NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def stix_pattern(ioc, itype):
    t = itype.lower()
    if t == "sha256":
        return f"[file:hashes.'SHA-256'='{ioc}']"
    if t == "sha1":
        return f"[file:hashes.'SHA-1'='{ioc}']"
    if t == "md5":
        return f"[file:hashes.'MD5'='{ioc}']"
    if t in ("ip", "ipv4"):
        return f"[ipv4-addr:value='{ioc}']"
    if t == "domain":
        return f"[domain-name:value='{ioc}']"
    if t == "url":
        return f"[url:value='{ioc}']"
    if t == "email":
        return f"[email-addr:value='{ioc}']"
    if t == "account":
        return f"[user-account:account_login='{ioc}']"
    if t in ("filename", "filepath"):
        return f"[file:name='{ioc}']"
    if t == "regkey":
        return f"[windows-registry-key:key='{ioc}']"
    return f"[x-agentropix:value='{ioc}']"


objs = []
identity_id = "identity--" + str(uuid.uuid5(NS, "agentropix-sift"))
objs.append({
    "type": "identity", "spec_version": "2.1", "id": identity_id,
    "created": now, "modified": now, "name": "Agentropix-SIFT",
    "identity_class": "system",
})
for r in ioc_rows:
    ind_id = "indicator--" + str(uuid.uuid5(NS, r["ioc"] + "|" + r["ioc_type"]))
    labels = []
    if r["verdict"] == "malicious":
        labels.append("malicious-activity")
    elif r["verdict"] == "suspicious":
        labels.append("anomalous-activity")
    elif r["verdict"] == "clean":
        labels.append("benign")
    obj = {
        "type": "indicator", "spec_version": "2.1", "id": ind_id,
        "created": now, "modified": now,
        "created_by_ref": identity_id,
        "name": f"{r['ioc_type']} {r['ioc']}",
        "pattern": stix_pattern(r["ioc"], r["ioc_type"]),
        "pattern_type": "stix",
        "valid_from": r["checked_at"] or now,
        "labels": labels or ["unknown"],
        "x_agentropix_case_id": CASE,
        "x_agentropix_verdict": r["verdict"],
        "x_agentropix_vt_malicious": r["vt_malicious"],
        "x_agentropix_vt_total": r["vt_total"],
        "x_agentropix_otx_pulses": r["otx_pulses"],
        "x_agentropix_providers": r["providers"],
        "x_agentropix_first_host": r["first_host"],
        "x_agentropix_source": r["source"],
    }
    objs.append(obj)

bundle = {"type": "bundle", "id": "bundle--" + str(uuid.uuid4()), "objects": objs}
(OUT / "iocs-stix.json").write_text(json.dumps(bundle, indent=2))

# ---- malicious file-hashes (drive carve phase) ----
malicious_hashes = sorted({r["ioc"] for r in ioc_rows
                           if r["verdict"] == "malicious"
                           and r["ioc_type"] in ("sha256", "sha1", "md5")})

# ============================ EAR ============================
# MCP exec_registry_get returned 0 for this case -> derive from findings.
# Inventory = every sha256 IOC that maps to a PE (.exe/.dll/.sys/.scr) name/path,
# attributed to its first_host, verdict-flagged.
verdict_by_ioc = {r["ioc"]: r["verdict"] for r in ioc_rows}
mal_set = set(malicious_hashes)

ear_rows = []
all_sha = [r["ioc"] for r in ioc_rows if r["ioc_type"] == "sha256"]
for sha in all_sha:
    host, names, paths, src = attribute_host(sha.lower())
    # only include if it resolves to an executable (PE-ish) name or path
    pe_names = sorted(n for n in names)
    pe_paths = sorted(p for p in paths)
    if not pe_names and not pe_paths:
        continue
    name = pe_names[0] if pe_names else Path(pe_paths[0]).name
    path = pe_paths[0] if pe_paths else name
    verdict = verdict_by_ioc.get(sha, "unknown")
    suspect = (sha in mal_set) or (verdict == "malicious")
    ear_rows.append({
        "path": path,
        "name": name,
        "host": host,
        "sha256": sha,
        "signer": "",      # not present in findings JSON
        "signed": "",      # not present in findings JSON
        "verdict": verdict,
        "suspect": suspect,
        "all_names": "|".join(pe_names),
        "all_paths": "|".join(pe_paths),
    })

ear_rows.sort(key=lambda x: (not x["suspect"], x["host"], x["name"]))

ear_fields = ["path", "name", "host", "sha256", "signer", "signed", "verdict", "suspect"]
with (OUT / "ear.csv").open("w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=ear_fields, extrasaction="ignore")
    w.writeheader()
    for row in ear_rows:
        w.writerow(row)

ear_json = {
    "case_id": CASE,
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "derivation": "MCP exec_registry_get returned count=0 for this case; "
                  "inventory derived from per-host disk.json/memory.json findings "
                  "(sha256 IOC + PE name/path attribution).",
    "ear_count": len(ear_rows),
    "suspect_count": sum(1 for r in ear_rows if r["suspect"]),
    "executables": ear_rows,
}
(OUT / "ear.json").write_text(json.dumps(ear_json, indent=2))

print(json.dumps({
    "ioc_count": len(ioc_rows),
    "ioc_tally": ioc_json["tally"],
    "malicious_hashes": malicious_hashes,
    "ear_count": len(ear_rows),
    "ear_suspect": ear_json["suspect_count"],
    "files": [str(OUT / f) for f in ("iocs.csv", "iocs.json", "iocs-stix.json", "ear.csv", "ear.json")],
}, indent=2))
