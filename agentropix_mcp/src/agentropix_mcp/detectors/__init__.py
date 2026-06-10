"""Specialist SwarmAgent-shaped detectors.

* :mod:`yara_hunt` — YARAHuntAgent — signature-based detection of Cobalt
  Strike beacon stagers (T1055 via YARA rule match). Closes W-052-T2.
* :mod:`injection_detector` — InjectionDetector — Volatility-driven
  in-memory process injection detection (T1055.x). Closes W-052-T6.
* :mod:`t1059_001_iex_loopback_c2` — IexLoopbackC2Detector — PowerShell
  ScriptBlock IEX-loopback C2 detection (T1059.001). Closes W-205.
* :mod:`t1546_008_accessibility_ifeo_hijack` — T1546.008 IFEO accessibility-
  binary hijack detection. Closes W-204.
* :mod:`t1071_001_svchost_outbound_http` — T1071SvchostOutboundHttpDetector
  — svchost-as-source HTTP/80 callbacks to non-Microsoft public IPs
  (T1071.001). Closes W-215 (phishing-chain plan Phase 4).

All detectors follow the standard SwarmAgent contract: investigate(image)
returns list[Finding], errors return as ToolError data not exceptions,
findings publish to the shared Blackboard for HuntAgent quorum detection.
"""
