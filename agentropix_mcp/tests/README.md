# agentropix_mcp — Constraint-Bypass Test Evidence

These suites are the published evidence that the Thymus evidence gate and the
tool wrappers hold up under adversarial and fault-injected inputs. They were
copied from the main repo's hardening test corpus and rewritten against the
`agentropix_mcp` package layout (`agentropix_sift.mcp_server.*` → `agentropix_mcp.*`).

Run from the package root:

```
PYTHONPATH=src python3 -m pytest tests/ -q
```

## Suites

### `unit/test_thymus_policy.py` — Evidence-gate policy
Locks the read/write allowlist contract: reads permitted only from evidence
zones, **all** writes rejected (evidence integrity is architectural), audit-log
ring buffer, env-var allowlist wiring, allowed-directory-itself matching,
YARA tooling zone, disambiguated reject reason codes, and symlink-target
validation (escapes to `/etc`, `/proc`, `/dev`, chained and relative-traversal
symlinks all rejected).

### `unit/test_w108_w109_thymus_hardening.py` — Evidence-gate bypass attempts
The constraint-bypass core, from `hardtest` adversarial-input runs:
- **Encoded traversal (W-108):** URL-encoded `%2e%2e` (lower/upper/mixed case)
  must be caught after URL-decode, before `normpath` collapses it away.
  Single-pass decode is the documented contract.
- **PATH_MAX guard (W-109):** paths over 4096 bytes rejected with a typed
  `REJECT_PATH_TOO_LONG`, evaluated before URL-decode / normpath.
- **No-regression:** null bytes, `/proc`, `/etc/shadow`, and double-slash
  normalization all still rejected/normalized correctly.

### `chaos/test_fault_paths.py` — Fault-path resilience
Mock-based fault injection (no real forensic tools required) verifying cleanup
and error-propagation paths that fixed real production bugs:
- Plaso tmpdir cleanup on timeout / success, and `os.killpg`
  `ProcessLookupError` swallowed (W-022, R2).
- bulk_extractor EWF auto-mount, missing-`ewfmount` clear error, mount-tmpdir
  cleanup on BE failure, and `ewf1`-never-appears handling (W-041, R1, R3).
- extract_files traversal / NUL-byte paths land in `rejected[]` before any
  subprocess fires.
- memory-monitor task cancellation, and Volatility / YARA subprocess kill on
  timeout (R4, R5a, R5b).

All `chaos` tests are tagged `pytest.mark.chaos`.

## Notes
- Test-local fixtures were inlined where present; no fixtures pulling in
  modules absent from `src/agentropix_mcp` were required, so no test classes
  were trimmed.
- Absolute operator paths in fixture data were scrubbed to `~/`-relative form.
