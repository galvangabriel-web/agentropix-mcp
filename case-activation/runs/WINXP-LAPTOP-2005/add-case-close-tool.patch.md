# Patch: add a `case_close` MCP tool (status=closed/archived + ended_at)

Adds the missing lifecycle step. The data model already supports it
(`CaseRecord.status` = active|closed|archived, `ended_at`); this wires a
function + MCP registration that actually writes those values, upserting
the `agentropix-cases` doc in place (`_id == case_id`) and preserving all
other fields. Mirrors `case_init`/`case_status` conventions:
keyword-friendly, graceful indexer degradation, rate-limited, ToolError.

Apply against `galvangabriel-web/agentropix-mcp` @ HEAD:
`git apply add-case-close-tool.patch` (or follow the anchored blocks below).

---

## 1. `agentropix_mcp/src/agentropix_mcp/wrappers/case_lifecycle.py`

**Append at end of file** (after the `evidence_register` return):

```python
# --- Tool: case_close ------------------------------------------------- #


class CaseCloseResult(BaseModel):
    """Result of ``case_close``."""

    case_id: str
    case: CaseRecord | None  # the mutated record (None when not found / no client)
    indexed: bool
    error: str = ""


_CLOSE_STATUSES = ("closed", "archived")


async def case_close(
    case_id: str | None = None,
    *,
    examiner_id: str,
    status: str = "closed",
    reason: str = "",
    ended_at: str | None = None,
    indexer_client: Any = None,
) -> CaseCloseResult:
    """SIFT-W-289: close (or archive) an existing case.

    Reads the ``agentropix-cases`` doc, flips ``status`` to ``closed``
    (default) or ``archived`` and stamps ``ended_at``, then upserts the
    doc back in place (``_id == case_id``) so every other field is
    preserved. Idempotent: re-closing an already-closed case re-stamps
    the same terminal state. Closure metadata (who/when/why) is recorded
    under ``payload.closure`` for chain-of-custody.

    Args:
        case_id: optional; resolves the active-case pointer when ``None``.
        examiner_id: required; recorded in ``payload.closure.closed_by``.
        status: terminal state — ``"closed"`` (default) or ``"archived"``.
        reason: optional free-text disposition note.
        ended_at: optional ISO-8601 UTC override; defaults to now.
        indexer_client: injected ``IndexerClient`` (required to read+write).

    Returns:
        :class:`CaseCloseResult` with the mutated record when found.
    """
    if not examiner_id or not isinstance(examiner_id, str):
        raise ValueError("examiner_id must be a non-empty string")
    if status not in _CLOSE_STATUSES:
        raise ValueError(f"status must be one of {_CLOSE_STATUSES}; got {status!r}")

    if case_id is None:
        case_id = get_active_case_id()
        if case_id is None:
            raise ValueError("no active case; pass case_id= or call case_activate()")
    _validate_case_id(case_id)

    if indexer_client is None:
        return CaseCloseResult(
            case_id=case_id,
            case=None,
            indexed=False,
            error="indexer_client not injected",
        )

    # 1) Load the existing case doc (must exist to close it).
    try:
        search_resp = await indexer_client.search(
            CASES_INDEX,
            {"query": {"term": {"_id": case_id}}},
            size=1,
        )
    except Exception as exc:
        return CaseCloseResult(
            case_id=case_id,
            case=None,
            indexed=False,
            error=f"{type(exc).__name__}: {exc}",
        )
    hits = (search_resp.get("hits") or {}).get("hits") or []
    if not hits:
        raise ValueError(f"no agentropix-cases doc for {case_id!r}; nothing to close")
    try:
        record = CaseRecord.model_validate(hits[0].get("_source") or {})
    except Exception as exc:
        raise ValueError(f"malformed case doc for {case_id!r}: {exc}") from exc

    # 2) Mutate terminal state + audit trail (preserve prior payload).
    record.status = status
    record.ended_at = ended_at or _utc_now_iso()
    record.payload = {
        **record.payload,
        "closure": {
            "closed_by": examiner_id,
            "closed_at": record.ended_at,
            "status": status,
            "reason": reason,
        },
    }

    # 3) Upsert back in place (_id == case_id), graceful on outage.
    #    Preserve the original creation @timestamp (started_at), matching
    #    case_init, so closing doesn't reorder the doc by ingest time.
    indexed = False
    error = ""
    doc = record.model_dump()
    doc["@timestamp"] = record.started_at
    try:
        await indexer_client.index_one(CASES_INDEX, doc, doc_id=case_id)
        indexed = True
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        logger.warning("case_close: indexer write failed for %s: %s", case_id, exc)

    logger.info("case_close: %s -> %s (by %s)", case_id, status, examiner_id)
    return CaseCloseResult(case_id=case_id, case=record, indexed=indexed, error=error)
```

---

## 2. `agentropix_mcp/src/agentropix_mcp/server.py`

**2a. Imports** — add `CaseCloseResult` to the model group and a new alias
import (place beside the other `case_lifecycle` imports, ~lines 36–50):

```python
from agentropix_mcp.wrappers.case_lifecycle import (
    CaseRecord,
    CaseStatusReport,
    CaseCloseResult,          # <-- add
    EvidenceRegisterResult,
)
from agentropix_mcp.wrappers.case_lifecycle import (
    case_close as _case_close_impl,   # <-- add this whole group
)
```

**2b. Wrapper** — insert **immediately before** the line
`@traced("evidence_register")` (i.e. right after `mcp_case_status`):

```python
@traced("case_close")
async def mcp_case_close(
    examiner_id: str,
    case_id: str | None = None,
    status: str = "closed",
    reason: str = "",
    ended_at: str | None = None,
) -> CaseCloseResult | ToolError:
    """Close (or archive) an existing case: set status + ended_at."""
    rate_err = _rate_limiter.check("case_close")
    if rate_err:
        return ToolError(tool="case_close", error=rate_err)
    client = _get_indexer_client()
    try:
        return await _case_close_impl(
            case_id,
            examiner_id=examiner_id,
            status=status,
            reason=reason,
            ended_at=ended_at,
            indexer_client=client,
        )
    except (ValueError, FileNotFoundError) as exc:
        return ToolError(tool="case_close", error=str(exc))
```

---

## 3. `agentropix_mcp/src/agentropix_mcp/fastmcp_app.py`

**Insert immediately before** the `@app.tool()` / `async def evidence_register(`
block (right after the `case_status` tool):

```python
    @app.tool()
    async def case_close(
        examiner_id: str,
        case_id: str | None = None,
        status: str = "closed",
        reason: str = "",
        ended_at: str | None = None,
    ) -> dict:
        """Close (or archive) an existing case.

        Flips the ``agentropix-cases`` doc ``status`` to ``closed``
        (default) or ``archived`` and stamps ``ended_at``, upserting in
        place so all other fields are preserved. Resolves the active-case
        pointer when ``case_id`` is ``None``. Closure metadata is recorded
        under ``payload.closure`` for chain-of-custody.

        Args:
            examiner_id: required; recorded as the closer.
            case_id: optional slug; defaults to the active case.
            status: ``"closed"`` (default) or ``"archived"``.
            reason: optional disposition note.
            ended_at: optional ISO-8601 UTC override; defaults to now.
        """
        result = await _inner.mcp_case_close(
            examiner_id=examiner_id,
            case_id=case_id,
            status=status,
            reason=reason,
            ended_at=ended_at,
        )
        return result.model_dump()
```

---

## 4. Test (suggested) — `agentropix_mcp/tests/unit/test_case_close.py`

```python
import pytest
from agentropix_mcp.wrappers.case_lifecycle import case_close, CaseRecord


class _FakeIndexer:
    def __init__(self, doc):
        self._doc = doc
        self.written = None

    async def search(self, index, body, size=1):
        if self._doc is None:
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [{"_source": self._doc}]}}

    async def index_one(self, index, doc, doc_id=None):
        self.written = (index, doc, doc_id)


def _seed(case_id="C1"):
    return CaseRecord(
        case_id=case_id, case_name="t", examiner_id="e",
        started_at="2026-01-01T00:00:00+00:00",
    ).model_dump()


@pytest.mark.asyncio
async def test_case_close_sets_status_and_ended_at():
    idx = _FakeIndexer(_seed())
    res = await case_close("C1", examiner_id="victor", reason="benign",
                           indexer_client=idx)
    assert res.indexed and res.case.status == "closed"
    assert res.case.ended_at is not None
    assert res.case.payload["closure"]["closed_by"] == "victor"
    # upsert keeps _id == case_id
    assert idx.written[2] == "C1"


@pytest.mark.asyncio
async def test_case_close_missing_doc_raises():
    with pytest.raises(ValueError):
        await case_close("NOPE", examiner_id="v", indexer_client=_FakeIndexer(None))


@pytest.mark.asyncio
async def test_case_close_bad_status_raises():
    with pytest.raises(ValueError):
        await case_close("C1", examiner_id="v", status="deleted",
                         indexer_client=_FakeIndexer(_seed()))
```

---

## Notes
- **Why read-modify-upsert** (not a partial `_update`): keeps the wrapper
  using the same `indexer_client.index_one(..., doc_id=case_id)` surface as
  `case_init`; no new client method required. If `IndexerClient` later grows
  a partial-update method, step 3 can switch to it.
- **`case_status` already reads `status`/`ended_at`**, so it reflects the
  closed state immediately — no reader change needed.
- **No approval gate**: closing is a lifecycle action, not a finding, so it
  intentionally does not route through the W-286 draft-gate / sidecar.
- After applying: `pytest agentropix_mcp/tests/unit/test_case_close.py` and
  restart the MCP server so the new tool registers.
