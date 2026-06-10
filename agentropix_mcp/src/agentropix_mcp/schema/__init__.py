"""Typed result schemas for SIFT MCP tool returns.

Historically each wrapper colocated its Pydantic models (``YaraReport``,
``ExtractManifest`` …). New tool families that own a non-trivial schema
surface land here so the wrapper file stays a thin protocol-driver and
the model is the single source of truth — also keeps cross-tool reuse
cheap (e.g. ``ArchiveEntry`` shape mirrors ``ExtractedFile``).
"""
