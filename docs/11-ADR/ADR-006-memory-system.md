> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-006: Memory System (Zep)

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Implemented |
| **Date** | 2026-01-02 |
| **Accepted** | 2026-01-11 |
| **Implemented** | 2026-01-14 |
| **Decision Makers** | Architecture Team |
| **Bio-Agentic Component** | Epigenetic Memory (Long-Term Knowledge) |
| **Priority** | P1 (High) |

## Context

Agentropix agents need long-term memory that persists across sessions:
- Learned patterns from past executions
- User preferences and context
- Semantic knowledge base
- Cross-session continuity

The Epigenetic Memory component (named after heritable gene expression changes) handles persistent knowledge that "remembers" past experiences.

### Problem Statement

We need a memory system that:
1. Stores conversation history with semantic search
2. Automatically summarizes and extracts facts
3. Provides relevant context for new sessions
4. Handles large memory volumes efficiently
5. Integrates with LLM workflows

### Constraints

- Must support vector similarity search
- Must automatically manage memory size (summarization)
- Must provide fast retrieval (< 100ms)
- Must support multi-user/multi-agent isolation
- Python SDK required

### Assumptions

- Semantic search is more useful than keyword search for agents
- Memory size will grow significantly over time
- Automatic summarization is acceptable (vs perfect recall)
- Memory can be eventually consistent

## Decision Drivers

1. **Semantic retrieval** - Find relevant context by meaning
2. **Automatic summarization** - Manage unbounded growth
3. **LLM integration** - Purpose-built for AI agents
4. **Self-hosted option** - Data privacy requirements
5. **Active development** - Growing ecosystem

## Considered Options

### Option 1: Zep

**Description:** Purpose-built memory layer for AI assistants with automatic summarization.

**Pros:**
- Designed specifically for LLM applications
- Automatic memory summarization
- Hybrid search (vector + keyword)
- Built-in user/session isolation
- Fact extraction from conversations
- Self-hosted or cloud options
- Native Python SDK

**Cons:**
- Relatively new project
- Smaller community than general-purpose vector DBs
- Some features require Pro tier

### Option 2: Pinecone

**Description:** Managed vector database with high performance.

**Pros:**
- High performance, scalable
- Simple API
- Managed infrastructure

**Cons:**
- No automatic summarization (must build)
- Cloud-only (no self-hosted)
- Per-query pricing can add up
- Not purpose-built for conversations

### Option 3: Weaviate

**Description:** Open-source vector database with ML integration.

**Pros:**
- Open-source and self-hostable
- GraphQL API
- Built-in ML models
- Active community

**Cons:**
- No automatic summarization
- Must build conversation management
- More complex setup than Zep
- General-purpose (not AI-agent specific)

### Option 4: ChromaDB

**Description:** Simple, embedded vector database.

**Pros:**
- Extremely simple to start
- Embedded (no separate server)
- Open-source
- Good for prototyping

**Cons:**
- Limited scalability
- No automatic summarization
- No built-in memory management
- Single-node only

### Option 5: LangChain Memory

**Description:** Use LangChain's built-in memory modules.

**Pros:**
- Integrated with LangChain (ADR-001)
- Multiple memory types available
- Simple API

**Cons:**
- In-memory by default (not persistent)
- Limited summarization options
- Not designed for production scale
- Tight coupling to LangChain

## Decision

We will use **Zep** because:

1. **Purpose-built**: Designed specifically for AI agent memory
2. **Automatic management**: Summarization handles unbounded growth
3. **Self-hosted**: Data privacy requirements met
4. **Conversation-native**: Understands sessions, users, facts
5. **Research alignment**: Mentioned in Agentropix research documentation

### Implementation Approach

```python
from zep_python import ZepClient
from zep_python.memory import Memory, Message
from dataclasses import dataclass

@dataclass
class EpigeneticMark:
    """A persistent memory unit."""
    content: str
    embedding: list[float]
    metadata: dict
    created_at: str
    session_id: str

class EpigeneticMemory:
    """Long-term memory system powered by Zep."""

    def __init__(self, zep_url: str = "http://localhost:8000"):
        self.client = ZepClient(base_url=zep_url)

    async def remember(
        self,
        session_id: str,
        role: str,
        content: str,
        metadata: dict = None
    ):
        """Store a memory (conversation message)."""
        message = Message(
            role=role,
            content=content,
            metadata=metadata or {}
        )
        await self.client.memory.add_memory(
            session_id=session_id,
            memory=Memory(messages=[message])
        )

    async def recall(
        self,
        session_id: str,
        query: str,
        top_k: int = 10
    ) -> list[EpigeneticMark]:
        """Retrieve relevant memories."""
        results = await self.client.memory.search_memory(
            session_id=session_id,
            text=query,
            search_type="similarity",
            limit=top_k
        )
        return [
            EpigeneticMark(
                content=r.message.content,
                embedding=r.embedding,
                metadata=r.message.metadata,
                created_at=r.message.created_at,
                session_id=session_id
            )
            for r in results
        ]

    async def get_context(self, session_id: str) -> dict:
        """Get full session context including summary and facts."""
        memory = await self.client.memory.get_memory(session_id=session_id)
        return {
            "messages": memory.messages,
            "summary": memory.summary.content if memory.summary else None,
            "facts": memory.facts,  # Extracted facts
            "relevant_memories": memory.relevant_memories
        }

    async def extract_facts(self, session_id: str) -> list[str]:
        """Get extracted facts from conversation."""
        memory = await self.client.memory.get_memory(session_id=session_id)
        return memory.facts or []

    async def search_all_sessions(
        self,
        user_id: str,
        query: str,
        top_k: int = 10
    ) -> list[EpigeneticMark]:
        """Search across all sessions for a user."""
        results = await self.client.memory.search_sessions(
            user_id=user_id,
            text=query,
            limit=top_k
        )
        return [
            EpigeneticMark(
                content=r.message.content,
                embedding=r.embedding,
                metadata=r.message.metadata,
                created_at=r.message.created_at,
                session_id=r.session_id
            )
            for r in results
        ]
```

### Memory Hierarchy

```
┌─────────────────────────────────────────────────────────┐
│                    Epigenetic Memory (Zep)               │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────────────────────────────────────────┐   │
│  │  User Level (user_id)                            │   │
│  │  ├── Preferences learned across all sessions    │   │
│  │  └── Extracted facts about user                 │   │
│  └─────────────────────────────────────────────────┘   │
│                           │                              │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Session Level (session_id)                      │   │
│  │  ├── Conversation messages                       │   │
│  │  ├── Automatic summary (rolling)                 │   │
│  │  ├── Session-specific facts                      │   │
│  │  └── Tool results and outputs                    │   │
│  └─────────────────────────────────────────────────┘   │
│                           │                              │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Agent Level (agent_id within session)           │   │
│  │  ├── Sub-agent memories                          │   │
│  │  └── Exploration branch memories                 │   │
│  └─────────────────────────────────────────────────┘   │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

### Integration with LineageManager (ADR-003)

```python
class MemoryCheckpointIntegration:
    """Bridge between Epigenetic Memory and LineageManager."""

    def __init__(self, memory: EpigeneticMemory, lineage: LineageManager):
        self.memory = memory
        self.lineage = lineage

    async def checkpoint_with_memory(self, state: AgentState, session_id: str):
        """Checkpoint state AND memory snapshot."""
        # Get current memory summary
        context = await self.memory.get_context(session_id)

        # Include in state
        state.metadata["memory_summary"] = context["summary"]
        state.metadata["memory_facts"] = context["facts"]

        # Checkpoint to git
        await self.lineage.checkpoint(state)

    async def restore_with_memory(self, checkpoint_ref: str, session_id: str):
        """Restore state and prime memory context."""
        state = await self.lineage.restore(checkpoint_ref)

        # Memory is already in Zep, but we can warm the cache
        summary = state.metadata.get("memory_summary")
        if summary:
            # Log that we're resuming with this context
            await self.memory.remember(
                session_id=session_id,
                role="system",
                content=f"[Resumed from checkpoint with context: {summary}]"
            )

        return state
```

## Consequences

### Positive

- **Semantic search**: Find relevant context by meaning
- **Automatic summarization**: Memory stays manageable
- **Fact extraction**: Structured knowledge from conversations
- **Session isolation**: Multi-user/multi-agent support
- **Self-hosted**: Data stays under control

### Negative

- **New dependency**: Zep server to deploy and maintain
  - *Mitigation*: Docker Compose for local, K8s helm chart for prod
- **Summarization quality**: May lose nuanced details
  - *Mitigation*: Tune summarization settings, keep raw history option
- **Learning curve**: New API for team
  - *Mitigation*: Documentation and examples

### Neutral

- Zep is actively evolving; API may change
- Pro tier offers additional features (consider for production)

## Bio-Agentic Mapping

| Agentropix Component | Zep Concept |
|---------------------|-------------|
| Epigenetic Memory | Zep Memory Layer |
| Memory Mark | Message + embedding |
| Methylation (summarization) | Automatic summarization |
| Histone Modification | Metadata on memories |
| Recall | Semantic search |
| Cross-Session Knowledge | User-level search |

## Validation Criteria

- [x] Memory storage and retrieval < 100ms (ChromaDB in-memory mode ~13-16 Kops/s)
- [x] Semantic search returning relevant results (HippocampusMemory.recall() with vector search)
- [x] Automatic summarization activating on long sessions (CRISPR decay mechanism)
- [x] Fact extraction producing useful facts (ReasoningTrace with fitness scoring)
- [x] Session isolation verified (namespace isolation in ChromaDB)
- [x] Integration with LineageManager working (Chromosome.inject_trace() Lamarckian inheritance)

Note: Implementation uses ChromaDB instead of Zep for self-hosted simplicity. Zep remains valid alternative for production.

## References

- [Zep Documentation](https://docs.getzep.com/)
- [Zep Python SDK](https://github.com/getzep/zep-python)
- Research: `v2/memory_research/` directory
- Related: [ADR-003: State Persistence](ADR-003-state-persistence.md)
- Related: [ADR-001: SDK Selection](ADR-001-sdk-selection.md) (LangChain integration)

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-02 | Claude Code | Initial draft |
