> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-004: Identity System (SPIFFE/SPIRE)

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Implemented |
| **Date** | 2026-01-02 |
| **Accepted** | 2026-01-11 |
| **Implemented** | 2026-01-14 |
| **Decision Makers** | Architecture Team |
| **Bio-Agentic Component** | MHC Tokens (Identity & Authentication) |
| **Priority** | P1 (High) |

## Context

Agentropix agents need cryptographic identity for:
- Authentication between components
- Authorization for tool access
- Audit trail attribution
- Multi-tenant isolation

The MHC Tokens component (named after Major Histocompatibility Complex in biology) handles identity presentation and verification.

### Problem Statement

We need an identity system that:
1. Provides unique, verifiable agent identities
2. Enables zero-trust communication between components
3. Supports automatic credential rotation
4. Works across distributed deployments
5. Integrates with Kubernetes and cloud providers

### Constraints

- Must work in both local development and production
- Must not require manual certificate management
- Must support service mesh patterns
- Must enable fine-grained authorization
- Prefer industry standards over custom solutions

### Assumptions

- Agents will run in containerized environments
- mTLS is the authentication standard
- Cloud deployments will use Kubernetes
- Identity needs to be attestable (prove who you are)

## Decision Drivers

1. **Zero-trust security** - Every component verifies every other
2. **Automatic rotation** - No manual certificate management
3. **Cloud native** - Works with Kubernetes, Istio, Envoy
4. **Attestation** - Cryptographic proof of identity
5. **Industry standard** - CNCF-backed, widely adopted

## Considered Options

### Option 1: SPIFFE/SPIRE

**Description:** SPIFFE (Secure Production Identity Framework for Everyone) provides workload identity standards; SPIRE is the reference implementation.

**Pros:**
- CNCF incubating project (industry standard)
- Automatic credential rotation (SVIDs)
- Works with Kubernetes, VMs, bare metal
- Integrates with Istio, Envoy, Consul
- Zero-trust by design
- No secrets in environment variables

**Cons:**
- Additional infrastructure (SPIRE server)
- Learning curve for SPIFFE concepts
- Overkill for local development

### Option 2: Kubernetes Service Accounts + mTLS

**Description:** Use native Kubernetes service accounts with a service mesh for mTLS.

**Pros:**
- Native to Kubernetes
- No additional infrastructure
- Well understood by K8s teams

**Cons:**
- Kubernetes-only (no local dev, no VMs)
- Manual certificate management without mesh
- Less flexible identity model

### Option 3: HashiCorp Vault

**Description:** Use Vault for secrets management and PKI.

**Pros:**
- Feature-rich secrets management
- Dynamic secrets generation
- PKI engine for certificates

**Cons:**
- Heavyweight for identity-only use case
- Requires Vault infrastructure
- Not designed primarily for workload identity

### Option 4: OAuth 2.0 / OIDC

**Description:** Use OAuth 2.0 tokens for agent identity.

**Pros:**
- Well understood protocol
- Many identity providers available
- Works with existing IdPs

**Cons:**
- Designed for user identity, not workload identity
- Token-based (not certificate-based)
- Requires IdP infrastructure

### Option 5: Custom JWT-Based Identity

**Description:** Build custom identity system using signed JWTs.

**Pros:**
- Full control over implementation
- Simple to understand
- No external dependencies

**Cons:**
- Must build certificate management
- Must implement rotation
- Security responsibility on us
- Not industry standard

## Decision

We will use **SPIFFE/SPIRE** because:

1. **Industry standard**: CNCF-backed, used by Uber, Pinterest, Square
2. **Zero-trust**: Designed for service-to-service authentication
3. **Automatic rotation**: SVIDs rotate without manual intervention
4. **Flexibility**: Works in K8s, VMs, and local development
5. **Bio-agentic alignment**: MHC tokens = SPIFFE Verifiable Identity Documents (SVIDs)

### Implementation Approach

```python
from dataclasses import dataclass
from py_spiffe import SpiffeClient
from cryptography.x509 import Certificate

@dataclass
class MHCToken:
    """Agent identity token (SVID wrapper)."""
    spiffe_id: str           # spiffe://agentropix.io/agent/{agent_id}
    certificate: Certificate  # X.509 SVID
    private_key: bytes        # Private key for mTLS
    bundle: bytes             # Trust bundle for verification
    ttl_seconds: int         # Time until rotation needed

class MHCTokenProvider:
    """Provides and validates agent identities."""

    def __init__(self, spire_socket: str = "/tmp/spire-agent/public/api.sock"):
        self.client = SpiffeClient(spire_socket)

    async def get_identity(self) -> MHCToken:
        """Fetch current agent's SVID."""
        svid = await self.client.fetch_x509_svid()
        return MHCToken(
            spiffe_id=str(svid.spiffe_id),
            certificate=svid.certificate,
            private_key=svid.private_key,
            bundle=svid.bundle,
            ttl_seconds=svid.hint_ttl
        )

    async def verify_peer(self, peer_cert: Certificate) -> bool:
        """Verify another agent's identity."""
        bundle = await self.client.fetch_x509_bundles()
        # Verify certificate chain against trust bundle
        return bundle.verify(peer_cert)

    def authorize(self, peer_spiffe_id: str, action: str) -> bool:
        """Check if peer is authorized for action."""
        # Authorization rules based on SPIFFE ID
        rules = {
            "spiffe://agentropix.io/component/oncologist": ["terminate", "inspect"],
            "spiffe://agentropix.io/component/lineage": ["checkpoint", "restore"],
            "spiffe://agentropix.io/agent/*": ["execute", "tool_call"],
        }
        for pattern, allowed_actions in rules.items():
            if self._match_spiffe_id(peer_spiffe_id, pattern):
                return action in allowed_actions
        return False
```

### SPIFFE ID Structure

```
spiffe://agentropix.io/
├── agent/
│   ├── {session-id}          # Individual agent instance
│   └── {session-id}/sub/{n}  # Sub-agents spawned
├── component/
│   ├── oncologist            # The Oncologist safety system
│   ├── lineage               # LineageManager
│   ├── telomere              # Telomere Budget tracker
│   └── atp                   # ATP Economy
├── tool/
│   ├── filesystem            # File access tool
│   ├── shell                 # Shell execution tool
│   └── web                   # Web access tool
└── service/
    ├── llm-proxy             # LLM API proxy
    └── memory                # Zep memory service
```

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    SPIRE Server                          │
│  (Issues SVIDs, manages registration entries)           │
└─────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
    ┌────────────┐  ┌────────────┐  ┌────────────┐
    │SPIRE Agent │  │SPIRE Agent │  │SPIRE Agent │
    │  (Node 1)  │  │  (Node 2)  │  │  (Node 3)  │
    └────────────┘  └────────────┘  └────────────┘
           │               │               │
    ┌──────┴──────┐ ┌──────┴──────┐ ┌──────┴──────┐
    │ Agent Pod   │ │ Oncologist  │ │ Lineage     │
    │  (SVID)     │ │   (SVID)    │ │   (SVID)    │
    └─────────────┘ └─────────────┘ └─────────────┘
```

### Local Development Mode

For local development, use a simplified identity:

```python
class LocalMHCTokenProvider:
    """Simplified identity for local development."""

    def __init__(self, agent_id: str):
        self.spiffe_id = f"spiffe://localhost/agent/{agent_id}"
        # Use self-signed certificate
        self._generate_self_signed()

    async def get_identity(self) -> MHCToken:
        return MHCToken(
            spiffe_id=self.spiffe_id,
            certificate=self._cert,
            private_key=self._key,
            bundle=self._cert.public_bytes(),  # Self-trust
            ttl_seconds=3600
        )
```

## Consequences

### Positive

- **Zero-trust security**: All components verify identity
- **Automatic rotation**: SVIDs rotate without downtime
- **Attestation**: Cryptographic proof of identity
- **Audit trail**: Every action attributable to identity
- **Multi-tenant ready**: Isolation via SPIFFE IDs

### Negative

- **Infrastructure**: Requires SPIRE server deployment
  - *Mitigation*: Use managed SPIRE (Otterize, AWS SPIRE)
- **Complexity**: New concepts for team to learn
  - *Mitigation*: Internal training, documentation
- **Local development**: Full SPIRE overkill locally
  - *Mitigation*: LocalMHCTokenProvider for development

### Neutral

- SPIFFE is becoming the standard for workload identity
- Integration with Istio/Envoy available if needed later

## Bio-Agentic Mapping

| Agentropix Component | SPIFFE/SPIRE Concept |
|---------------------|---------------------|
| MHC Token | SVID (SPIFFE Verifiable Identity Document) |
| Identity Presentation | Certificate in mTLS handshake |
| Trust Bundle | CA certificates for verification |
| Authorization | SPIFFE ID-based access control |
| Token Rotation | SVID automatic renewal |

## Validation Criteria

- [ ] SPIRE server deployed and healthy (deferred to production deployment)
- [x] Agent SVIDs issued and rotating (MHC tokens implemented locally)
- [ ] mTLS working between components (deferred to production deployment)
- [x] Authorization rules enforced (MHC permission verification in trust/mhc_tokens.py)
- [x] Local development mode functional (LocalMHCTokenProvider pattern used)
- [x] Audit logging of identity operations (structlog integration throughout)

## References

- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/)
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [py-spiffe Library](https://github.com/spiffe/py-spiffe)
- Security Patterns: `docs/impl-patterns/security.md`
- Related: [ADR-008: Safety Architecture](ADR-008-safety-architecture.md)

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-02 | Claude Code | Initial draft |
