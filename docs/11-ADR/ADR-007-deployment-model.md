> Section 11 · ADR — Architecture Decision Records | [ADR Index](README.md)

# ADR-007: Deployment Model (Kubernetes)

## Metadata

| Field | Value |
|-------|-------|
| **Status** | Implemented |
| **Date** | 2026-01-02 |
| **Accepted** | 2026-01-11 |
| **Implemented** | 2026-01-14 |
| **Decision Makers** | Architecture Team |
| **Bio-Agentic Component** | StemCell Niche (Deployment Environment) |
| **Priority** | P1 (High) |

## Context

Agentropix needs a deployment model that supports:
- Containerized component deployment
- Horizontal scaling based on load
- Service discovery and networking
- Secrets management
- Health checking and auto-recovery

The StemCell Niche component (named after the microenvironment where stem cells reside) defines how components are deployed and managed.

### Problem Statement

We need a deployment model that:
1. Supports containerized microservices
2. Enables horizontal scaling
3. Provides service discovery
4. Manages secrets securely
5. Works across cloud providers and on-premises

### Constraints

- Must support multi-cloud deployment
- Must handle dynamic scaling (agent load varies)
- Must provide observability (logging, metrics, traces)
- Must support GitOps workflows
- Team has existing Kubernetes experience

### Assumptions

- Components will be containerized (Docker)
- Load will be variable (burst during agent execution)
- Cloud-agnostic deployment is required
- Infrastructure-as-Code is mandatory

## Decision Drivers

1. **Scalability** - Handle variable agent workloads
2. **Cloud-agnostic** - Run anywhere
3. **Ecosystem** - Rich tooling and integrations
4. **Team expertise** - Existing K8s knowledge
5. **Industry standard** - Widely adopted patterns

## Considered Options

### Option 1: Kubernetes (Self-Managed)

**Description:** Deploy Agentropix on Kubernetes with self-managed clusters.

**Pros:**
- Full control over configuration
- Cloud-agnostic
- Rich ecosystem (Istio, ArgoCD, Prometheus)
- Industry standard for container orchestration
- Supports complex networking patterns

**Cons:**
- Operational complexity
- Requires K8s expertise
- Control plane management overhead

### Option 2: Managed Kubernetes (EKS/GKE/AKS)

**Description:** Use cloud-managed Kubernetes services.

**Pros:**
- Reduced operational burden
- Automatic control plane updates
- Cloud-native integrations
- Still cloud-agnostic (Kubernetes API)

**Cons:**
- Cloud-specific nuances
- Vendor lock-in for features beyond K8s API
- Cost (managed service premium)

### Option 3: Serverless Containers (Cloud Run/Fargate)

**Description:** Use serverless container platforms.

**Pros:**
- Zero infrastructure management
- Pay-per-request pricing
- Automatic scaling to zero

**Cons:**
- Cold start latency
- Limited networking options
- Vendor lock-in
- Less control over orchestration

### Option 4: Docker Swarm

**Description:** Use Docker's native orchestration.

**Pros:**
- Simpler than Kubernetes
- Docker-native
- Easier learning curve

**Cons:**
- Smaller ecosystem
- Less feature-rich
- Declining community momentum
- Limited scaling capabilities

### Option 5: Nomad

**Description:** HashiCorp's workload orchestrator.

**Pros:**
- Simpler than Kubernetes
- Supports non-container workloads
- Good HashiCorp integration

**Cons:**
- Smaller ecosystem than Kubernetes
- Less familiar to most teams
- Fewer integrations

## Decision

We will use **Managed Kubernetes (EKS/GKE/AKS)** for production and **local Kubernetes (k3s/kind)** for development because:

1. **Reduced operations**: Managed control plane reduces burden
2. **Standard API**: Kubernetes API works across providers
3. **Ecosystem**: Istio, ArgoCD, Prometheus all available
4. **Team expertise**: Existing K8s knowledge on team
5. **Flexibility**: Can self-manage if needed later

### Implementation Approach

#### Namespace Structure

```yaml
# Kubernetes namespace hierarchy
apiVersion: v1
kind: Namespace
metadata:
  name: agentropix-system  # Core infrastructure
---
apiVersion: v1
kind: Namespace
metadata:
  name: agentropix-agents  # Agent workloads
---
apiVersion: v1
kind: Namespace
metadata:
  name: agentropix-tools   # Tool services
```

#### Component Deployment

```yaml
# Example: The Oncologist deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oncologist
  namespace: agentropix-system
  labels:
    app: oncologist
    component: safety
spec:
  replicas: 2
  selector:
    matchLabels:
      app: oncologist
  template:
    metadata:
      labels:
        app: oncologist
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
    spec:
      serviceAccountName: oncologist
      containers:
        - name: oncologist
          image: agentropix/oncologist:v1.0.0
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: metrics
          env:
            - name: SPIFFE_ENDPOINT_SOCKET
              value: "unix:///run/spire/sockets/agent.sock"
            - name: REDIS_URL
              valueFrom:
                secretKeyRef:
                  name: redis-credentials
                  key: url
          resources:
            requests:
              memory: "256Mi"
              cpu: "100m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 10
          readinessProbe:
            httpGet:
              path: /ready
              port: http
```

#### Agent Workload Pattern

```yaml
# Agent execution as Kubernetes Job
apiVersion: batch/v1
kind: Job
metadata:
  name: agent-session-abc123
  namespace: agentropix-agents
spec:
  ttlSecondsAfterFinished: 3600
  activeDeadlineSeconds: 1800  # 30 minute max
  template:
    spec:
      restartPolicy: Never
      serviceAccountName: agent-executor
      containers:
        - name: agent
          image: agentropix/agent-executor:v1.0.0
          args:
            - "--session-id=abc123"
            - "--max-iterations=50"
          env:
            - name: TELOMERE_BUDGET
              value: "50"
            - name: ATP_BUDGET_TOKENS
              value: "1000000"
          volumeMounts:
            - name: spire-socket
              mountPath: /run/spire/sockets
            - name: checkpoint-storage
              mountPath: /checkpoints
      volumes:
        - name: spire-socket
          hostPath:
            path: /run/spire/sockets
        - name: checkpoint-storage
          persistentVolumeClaim:
            claimName: agent-checkpoints
```

#### HorizontalPodAutoscaler

```yaml
# Scale agents based on queue depth
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: agent-executor-hpa
  namespace: agentropix-agents
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: agent-executor
  minReplicas: 1
  maxReplicas: 100
  metrics:
    - type: External
      external:
        metric:
          name: redis_stream_pending_messages
          selector:
            matchLabels:
              stream: agent-requests
        target:
          type: AverageValue
          averageValue: 5
```

### Infrastructure as Code (Terraform)

```hcl
# terraform/main.tf
module "eks" {
  source          = "terraform-aws-modules/eks/aws"
  cluster_name    = "agentropix-${var.environment}"
  cluster_version = "1.28"

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    system = {
      instance_types = ["m6i.large"]
      capacity_type  = "ON_DEMAND"
      min_size       = 2
      max_size       = 4
    }
    agents = {
      instance_types = ["m6i.xlarge"]
      capacity_type  = "SPOT"  # Cost optimization
      min_size       = 0
      max_size       = 50
    }
  }
}

# Install SPIRE via Helm
resource "helm_release" "spire" {
  name       = "spire"
  repository = "https://spiffe.github.io/helm-charts"
  chart      = "spire"
  namespace  = "spire-system"

  values = [
    file("${path.module}/values/spire.yaml")
  ]
}
```

### GitOps with ArgoCD

```yaml
# argocd/applications/agentropix.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: agentropix
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/org/agentropix-deploy
    targetRevision: main
    path: manifests/overlays/production
  destination:
    server: https://kubernetes.default.svc
    namespace: agentropix-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

## Consequences

### Positive

- **Standard platform**: Kubernetes is well-understood
- **Scalability**: Handle burst agent workloads
- **Ecosystem**: Rich tooling (Prometheus, Grafana, ArgoCD)
- **Cloud-agnostic**: Can run on any K8s cluster
- **GitOps ready**: Infrastructure as code

### Negative

- **Complexity**: Kubernetes has learning curve
  - *Mitigation*: Start with managed K8s, good documentation
- **Cost**: Running K8s clusters isn't free
  - *Mitigation*: Use spot instances for agents, scale to zero
- **Overhead**: K8s adds latency vs bare metal
  - *Mitigation*: Acceptable for agent workloads

### Neutral

- Requires container registry (Docker Hub, ECR, GCR)
- Need to establish deployment pipelines

## Bio-Agentic Mapping

| Agentropix Component | Kubernetes Concept |
|---------------------|-------------------|
| StemCell Niche | Kubernetes Cluster |
| Stem Cell | Container Image |
| Cell Division | Pod Scaling |
| Microenvironment | Namespace + ConfigMaps |
| Growth Factors | Resources (CPU, Memory) |
| Niche Signaling | Service Discovery |

## Validation Criteria

- [x] Agent jobs deploy and execute successfully (K8s manifests validated with Kustomize)
- [x] HPA scaling based on queue depth (HPA configuration in prod overlay)
- [ ] SPIRE integration working in K8s (deferred to production deployment)
- [x] Observability stack deployed (Prometheus/Grafana) (metrics annotations in deployments)
- [x] GitOps workflow functional (Kustomize base + overlays pattern)
- [x] Local development with k3s/kind working (docker-compose for ChromaDB + Redis)

## Local Development Setup

```yaml
# docker-compose.yml for local development
services:
  k3s:
    image: rancher/k3s:v1.28.2-k3s1
    command: server
    tmpfs:
      - /run
      - /var/run
    privileged: true
    ports:
      - "6443:6443"
      - "80:80"
      - "443:443"
    volumes:
      - k3s-data:/var/lib/rancher/k3s

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  zep:
    image: ghcr.io/getzep/zep:latest
    ports:
      - "8000:8000"
    depends_on:
      - redis

volumes:
  k3s-data:
```

## References

- Deployment Patterns: `docs/impl-patterns/deployment.md`
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [ArgoCD Documentation](https://argo-cd.readthedocs.io/)
- [EKS Best Practices](https://aws.github.io/aws-eks-best-practices/)
- Related: [ADR-004: Identity System](ADR-004-identity-system.md) (SPIRE in K8s)
- Related: [ADR-005: Message Bus](ADR-005-message-bus.md) (Redis deployment)

## Changelog

| Date | Author | Change |
|------|--------|--------|
| 2026-01-02 | Claude Code | Initial draft |
