# Network Policy Security Analysis Reference

Comprehensive guide for analyzing Kubernetes network policies and identifying network segmentation gaps.

## Table of Contents

1. [Network Policy Fundamentals](#network-policy-fundamentals)
2. [Security Assessment Queries](#security-assessment-queries)
3. [Common Gaps](#common-gaps)
4. [Secure Policy Templates](#secure-policy-templates)
5. [CNI Considerations](#cni-considerations)

## Network Policy Fundamentals

### Default Behavior

Without NetworkPolicies, Kubernetes allows **all pod-to-pod traffic** within and across namespaces. This is the most critical network security gap.

### Policy Types

- **Ingress**: Controls incoming traffic to selected pods
- **Egress**: Controls outgoing traffic from selected pods

A policy with empty `policyTypes` only affects the types with rules defined.

## Security Assessment Queries

### Find Unprotected Namespaces

```bash
# Namespaces with zero NetworkPolicies
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  count=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "UNPROTECTED: $ns"
  else
    echo "Protected ($count policies): $ns"
  fi
done
```

### Check for Default Deny Policies

```bash
# Find namespaces with default deny ingress
kubectl get networkpolicies -A -o json | jq -r '
  .items[] | 
  select(.spec.podSelector == {} and .spec.policyTypes[]? == "Ingress" and (.spec.ingress == null or .spec.ingress == [])) |
  "\(.metadata.namespace): default-deny-ingress"
'

# Find namespaces with default deny egress
kubectl get networkpolicies -A -o json | jq -r '
  .items[] | 
  select(.spec.podSelector == {} and .spec.policyTypes[]? == "Egress" and (.spec.egress == null or .spec.egress == [])) |
  "\(.metadata.namespace): default-deny-egress"
'
```

### Identify Overly Permissive Policies

```bash
# Policies allowing all ingress (empty ingress array = allow all)
kubectl get networkpolicies -A -o json | jq -r '
  .items[] | 
  select(.spec.ingress == [{}] or (.spec.ingress[0]? | keys | length == 0)) |
  "\(.metadata.namespace)/\(.metadata.name): allows all ingress"
'

# Policies with namespace-wide selectors (empty podSelector)
kubectl get networkpolicies -A -o json | jq -r '
  .items[] | 
  select(.spec.ingress[]?.from[]?.namespaceSelector == {}) |
  "\(.metadata.namespace)/\(.metadata.name): allows from all namespaces"
'
```

### Check Egress to Metadata API

Cloud metadata APIs (169.254.169.254) are common attack targets:

```bash
# Look for explicit blocks or lack of egress policies
kubectl get networkpolicies -A -o json | jq -r '
  .items[] | 
  select(.spec.policyTypes[]? == "Egress") |
  select(.spec.egress[]?.to[]?.ipBlock.except[]? == "169.254.169.254/32" | not) |
  "\(.metadata.namespace)/\(.metadata.name): may allow metadata API access"
'
```

### Map Pod-to-Policy Coverage

```bash
# For each namespace, show which pods are covered by policies
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  echo "=== Namespace: $ns ==="
  policies=$(kubectl get networkpolicies -n "$ns" -o json)
  pods=$(kubectl get pods -n "$ns" -o json)
  
  echo "Policies:"
  echo "$policies" | jq -r '.items[].metadata.name'
  
  echo "Pods and coverage:"
  echo "$pods" | jq -r '.items[] | "\(.metadata.name): \(.metadata.labels)"'
done
```

## Common Gaps

### Gap 1: No Default Deny

**Risk:** Any pod can communicate with any other pod.

**Detection:**
```bash
# Count namespaces without default deny
kubectl get networkpolicies -A -o json | jq '[.items[] | select(.spec.podSelector == {} and .spec.policyTypes[]? == "Ingress")] | length'
```

### Gap 2: DNS Egress Not Considered

Blocking all egress breaks DNS resolution:

**Detection:**
```bash
# Find egress policies that might block DNS
kubectl get networkpolicies -A -o json | jq -r '
  .items[] | 
  select(.spec.policyTypes[]? == "Egress") |
  select(.spec.egress == null or (.spec.egress[]?.to[]? | select(.namespaceSelector.matchLabels["kubernetes.io/metadata.name"] == "kube-system") | not)) |
  "\(.metadata.namespace)/\(.metadata.name): may block DNS"
'
```

### Gap 3: Metadata API Exposed

**Risk:** Pods can query cloud metadata for credentials.

**Secure egress must block:**
```yaml
spec:
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32  # AWS/GCP metadata
        - 169.254.170.2/32    # ECS task metadata
```

### Gap 4: Cross-Namespace Access

**Risk:** Compromised pod in one namespace accesses another.

**Detection:**
```bash
# Find policies allowing cross-namespace ingress
kubectl get networkpolicies -A -o json | jq -r '
  .items[] | 
  select(.spec.ingress[]?.from[]?.namespaceSelector != null) |
  "\(.metadata.namespace)/\(.metadata.name)"
'
```

### Gap 5: Service Mesh Bypass

If using a service mesh, ensure NetworkPolicies complement mesh policies and don't create gaps when mesh sidecar is absent.

## Secure Policy Templates

### Template 1: Default Deny All (Namespace)

Apply to every namespace as baseline:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: <namespace>
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

### Template 2: Allow DNS Egress

Required for pods to resolve service names:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: <namespace>
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53
```

### Template 3: Allow Same-Namespace Traffic

Allow pods in same namespace to communicate:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: <namespace>
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector: {}
```

### Template 4: Block Metadata API

Critical for cloud environments:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: block-metadata-api
  namespace: <namespace>
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
```

### Template 5: Web Application (Frontend → Backend → DB)

```yaml
# Frontend: allow ingress from internet, egress to backend
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: frontend-policy
spec:
  podSelector:
    matchLabels:
      tier: frontend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - {} # Allow from anywhere (use Ingress controller)
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - port: 8080
---
# Backend: only from frontend, only to database
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
spec:
  podSelector:
    matchLabels:
      tier: backend
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: frontend
    ports:
    - port: 8080
  egress:
  - to:
    - podSelector:
        matchLabels:
          tier: database
    ports:
    - port: 5432
---
# Database: only from backend, no egress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: database-policy
spec:
  podSelector:
    matchLabels:
      tier: database
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          tier: backend
    ports:
    - port: 5432
  egress: [] # No egress allowed
```

## CNI Considerations

### CNI Support Matrix

| CNI | NetworkPolicy Support | Notes |
|-----|----------------------|-------|
| Calico | Full | Best policy support, includes GlobalNetworkPolicy |
| Cilium | Full | eBPF-based, CiliumNetworkPolicy extensions |
| Weave | Full | Standard NetworkPolicy |
| Flannel | **None** | Requires Calico overlay for policies |
| AWS VPC CNI | Partial | Use Calico for policies |
| Azure CNI | Full | Native support |
| GKE | Full | Requires enabling network policy |

### Check CNI Type

```bash
# Check CNI in use
kubectl get pods -n kube-system -o wide | grep -E "calico|cilium|weave|flannel"

# For managed clusters
kubectl get daemonsets -n kube-system
```

### CNI-Specific Extensions

**Calico GlobalNetworkPolicy:**
```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-metadata-api
spec:
  selector: all()
  types:
  - Egress
  egress:
  - action: Deny
    destination:
      nets:
      - 169.254.169.254/32
```

**Cilium CiliumNetworkPolicy:**
```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: l7-policy
spec:
  endpointSelector:
    matchLabels:
      app: api
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: frontend
    toPorts:
    - ports:
      - port: "80"
      rules:
        http:
        - method: GET
          path: "/api/.*"
```
