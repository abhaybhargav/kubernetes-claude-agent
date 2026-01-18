# RBAC Security Analysis Reference

Deep-dive guide for analyzing Kubernetes RBAC misconfigurations and privilege escalation paths.

## Table of Contents

1. [Privilege Escalation Paths](#privilege-escalation-paths)
2. [Dangerous Verbs and Resources](#dangerous-verbs-and-resources)
3. [Detection Queries](#detection-queries)
4. [Common Misconfigurations](#common-misconfigurations)
5. [Remediation Patterns](#remediation-patterns)

## Privilege Escalation Paths

### Path 1: Create Pods → Cluster Admin

If a subject can create pods, they can mount the node's service account token and escalate:

```yaml
# Dangerous: pod creation allows mounting host service accounts
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create"]
```

**Detection:**
```bash
kubectl auth can-i create pods --all-namespaces --list
```

### Path 2: Pods/Exec → Container Breakout

Exec into existing privileged containers to access host:

```yaml
# Dangerous: exec allows command execution in running containers
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
```

**Detection:**
```bash
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | select(.resources[]? == "pods/exec" and .verbs[]? == "create")) | .metadata.name'
```

### Path 3: Secrets Access → Credential Theft

Reading secrets provides service account tokens, TLS certs, passwords:

```yaml
# Dangerous: secrets contain sensitive credentials
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list", "watch"]
```

**Detection:**
```bash
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | select(.resources[]? == "secrets" and (.verbs[]? == "get" or .verbs[]? == "list"))) | .metadata.name'
```

### Path 4: ServiceAccount Token Mount → Impersonation

Auto-mounted tokens allow workloads to impersonate their SA:

**Detection:**
```bash
# Find pods with auto-mounted tokens
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.automountServiceAccountToken != false) | "\(.metadata.namespace)/\(.metadata.name)"'
```

### Path 5: Impersonate Users/Groups → Arbitrary Access

Impersonation rights allow assuming any identity:

```yaml
# Critical: impersonation = arbitrary privilege
rules:
- apiGroups: [""]
  resources: ["users", "groups", "serviceaccounts"]
  verbs: ["impersonate"]
```

**Detection:**
```bash
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | select(.verbs[]? == "impersonate")) | .metadata.name'
```

### Path 6: Escalate Verb → Bypass RBAC Restrictions

The `escalate` verb allows granting permissions the user doesn't have:

```yaml
# Critical: bypasses RBAC self-restrictions
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles", "roles"]
  verbs: ["escalate"]
```

### Path 7: Bind Verb → Grant Arbitrary Roles

The `bind` verb allows binding any role:

```yaml
# Critical: can bind cluster-admin to self
rules:
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterrolebindings", "rolebindings"]
  verbs: ["bind"]
```

## Dangerous Verbs and Resources

### Critical Risk Combinations

| Verb | Resource | Risk |
|------|----------|------|
| `*` | `*` | **Critical** - Full cluster access |
| `create` | `pods` | **Critical** - Container escape possible |
| `create` | `pods/exec` | **High** - Execute in existing containers |
| `get/list` | `secrets` | **High** - Credential theft |
| `impersonate` | `users/groups/serviceaccounts` | **Critical** - Identity hijacking |
| `escalate` | `roles/clusterroles` | **Critical** - Bypass RBAC |
| `bind` | `rolebindings/clusterrolebindings` | **Critical** - Grant arbitrary roles |
| `create` | `serviceaccounts/token` | **High** - Token generation |
| `update/patch` | `pods` | **Medium** - Modify running workloads |
| `delete` | `pods` | **Medium** - Denial of service |

### Resource Wildcards

Wildcard resources are always suspicious:

```bash
# Find wildcard resources
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.resources[]? == "*") | .metadata.name'

# Find wildcard verbs
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.verbs[]? == "*") | .metadata.name'
```

## Detection Queries

### Comprehensive RBAC Dump

```bash
# Export all RBAC for offline analysis
kubectl get clusterroles,clusterrolebindings,roles,rolebindings -A -o yaml > rbac_dump.yaml
```

### Find High-Privilege ClusterRoles

```bash
kubectl get clusterroles -o json | jq -r '
  .items[] | 
  select(
    .rules[]? | 
    ((.resources[]? == "*") or (.verbs[]? == "*") or 
     (.resources[]? == "secrets") or 
     (.resources[]? == "pods/exec"))
  ) | 
  .metadata.name
'
```

### Map ServiceAccounts to Permissions

```bash
# For each SA, show bound roles
for sa in $(kubectl get sa -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\n"}{end}'); do
  ns=$(echo $sa | cut -d/ -f1)
  name=$(echo $sa | cut -d/ -f2)
  echo "=== $sa ==="
  kubectl get rolebindings,clusterrolebindings -A -o json | jq -r --arg ns "$ns" --arg name "$name" '
    .items[] | 
    select(.subjects[]? | select(.kind == "ServiceAccount" and .name == $name and (.namespace == $ns or .namespace == null))) |
    "  \(.roleRef.kind)/\(.roleRef.name)"
  '
done
```

### Find Subjects with Cluster-Admin Equivalent

```bash
kubectl get clusterrolebindings -o json | jq -r '
  .items[] | 
  select(.roleRef.name == "cluster-admin" or .roleRef.name == "admin") |
  .subjects[]? | 
  "\(.kind): \(.namespace // "cluster-scoped")/\(.name)"
'
```

## Common Misconfigurations

### 1. Default ServiceAccount Abuse

Many pods use the `default` SA which often has excessive permissions:

```bash
# Find pods using default SA
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.serviceAccountName == "default" or .spec.serviceAccountName == null) | "\(.metadata.namespace)/\(.metadata.name)"'
```

**Fix:** Create dedicated SAs with minimal permissions.

### 2. Overly Broad Group Bindings

Binding to `system:authenticated` or `system:serviceaccounts` grants access to too many subjects:

```bash
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.subjects[]?.name == "system:authenticated" or .subjects[]?.name == "system:serviceaccounts") | .metadata.name'
```

### 3. Namespace-Scoped Secrets Without Restriction

Roles granting secrets access in a namespace apply to ALL secrets there:

```yaml
# Bad: Access to all secrets in namespace
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]

# Better: Specific secret names
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["my-specific-secret"]
  verbs: ["get"]
```

### 4. Aggregated ClusterRoles

Check for roles using aggregation that might inherit dangerous permissions:

```bash
kubectl get clusterroles -o json | jq -r '.items[] | select(.aggregationRule != null) | .metadata.name'
```

## Remediation Patterns

### Principle of Least Privilege

1. Use namespaced Roles instead of ClusterRoles when possible
2. Specify `resourceNames` to limit to specific resources
3. Avoid wildcard verbs and resources
4. Create dedicated ServiceAccounts per workload

### Disable Token Auto-Mount

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
automountServiceAccountToken: false
```

### Time-Limited Admin Access

Use impersonation with audit logging instead of direct cluster-admin binding:

```bash
# Admin uses impersonation (audited) instead of direct binding
kubectl --as=admin-sa --as-group=system:masters get pods
```

### Role Template: Read-Only Namespace Access

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: namespace-reader
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
# Explicitly exclude secrets
```
