---
name: k8s-security-audit
description: Comprehensive Kubernetes cluster security audit and assessment. Use when Claude needs to analyze a Kubernetes cluster for security vulnerabilities, misconfigurations, RBAC issues, network policies, pod security, secrets management, and compliance gaps. Triggers on requests to audit, assess, review, or analyze Kubernetes security, including CIS benchmark checks, privilege escalation paths, container security, ingress/egress analysis, and generating security posture reports. Requires kubectl access with administrative permissions.
---

# Kubernetes Security Audit

Perform comprehensive security audits of Kubernetes clusters, identifying vulnerabilities, misconfigurations, and compliance gaps.

## Prerequisites

- kubectl configured with administrative access (kubeconfig in `~/.kube/config` or specified via `KUBECONFIG`)
- Cluster admin or equivalent read permissions across all namespaces
- Python 3.8+ with `pyyaml`, `tabulate` dependencies (optional, for report generation)

## Audit Workflow Overview

1. **Cluster Access Validation** - Verify connectivity and permissions
2. **Cluster Information Gathering** - Version, nodes, namespaces inventory
3. **RBAC Analysis** - Roles, bindings, privilege escalation paths
4. **Pod Security Assessment** - Container privileges, security contexts
5. **Network Policy Review** - Ingress/egress rules, default deny policies
6. **Secrets Management Audit** - Encryption, exposure risks
7. **Workload Configuration Review** - Resource limits, probes, images
8. **CIS Benchmark Checks** - Alignment with Kubernetes security benchmarks
9. **Report Generation** - Findings with severity and remediation

## Step 1: Cluster Access Validation

Verify kubectl connectivity and permissions before proceeding:

```bash
# Test cluster connectivity
kubectl cluster-info

# Verify admin access
kubectl auth can-i '*' '*' --all-namespaces

# Check current context
kubectl config current-context

# List available contexts
kubectl config get-contexts
```

If `kubectl auth can-i '*' '*'` returns `no`, document limited permissions and adjust audit scope accordingly.

## Step 2: Cluster Information Gathering

Collect cluster metadata for context:

```bash
# Kubernetes version (check for EOL or vulnerable versions)
kubectl version --output=yaml

# Node inventory with roles
kubectl get nodes -o wide

# Namespace inventory
kubectl get namespaces

# API resources available
kubectl api-resources --verbs=list -o name

# Cluster events (last 100, look for security-relevant)
kubectl get events -A --sort-by='.lastTimestamp' | tail -100
```

### Version Security Check

Compare against [references/k8s_cve_versions.md](references/k8s_cve_versions.md) for known vulnerabilities in the running version.

## Step 3: RBAC Analysis

See [references/rbac_analysis.md](references/rbac_analysis.md) for detailed RBAC security patterns.

### Extract RBAC Configuration

```bash
# ClusterRoles (focus on high-privilege)
kubectl get clusterroles -o yaml > /tmp/clusterroles.yaml

# ClusterRoleBindings
kubectl get clusterrolebindings -o yaml > /tmp/clusterrolebindings.yaml

# Roles per namespace
kubectl get roles -A -o yaml > /tmp/roles.yaml

# RoleBindings per namespace
kubectl get rolebindings -A -o yaml > /tmp/rolebindings.yaml

# ServiceAccounts
kubectl get serviceaccounts -A -o yaml > /tmp/serviceaccounts.yaml
```

### High-Risk RBAC Patterns to Flag

| Risk | Pattern | Detection |
|------|---------|-----------|
| **Critical** | Wildcard permissions (`*` on resources/verbs) | `grep -E "resources:.*\*\|verbs:.*\*"` |
| **Critical** | Secrets access cluster-wide | ClusterRole with `get/list secrets` |
| **High** | Pod exec permissions | Verb `create` on `pods/exec` |
| **High** | ServiceAccount token mounting | `automountServiceAccountToken: true` |
| **High** | Impersonation rights | Verb on `users`, `groups`, `serviceaccounts` impersonate |
| **Medium** | Excessive namespace admin | RoleBinding to `admin` or `edit` for broad groups |

### Quick RBAC Risk Detection

```bash
# Find wildcard cluster permissions
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]?.resources[]? == "*" or .rules[]?.verbs[]? == "*") | .metadata.name'

# Find who can exec into pods
kubectl auth can-i create pods/exec --all-namespaces --list

# Find who can read secrets cluster-wide
kubectl auth can-i get secrets --all-namespaces --list

# ServiceAccounts with cluster-admin binding
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .subjects[]? | select(.kind == "ServiceAccount") | "\(.namespace)/\(.name)"'
```

## Step 4: Pod Security Assessment

### Gather Pod Security Contexts

```bash
# All pods with security context details
kubectl get pods -A -o json | jq -r '
  .items[] | 
  "\(.metadata.namespace)/\(.metadata.name): privileged=\(.spec.containers[].securityContext.privileged // false), runAsRoot=\(.spec.containers[].securityContext.runAsNonRoot // "unset"), hostNetwork=\(.spec.hostNetwork // false), hostPID=\(.spec.hostPID // false)"
'
```

### Critical Security Flags

| Flag | Risk | Query |
|------|------|-------|
| `privileged: true` | **Critical** - Full host access | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.containers[].securityContext.privileged == true)'` |
| `hostNetwork: true` | **High** - Network namespace escape | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.hostNetwork == true)'` |
| `hostPID: true` | **High** - Process namespace escape | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.hostPID == true)'` |
| `hostPath` volumes | **High** - Host filesystem access | `kubectl get pods -A -o json \| jq '.items[] \| select(.spec.volumes[]?.hostPath != null)'` |
| `runAsUser: 0` | **Medium** - Container runs as root | Check `securityContext.runAsUser` |
| Missing `readOnlyRootFilesystem` | **Low** - Writable container filesystem | Default is writable |

### Pod Security Standards Compliance

Check namespace labels for Pod Security Standards enforcement:

```bash
# Check PSS labels on namespaces
kubectl get namespaces -o json | jq -r '.items[] | "\(.metadata.name): enforce=\(.metadata.labels["pod-security.kubernetes.io/enforce"] // "none"), audit=\(.metadata.labels["pod-security.kubernetes.io/audit"] // "none")"'
```

Expected: Production namespaces should have `restricted` or `baseline` enforcement.

## Step 5: Network Policy Review

See [references/network_policy_analysis.md](references/network_policy_analysis.md) for network security patterns.

### Inventory Network Policies

```bash
# All NetworkPolicies
kubectl get networkpolicies -A -o yaml > /tmp/netpols.yaml

# Namespaces without any NetworkPolicy
kubectl get namespaces -o name | while read ns; do
  ns_name=${ns#namespace/}
  count=$(kubectl get networkpolicies -n "$ns_name" --no-headers 2>/dev/null | wc -l)
  if [ "$count" -eq 0 ]; then
    echo "No NetworkPolicy: $ns_name"
  fi
done
```

### Network Security Checklist

- [ ] Default deny ingress policy exists in production namespaces
- [ ] Default deny egress policy exists (prevents data exfiltration)
- [ ] Policies use specific podSelectors (not empty `{}`)
- [ ] Egress to metadata API (169.254.169.254) is blocked
- [ ] Cross-namespace communication is explicitly allowed only where needed

### Default Deny Policy Template

Namespaces lacking this pattern are exposed:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## Step 6: Secrets Management Audit

### Secrets Inventory

```bash
# Count secrets by namespace and type
kubectl get secrets -A -o json | jq -r '.items | group_by(.metadata.namespace) | .[] | "\(.[0].metadata.namespace): \(length) secrets"'

# Identify secret types
kubectl get secrets -A -o json | jq -r '.items | group_by(.type) | .[] | "\(.[0].type): \(length)"'

# Find secrets mounted in pods
kubectl get pods -A -o json | jq -r '.items[] | .spec.volumes[]? | select(.secret != null) | .secret.secretName' | sort -u
```

### Secrets Security Checklist

- [ ] Encryption at rest enabled (`kubectl get apiservices v1 -o yaml` - check for EncryptionConfiguration)
- [ ] No secrets in environment variables (prefer volume mounts)
- [ ] External secrets manager integration (e.g., Vault, AWS Secrets Manager, External Secrets Operator)
- [ ] Secrets not stored in ConfigMaps
- [ ] RBAC restricts secret access appropriately

### Check for Secrets in ConfigMaps (Anti-pattern)

```bash
# Look for base64-encoded or password-like values in ConfigMaps
kubectl get configmaps -A -o json | jq -r '.items[] | select(.data != null) | select(.data | to_entries[] | .key | test("password|secret|key|token|credential"; "i")) | "\(.metadata.namespace)/\(.metadata.name)"'
```

## Step 7: Workload Configuration Review

### Image Security

```bash
# List all container images
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | sort -u

# Find images without explicit tags (using :latest or no tag)
kubectl get pods -A -o json | jq -r '.items[].spec.containers[] | select(.image | test(":latest$") or (test(":") | not)) | .image' | sort -u

# Find images from untrusted registries
kubectl get pods -A -o json | jq -r '.items[].spec.containers[].image' | grep -vE "^(gcr.io|docker.io|quay.io|registry.k8s.io|your-registry.com)" | sort -u
```

### Resource Limits Check

```bash
# Pods without resource limits
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[] | .resources.limits == null) | "\(.metadata.namespace)/\(.metadata.name)"'

# Pods without resource requests
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[] | .resources.requests == null) | "\(.metadata.namespace)/\(.metadata.name)"'
```

### Liveness/Readiness Probes

```bash
# Pods without health probes
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[] | (.livenessProbe == null) and (.readinessProbe == null)) | "\(.metadata.namespace)/\(.metadata.name)"'
```

## Step 8: CIS Benchmark Quick Checks

See [references/cis_benchmarks.md](references/cis_benchmarks.md) for complete CIS Kubernetes Benchmark mapping.

### Control Plane Security (if accessible)

```bash
# Check API server flags (if running as pod)
kubectl get pods -n kube-system -l component=kube-apiserver -o yaml | grep -E "anonymous-auth|enable-admission-plugins|audit-log"

# Check etcd encryption
kubectl get pods -n kube-system -l component=etcd -o yaml | grep -E "client-cert-auth|peer-client-cert-auth"
```

### Worker Node Security

```bash
# Kubelet configuration (requires node access or kubelet API)
# Check for --anonymous-auth=false, --authorization-mode not AlwaysAllow
kubectl get nodes -o json | jq -r '.items[].status.nodeInfo'
```

## Step 9: Generate Audit Report

Use [scripts/generate_report.py](scripts/generate_report.py) to compile findings:

```bash
python scripts/generate_report.py --kubeconfig ~/.kube/config --output audit_report.md
```

### Report Structure

```markdown
# Kubernetes Security Audit Report

**Cluster**: {context_name}
**Date**: {timestamp}
**Auditor**: Claude AI

## Executive Summary

| Category | Critical | High | Medium | Low |
|----------|----------|------|--------|-----|
| RBAC | X | X | X | X |
| Pod Security | X | X | X | X |
| Network | X | X | X | X |
| Secrets | X | X | X | X |
| Workloads | X | X | X | X |

**Overall Risk Level**: {Critical/High/Medium/Low}

## Cluster Information
- Kubernetes Version: {version}
- Nodes: {count}
- Namespaces: {count}

## Critical Findings
{findings with remediation}

## High-Risk Findings
{findings with remediation}

## Detailed Findings by Category

### RBAC Analysis
{detailed findings}

### Pod Security
{detailed findings}

### Network Policies
{detailed findings}

### Secrets Management
{detailed findings}

### Workload Configuration
{detailed findings}

## Remediation Priority Matrix
{ordered list by risk and effort}

## Appendix
- Raw data references
- Commands used
```

## Quick Audit Commands

Run this script for a rapid security snapshot:

```bash
#!/bin/bash
echo "=== K8s Security Quick Audit ==="

echo -e "\n[1] Privileged Pods:"
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n[2] Pods with hostNetwork/hostPID:"
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true) | "\(.metadata.namespace)/\(.metadata.name)"'

echo -e "\n[3] Cluster-admin ServiceAccounts:"
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .subjects[]? | "\(.kind): \(.namespace // "cluster")/\(.name)"'

echo -e "\n[4] Namespaces without NetworkPolicies:"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  [ $(kubectl get netpol -n $ns --no-headers 2>/dev/null | wc -l) -eq 0 ] && echo "$ns"
done

echo -e "\n[5] Pods with latest/untagged images:"
kubectl get pods -A -o json | jq -r '.items[].spec.containers[] | select(.image | test(":latest$") or (test(":") | not)) | .image' | sort -u

echo -e "\n[6] Pods without resource limits:"
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[] | .resources.limits == null) | "\(.metadata.namespace)/\(.metadata.name)"' | head -20
```

## Reference Files

- **[references/rbac_analysis.md](references/rbac_analysis.md)**: Deep-dive RBAC security patterns and privilege escalation paths
- **[references/network_policy_analysis.md](references/network_policy_analysis.md)**: Network policy security patterns and templates
- **[references/cis_benchmarks.md](references/cis_benchmarks.md)**: CIS Kubernetes Benchmark controls mapping
- **[references/k8s_cve_versions.md](references/k8s_cve_versions.md)**: Known CVEs by Kubernetes version

## Report Template

Use [assets/audit_report_template.md](assets/audit_report_template.md) for consistent report formatting.

## Common Remediation Patterns

| Finding | Remediation |
|---------|-------------|
| Privileged pods | Add `securityContext.privileged: false`, use capabilities instead |
| Missing NetworkPolicies | Apply default-deny, then allow required traffic |
| Overly permissive RBAC | Follow least-privilege, use namespaced Roles |
| Secrets in env vars | Mount as volumes with `defaultMode: 0400` |
| Latest image tags | Pin to specific digests or semantic versions |
| Missing resource limits | Define CPU/memory limits and requests |
| No Pod Security Standards | Add `pod-security.kubernetes.io/*` labels to namespaces |
