#!/bin/bash
#
# Kubernetes Security Quick Audit Script
# Performs rapid security assessment using kubectl and jq
#
# Usage: ./quick_audit.sh [--kubeconfig PATH] [--context NAME]
#

set -e

# Parse arguments
KUBECTL_ARGS=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --kubeconfig)
            KUBECTL_ARGS="$KUBECTL_ARGS --kubeconfig $2"
            shift 2
            ;;
        --context)
            KUBECTL_ARGS="$KUBECTL_ARGS --context $2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Helper function
kubectl_cmd() {
    kubectl $KUBECTL_ARGS "$@"
}

echo "=============================================="
echo "  Kubernetes Security Quick Audit"
echo "=============================================="
echo ""

# Cluster info
echo "[INFO] Cluster Context: $(kubectl_cmd config current-context 2>/dev/null || echo 'unknown')"
echo "[INFO] Kubernetes Version: $(kubectl_cmd version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion' || echo 'unknown')"
echo ""

# 1. Privileged Pods
echo "=== [1] PRIVILEGED PODS ==="
PRIV_PODS=$(kubectl_cmd get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.spec.containers[]?.securityContext?.privileged == true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")
if [ -n "$PRIV_PODS" ]; then
    echo "⚠️  CRITICAL: Privileged pods found:"
    echo "$PRIV_PODS" | head -10
    PRIV_COUNT=$(echo "$PRIV_PODS" | wc -l)
    [ "$PRIV_COUNT" -gt 10 ] && echo "   ... and $((PRIV_COUNT - 10)) more"
else
    echo "✅ No privileged pods found"
fi
echo ""

# 2. Host Namespace Access
echo "=== [2] HOST NAMESPACE ACCESS ==="
HOST_ACCESS=$(kubectl_cmd get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.spec.hostNetwork == true or .spec.hostPID == true or .spec.hostIPC == true) | "\(.metadata.namespace)/\(.metadata.name): hostNetwork=\(.spec.hostNetwork // false), hostPID=\(.spec.hostPID // false), hostIPC=\(.spec.hostIPC // false)"' 2>/dev/null || echo "")
if [ -n "$HOST_ACCESS" ]; then
    echo "⚠️  HIGH: Pods with host namespace access:"
    echo "$HOST_ACCESS" | head -10
else
    echo "✅ No pods with host namespace access"
fi
echo ""

# 3. Cluster-Admin Bindings
echo "=== [3] CLUSTER-ADMIN BINDINGS ==="
ADMIN_BINDINGS=$(kubectl_cmd get clusterrolebindings -o json 2>/dev/null | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .subjects[]? | "\(.kind): \(.namespace // "cluster-scoped")/\(.name)"' 2>/dev/null || echo "")
if [ -n "$ADMIN_BINDINGS" ]; then
    echo "ℹ️  Subjects with cluster-admin:"
    echo "$ADMIN_BINDINGS"
else
    echo "✅ No custom cluster-admin bindings"
fi
echo ""

# 4. Wildcard RBAC Permissions
echo "=== [4] WILDCARD RBAC PERMISSIONS ==="
WILDCARD_ROLES=$(kubectl_cmd get clusterroles -o json 2>/dev/null | jq -r '.items[] | select(.rules[]? | (.resources[]? == "*" and .verbs[]? == "*")) | .metadata.name' 2>/dev/null | grep -v "^system:" || echo "")
if [ -n "$WILDCARD_ROLES" ]; then
    echo "⚠️  CRITICAL: ClusterRoles with wildcard permissions:"
    echo "$WILDCARD_ROLES"
else
    echo "✅ No non-system wildcard ClusterRoles"
fi
echo ""

# 5. Namespaces Without Network Policies
echo "=== [5] NAMESPACES WITHOUT NETWORK POLICIES ==="
NO_NETPOL=""
for ns in $(kubectl_cmd get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    # Skip system namespaces
    if [[ "$ns" == "kube-system" || "$ns" == "kube-public" || "$ns" == "kube-node-lease" ]]; then
        continue
    fi
    count=$(kubectl_cmd get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l || echo 0)
    if [ "$count" -eq 0 ]; then
        NO_NETPOL="$NO_NETPOL $ns"
    fi
done
if [ -n "$NO_NETPOL" ]; then
    echo "⚠️  HIGH: Namespaces without NetworkPolicies:"
    echo "$NO_NETPOL" | tr ' ' '\n' | grep -v '^$'
else
    echo "✅ All user namespaces have NetworkPolicies"
fi
echo ""

# 6. Pods Using Latest/Untagged Images
echo "=== [6] IMAGES WITH :latest OR NO TAG ==="
LATEST_IMAGES=$(kubectl_cmd get pods -A -o json 2>/dev/null | jq -r '.items[].spec.containers[].image' 2>/dev/null | grep -E ':latest$|^[^:]+$' | sort -u || echo "")
if [ -n "$LATEST_IMAGES" ]; then
    echo "⚠️  MEDIUM: Images using :latest or no tag:"
    echo "$LATEST_IMAGES" | head -10
    IMG_COUNT=$(echo "$LATEST_IMAGES" | wc -l)
    [ "$IMG_COUNT" -gt 10 ] && echo "   ... and $((IMG_COUNT - 10)) more"
else
    echo "✅ All images use specific tags"
fi
echo ""

# 7. Pods Without Resource Limits
echo "=== [7] PODS WITHOUT RESOURCE LIMITS ==="
NO_LIMITS=$(kubectl_cmd get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.spec.containers[] | .resources.limits == null) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | sort -u || echo "")
if [ -n "$NO_LIMITS" ]; then
    LIMIT_COUNT=$(echo "$NO_LIMITS" | wc -l)
    echo "⚠️  LOW: $LIMIT_COUNT pods without resource limits"
    echo "$NO_LIMITS" | head -5
    [ "$LIMIT_COUNT" -gt 5 ] && echo "   ... and $((LIMIT_COUNT - 5)) more"
else
    echo "✅ All pods have resource limits"
fi
echo ""

# 8. Secrets Access in RBAC
echo "=== [8] CLUSTERROLES WITH SECRETS ACCESS ==="
SECRETS_ACCESS=$(kubectl_cmd get clusterroles -o json 2>/dev/null | jq -r '.items[] | select(.rules[]? | .resources[]? == "secrets" and (.verbs[]? == "get" or .verbs[]? == "list" or .verbs[]? == "*")) | .metadata.name' 2>/dev/null | grep -v "^system:" || echo "")
if [ -n "$SECRETS_ACCESS" ]; then
    echo "⚠️  HIGH: Non-system ClusterRoles with secrets access:"
    echo "$SECRETS_ACCESS"
else
    echo "✅ No non-system ClusterRoles with cluster-wide secrets access"
fi
echo ""

# 9. Pod Security Standards
echo "=== [9] POD SECURITY STANDARDS ENFORCEMENT ==="
NO_PSS=""
for ns in $(kubectl_cmd get ns -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
    if [[ "$ns" == "kube-system" || "$ns" == "kube-public" || "$ns" == "kube-node-lease" ]]; then
        continue
    fi
    enforce=$(kubectl_cmd get ns "$ns" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null || echo "")
    if [ -z "$enforce" ]; then
        NO_PSS="$NO_PSS $ns"
    fi
done
if [ -n "$NO_PSS" ]; then
    echo "⚠️  MEDIUM: Namespaces without PSS enforcement:"
    echo "$NO_PSS" | tr ' ' '\n' | grep -v '^$'
else
    echo "✅ All user namespaces have PSS enforcement"
fi
echo ""

# 10. ServiceAccount Auto-Mount
echo "=== [10] SERVICEACCOUNT TOKEN AUTO-MOUNT ==="
AUTOMOUNT=$(kubectl_cmd get pods -A -o json 2>/dev/null | jq -r '.items[] | select(.spec.automountServiceAccountToken != false and .spec.serviceAccountName != null and .spec.serviceAccountName != "default") | "\(.metadata.namespace)/\(.metadata.name): \(.spec.serviceAccountName)"' 2>/dev/null | head -10 || echo "")
if [ -n "$AUTOMOUNT" ]; then
    echo "ℹ️  Pods with auto-mounted SA tokens (first 10):"
    echo "$AUTOMOUNT"
else
    echo "✅ No pods with auto-mounted non-default SA tokens"
fi
echo ""

# Summary
echo "=============================================="
echo "  AUDIT SUMMARY"
echo "=============================================="
echo ""
echo "Review findings above and address:"
echo "  1. CRITICAL issues immediately"
echo "  2. HIGH issues within 7 days"
echo "  3. MEDIUM issues within 30 days"
echo "  4. LOW issues in backlog"
echo ""
echo "For detailed audit, run: python k8s_security_audit.py --output report.md"
