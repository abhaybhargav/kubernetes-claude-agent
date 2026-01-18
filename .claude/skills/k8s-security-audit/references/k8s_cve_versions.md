# Kubernetes CVE Reference by Version

Quick reference for known critical CVEs affecting Kubernetes versions. Update this list periodically.

## Table of Contents

1. [Critical CVEs](#critical-cves)
2. [Version EOL Status](#version-eol-status)
3. [Detection Queries](#detection-queries)
4. [Upgrade Recommendations](#upgrade-recommendations)

## Critical CVEs

### CVE-2024-9486 (Critical) - VM Image Builder Credential Exposure
- **Affected**: Kubernetes Image Builder ≤ 0.1.37
- **Risk**: Default credentials in VM images allow SSH root access
- **Fixed**: Image Builder 0.1.38+
- **Check**: Review VM images built with affected versions

### CVE-2024-3177 (High) - Secrets Bypass in Encrypted Volumes
- **Affected**: 1.26.0-1.26.14, 1.27.0-1.27.11, 1.28.0-1.28.7, 1.29.0-1.29.2
- **Risk**: Bypass secret encryption at rest
- **Fixed**: 1.26.15, 1.27.12, 1.28.8, 1.29.3

### CVE-2023-5528 (High) - Windows Node Privilege Escalation
- **Affected**: All versions using Windows nodes
- **Risk**: Privileged container escape on Windows
- **Fixed**: 1.25.16, 1.26.11, 1.27.8, 1.28.4

### CVE-2023-3955 (High) - Windows Node Command Injection
- **Affected**: 1.25.0-1.25.14, 1.26.0-1.26.9, 1.27.0-1.27.6, 1.28.0-1.28.2
- **Risk**: Command injection via pod spec on Windows
- **Fixed**: 1.25.15, 1.26.10, 1.27.7, 1.28.3

### CVE-2023-2728 (High) - ServiceAccount Token Secrets Bypass
- **Affected**: 1.24.0-1.24.14, 1.25.0-1.25.10, 1.26.0-1.26.5, 1.27.0-1.27.2
- **Risk**: Access to secrets via service account tokens
- **Fixed**: 1.24.15, 1.25.11, 1.26.6, 1.27.3

### CVE-2022-3294 (High) - Node Address Verification Bypass
- **Affected**: 1.22.0-1.22.15, 1.23.0-1.23.13, 1.24.0-1.24.7, 1.25.0-1.25.3
- **Risk**: Bypass node address verification in aggregated API servers
- **Fixed**: 1.22.16, 1.23.14, 1.24.8, 1.25.4

### CVE-2022-3162 (Medium) - Unauthorized Directory Listing
- **Affected**: 1.22.0-1.22.15, 1.23.0-1.23.13, 1.24.0-1.24.7, 1.25.0-1.25.3
- **Risk**: Users can list directories in cluster file system
- **Fixed**: 1.22.16, 1.23.14, 1.24.8, 1.25.4

### CVE-2021-25749 (High) - runAsNonRoot Bypass
- **Affected**: 1.20.0-1.20.15, 1.21.0-1.21.14, 1.22.0-1.22.12, 1.23.0-1.23.9, 1.24.0-1.24.3
- **Risk**: Windows pods can bypass runAsNonRoot restriction
- **Fixed**: 1.22.13, 1.23.10, 1.24.4

### CVE-2021-25741 (High) - Symlink Exchange Attack
- **Affected**: 1.19.0-1.19.15, 1.20.0-1.20.11, 1.21.0-1.21.5, 1.22.0-1.22.2
- **Risk**: User can create symlink to escape container
- **Fixed**: 1.19.16, 1.20.12, 1.21.6, 1.22.3

### CVE-2020-8559 (Medium) - API Server Redirect Attack
- **Affected**: 1.16.0-1.16.14, 1.17.0-1.17.11, 1.18.0-1.18.7
- **Risk**: Compromised node can escalate to cluster admin
- **Fixed**: 1.16.15, 1.17.12, 1.18.8

## Version EOL Status

As of 2025, the following support windows apply:

| Version | Release Date | End of Support | Status |
|---------|--------------|----------------|--------|
| 1.32 | Dec 2024 | ~Dec 2025 | **Supported** |
| 1.31 | Aug 2024 | ~Aug 2025 | **Supported** |
| 1.30 | Apr 2024 | ~Apr 2025 | **Supported** |
| 1.29 | Dec 2023 | ~Dec 2024 | **EOL** |
| 1.28 | Aug 2023 | ~Aug 2024 | **EOL** |
| 1.27 | Apr 2023 | ~Apr 2024 | **EOL** |
| ≤1.26 | - | - | **EOL - Upgrade Immediately** |

**Note:** Kubernetes supports ~12 months per minor version. Always run supported versions.

## Detection Queries

### Check Cluster Version

```bash
# Server version
kubectl version -o json | jq -r '.serverVersion.gitVersion'

# Full version info
kubectl version --output=yaml
```

### Automated CVE Check

```bash
#!/bin/bash
VERSION=$(kubectl version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion' | sed 's/^v//')
MAJOR=$(echo $VERSION | cut -d. -f1)
MINOR=$(echo $VERSION | cut -d. -f2)
PATCH=$(echo $VERSION | cut -d. -f3)

echo "Kubernetes Version: $VERSION"
echo ""

# Check EOL
if [ "$MINOR" -lt 30 ]; then
  echo "⚠️  WARNING: Version 1.$MINOR is END OF LIFE - upgrade immediately!"
fi

# Check specific CVEs
if [ "$MINOR" -eq 26 ] && [ "$PATCH" -lt 15 ]; then
  echo "🔴 CRITICAL: Vulnerable to CVE-2024-3177 (Secrets Bypass)"
fi

if [ "$MINOR" -eq 27 ] && [ "$PATCH" -lt 12 ]; then
  echo "🔴 CRITICAL: Vulnerable to CVE-2024-3177 (Secrets Bypass)"
fi

if [ "$MINOR" -eq 28 ] && [ "$PATCH" -lt 8 ]; then
  echo "🔴 CRITICAL: Vulnerable to CVE-2024-3177 (Secrets Bypass)"
fi

if [ "$MINOR" -eq 29 ] && [ "$PATCH" -lt 3 ]; then
  echo "🔴 CRITICAL: Vulnerable to CVE-2024-3177 (Secrets Bypass)"
fi

# Check Windows nodes for Windows-specific CVEs
WINDOWS_NODES=$(kubectl get nodes -o json | jq -r '.items[] | select(.status.nodeInfo.operatingSystem == "windows") | .metadata.name')
if [ -n "$WINDOWS_NODES" ]; then
  echo ""
  echo "Windows nodes detected: $WINDOWS_NODES"
  if [ "$MINOR" -le 27 ]; then
    echo "🔴 Check CVE-2023-5528 and CVE-2023-3955 for Windows nodes"
  fi
fi
```

### Component Version Check

```bash
# All component versions
kubectl get nodes -o json | jq -r '.items[] | "\(.metadata.name): kubelet=\(.status.nodeInfo.kubeletVersion), proxy=\(.status.nodeInfo.kubeProxyVersion)"'

# Container runtime versions
kubectl get nodes -o json | jq -r '.items[] | "\(.metadata.name): \(.status.nodeInfo.containerRuntimeVersion)"'
```

## Upgrade Recommendations

### Before Upgrading

1. **Review changelog**: Check deprecated APIs and breaking changes
2. **Test in staging**: Validate workloads on new version
3. **Backup etcd**: `etcdctl snapshot save backup.db`
4. **Check API deprecations**: `kubectl deprecations` (with deprecations plugin)

### Upgrade Priority Matrix

| Current Version | Risk Level | Action |
|-----------------|------------|--------|
| ≤1.26 | **Critical** | Upgrade immediately - multiple unpatched CVEs |
| 1.27-1.28 | **High** | Upgrade within 30 days - EOL |
| 1.29 | **Medium** | Plan upgrade within 90 days |
| 1.30+ | **Low** | Stay current with patches |

### Post-Upgrade Validation

```bash
# Verify all nodes updated
kubectl get nodes -o wide

# Check system pods healthy
kubectl get pods -n kube-system

# Verify API server responsive
kubectl cluster-info

# Test workload connectivity
kubectl run test --image=busybox --rm -it -- wget -qO- kubernetes.default.svc
```

## External Resources

- [Kubernetes Security Announcements](https://groups.google.com/g/kubernetes-security-announce)
- [CVE Database - Kubernetes](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=kubernetes)
- [Kubernetes Version Skew Policy](https://kubernetes.io/releases/version-skew-policy/)
- [Kubernetes Release Notes](https://github.com/kubernetes/kubernetes/releases)
