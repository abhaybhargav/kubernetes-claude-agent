# CIS Kubernetes Benchmark Reference

Quick reference for CIS Kubernetes Benchmark v1.8+ security controls. Use this to map audit findings to industry standards.

## Table of Contents

1. [Control Plane Components](#control-plane-components)
2. [Worker Node Security](#worker-node-security)
3. [Policies](#policies)
4. [Managed Kubernetes Mapping](#managed-kubernetes-mapping)

## Control Plane Components

### 1.1 API Server

| CIS ID | Control | Check Command | Expected |
|--------|---------|---------------|----------|
| 1.1.1 | anonymous-auth disabled | `ps -ef \| grep kube-apiserver \| grep anonymous-auth` | `--anonymous-auth=false` |
| 1.1.2 | Basic auth disabled | `ps -ef \| grep kube-apiserver \| grep basic-auth` | No `--basic-auth-file` |
| 1.1.3 | Token auth file disabled | `ps -ef \| grep kube-apiserver` | No `--token-auth-file` |
| 1.1.4 | Kubelet HTTPS | `ps -ef \| grep kube-apiserver \| grep kubelet-https` | `--kubelet-https=true` |
| 1.1.5 | Kubelet client cert | Check `--kubelet-client-certificate` and `--kubelet-client-key` | Both set |
| 1.1.6 | Kubelet cert authority | Check `--kubelet-certificate-authority` | Set |
| 1.1.7 | Authorization mode | `ps -ef \| grep kube-apiserver \| grep authorization-mode` | Not `AlwaysAllow` |
| 1.1.8 | Node authorization | `--authorization-mode` | Includes `Node` |
| 1.1.9 | RBAC authorization | `--authorization-mode` | Includes `RBAC` |
| 1.1.10 | Admission controllers | `--enable-admission-plugins` | See required list below |
| 1.1.11 | AlwaysAdmit disabled | `--enable-admission-plugins` | Not `AlwaysAdmit` |
| 1.1.12 | AlwaysPullImages | Recommended for multi-tenant | `AlwaysPullImages` |
| 1.1.13 | SecurityContextDeny/PodSecurity | Recommended | One enabled |
| 1.1.14 | ServiceAccount admission | `--disable-admission-plugins` | Not `ServiceAccount` |
| 1.1.15 | NamespaceLifecycle | `--disable-admission-plugins` | Not `NamespaceLifecycle` |
| 1.1.16 | NodeRestriction | `--enable-admission-plugins` | `NodeRestriction` |
| 1.1.17 | Secure port | `--secure-port` | Not `0` |
| 1.1.18 | Profiling disabled | `--profiling` | `false` |
| 1.1.19 | Audit logging | `--audit-log-path` | Set |
| 1.1.20 | Audit log retention | `--audit-log-maxage` | `≥30` |
| 1.1.21 | Audit log backup count | `--audit-log-maxbackup` | `≥10` |
| 1.1.22 | Audit log size | `--audit-log-maxsize` | `≥100` |
| 1.1.23 | Service account lookup | `--service-account-lookup` | `true` |
| 1.1.24 | Service account key | `--service-account-key-file` | Set |
| 1.1.25 | etcd certfile | `--etcd-certfile` and `--etcd-keyfile` | Both set |
| 1.1.26 | TLS cert | `--tls-cert-file` and `--tls-private-key-file` | Both set |
| 1.1.27 | Client CA | `--client-ca-file` | Set |
| 1.1.28 | etcd CA | `--etcd-cafile` | Set |
| 1.1.29 | Encryption provider | `--encryption-provider-config` | Set (secrets at rest) |

### Required Admission Controllers

```
AlwaysPullImages, DefaultStorageClass, DefaultTolerationSeconds,
LimitRanger, MutatingAdmissionWebhook, NamespaceLifecycle,
NodeRestriction, PersistentVolumeClaimResize, PodSecurity,
Priority, ResourceQuota, ServiceAccount, StorageObjectInUseProtection,
TaintNodesByCondition, ValidatingAdmissionWebhook
```

### 1.2 Controller Manager

| CIS ID | Control | Expected |
|--------|---------|----------|
| 1.2.1 | Profiling disabled | `--profiling=false` |
| 1.2.2 | Use service account credentials | `--use-service-account-credentials=true` |
| 1.2.3 | Service account private key | `--service-account-private-key-file` set |
| 1.2.4 | Root CA file | `--root-ca-file` set |
| 1.2.5 | Rotate kubelet certs | `--rotate-certificates=true` |
| 1.2.6 | RotateKubeletServerCertificate | `--feature-gates=RotateKubeletServerCertificate=true` |
| 1.2.7 | Bind address | `--bind-address=127.0.0.1` |

### 1.3 Scheduler

| CIS ID | Control | Expected |
|--------|---------|----------|
| 1.3.1 | Profiling disabled | `--profiling=false` |
| 1.3.2 | Bind address | `--bind-address=127.0.0.1` |

### 1.4 etcd

| CIS ID | Control | Expected |
|--------|---------|----------|
| 1.4.1 | Peer cert auth | `--peer-client-cert-auth=true` |
| 1.4.2 | Client cert auth | `--client-cert-auth=true` |
| 1.4.3 | Auto TLS disabled | `--auto-tls=false` |
| 1.4.4 | Peer auto TLS disabled | `--peer-auto-tls=false` |
| 1.4.5 | TLS cert/key | `--cert-file` and `--key-file` set |
| 1.4.6 | Peer TLS cert/key | `--peer-cert-file` and `--peer-key-file` set |
| 1.4.7 | Trusted CA | `--trusted-ca-file` set |
| 1.4.8 | Peer trusted CA | `--peer-trusted-ca-file` set |

## Worker Node Security

### 2.1 Kubelet

| CIS ID | Control | Check | Expected |
|--------|---------|-------|----------|
| 2.1.1 | Anonymous auth | kubelet config | `authentication.anonymous.enabled=false` |
| 2.1.2 | Authorization mode | kubelet config | `authorization.mode=Webhook` |
| 2.1.3 | Client CA | `--client-ca-file` | Set |
| 2.1.4 | Read-only port | `--read-only-port` | `0` |
| 2.1.5 | Streaming connection timeout | `--streaming-connection-idle-timeout` | Not `0` |
| 2.1.6 | Protect kernel defaults | `--protect-kernel-defaults` | `true` |
| 2.1.7 | Make iptables rules | `--make-iptables-util-chains` | `true` |
| 2.1.8 | Hostname override | `--hostname-override` | Not set (unless needed) |
| 2.1.9 | Event record QPS | `--event-qps` | `0` to disable or appropriate limit |
| 2.1.10 | TLS cert | `--tls-cert-file` and `--tls-private-key-file` | Both set |
| 2.1.11 | Rotate certificates | `--rotate-certificates` | `true` |
| 2.1.12 | Rotate server certs | `serverTLSBootstrap` | `true` |

**Check kubelet configuration:**
```bash
# On node or via kubectl proxy
curl -k https://<node-ip>:10250/configz

# Or check kubelet arguments
ps -ef | grep kubelet
```

## Policies

### 3.1 RBAC and Service Accounts

| CIS ID | Control | Remediation |
|--------|---------|-------------|
| 3.1.1 | Limit cluster-admin usage | Use namespace-scoped roles |
| 3.1.2 | Minimize wildcard use | Specify explicit resources/verbs |
| 3.1.3 | Minimize cluster-admin bindings | Audit and remove unnecessary |
| 3.1.4 | Minimize access to secrets | Use resourceNames, limit to specific secrets |
| 3.1.5 | Minimize wildcard verbs | Specify `get`, `list` explicitly |
| 3.1.6 | Create service accounts per workload | Don't use default SA |

### 3.2 Pod Security

| CIS ID | Control | Remediation |
|--------|---------|-------------|
| 3.2.1 | Minimize privileged containers | Set `privileged: false` |
| 3.2.2 | Minimize hostPID sharing | Set `hostPID: false` |
| 3.2.3 | Minimize hostIPC sharing | Set `hostIPC: false` |
| 3.2.4 | Minimize hostNetwork | Set `hostNetwork: false` |
| 3.2.5 | Minimize AllowPrivilegeEscalation | Set `allowPrivilegeEscalation: false` |
| 3.2.6 | Minimize root user | Set `runAsNonRoot: true` |
| 3.2.7 | Minimize NET_RAW capability | Drop `NET_RAW` |
| 3.2.8 | Minimize added capabilities | Only add required capabilities |
| 3.2.9 | Minimize HostPath volumes | Avoid or restrict to read-only |

### 3.3 Network Policies

| CIS ID | Control | Remediation |
|--------|---------|-------------|
| 3.3.1 | NetworkPolicies in all namespaces | Apply default deny |
| 3.3.2 | Ingress NetworkPolicies | Define ingress rules |
| 3.3.3 | Egress NetworkPolicies | Define egress rules |

### 3.4 Secrets Management

| CIS ID | Control | Remediation |
|--------|---------|-------------|
| 3.4.1 | Prefer secrets over env vars | Mount secrets as volumes |
| 3.4.2 | External secrets manager | Use Vault, AWS SM, etc. |

### 3.5 General Policies

| CIS ID | Control | Remediation |
|--------|---------|-------------|
| 3.5.1 | Create namespaces to isolate | Don't use default namespace |
| 3.5.2 | Apply security context | Set at pod and container level |
| 3.5.3 | Use default namespace minimally | Reserve for system components |

## Managed Kubernetes Mapping

### EKS (Amazon)

| CIS Control | EKS Default | Notes |
|-------------|-------------|-------|
| API server auth | Managed by AWS | Use IAM auth |
| etcd encryption | Not default | Enable via AWS KMS |
| Audit logging | Available | Enable CloudWatch logging |
| Network policies | Not default CNI | Install Calico |
| Pod Security | Supported | Apply PSS labels |

**EKS-specific checks:**
```bash
# Check control plane logging
aws eks describe-cluster --name <cluster> --query 'cluster.logging'

# Check encryption config
aws eks describe-cluster --name <cluster> --query 'cluster.encryptionConfig'
```

### GKE (Google)

| CIS Control | GKE Default | Notes |
|-------------|-------------|-------|
| Network policy | Not default | Enable at cluster creation |
| Workload Identity | Recommended | Use instead of node SA |
| Binary Authorization | Available | Enable for image signing |
| Shielded nodes | Available | Enable for node integrity |

**GKE-specific checks:**
```bash
# Check network policy status
gcloud container clusters describe <cluster> --format='value(networkPolicy.enabled)'

# Check workload identity
gcloud container clusters describe <cluster> --format='value(workloadIdentityConfig)'
```

### AKS (Azure)

| CIS Control | AKS Default | Notes |
|-------------|-------------|-------|
| Network policy | Not default | Use Azure or Calico |
| Azure AD integration | Recommended | Enable for RBAC |
| Key Vault integration | Available | CSI driver for secrets |
| Defender for Containers | Available | Enable for security monitoring |

**AKS-specific checks:**
```bash
# Check network policy
az aks show -n <cluster> -g <rg> --query 'networkProfile.networkPolicy'

# Check Azure AD integration
az aks show -n <cluster> -g <rg> --query 'aadProfile'
```

## Quick Compliance Check Script

```bash
#!/bin/bash
echo "=== CIS Quick Check ==="

# 1.1.1 - Anonymous auth
echo "[1.1.1] API Server anonymous auth:"
kubectl get pods -n kube-system -l component=kube-apiserver -o yaml 2>/dev/null | grep -E "anonymous-auth" || echo "Unable to check (managed cluster?)"

# 1.1.29 - Encryption at rest
echo -e "\n[1.1.29] Secrets encryption:"
kubectl get secrets -n kube-system -o json | jq -r '.items[0].metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]' 2>/dev/null | head -1

# 3.2.1 - Privileged containers
echo -e "\n[3.2.1] Privileged pods:"
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.namespace + "/" + .metadata.name'

# 3.3.1 - Network policies
echo -e "\n[3.3.1] Namespaces without NetworkPolicy:"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
  [ $(kubectl get netpol -n $ns --no-headers 2>/dev/null | wc -l) -eq 0 ] && echo "  $ns"
done

# 3.1.1 - Cluster-admin bindings
echo -e "\n[3.1.1] Cluster-admin bindings:"
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name == "cluster-admin") | .metadata.name + ": " + (.subjects[]?.name // "no subjects")'
```
