#!/usr/bin/env python3
"""
Kubernetes Security Audit Script

Performs comprehensive security assessment of a Kubernetes cluster.
Requires kubectl configured with admin access.

Usage:
    python k8s_security_audit.py [--kubeconfig PATH] [--context NAME] [--output FILE]
"""

import subprocess
import json
import sys
import argparse
from datetime import datetime
from typing import Dict, List, Any, Optional


class Finding:
    """Represents a security finding."""
    def __init__(self, category: str, severity: str, title: str, 
                 description: str, resources: List[str] = None, 
                 remediation: str = ""):
        self.category = category
        self.severity = severity  # Critical, High, Medium, Low, Info
        self.title = title
        self.description = description
        self.resources = resources or []
        self.remediation = remediation


class K8sSecurityAuditor:
    """Kubernetes Security Auditor."""
    
    def __init__(self, kubeconfig: str = None, context: str = None):
        self.kubeconfig = kubeconfig
        self.context = context
        self.findings: List[Finding] = []
        self.cluster_info = {}
        
    def _kubectl(self, *args, parse_json: bool = True) -> Any:
        """Execute kubectl command and return output."""
        cmd = ["kubectl"]
        if self.kubeconfig:
            cmd.extend(["--kubeconfig", self.kubeconfig])
        if self.context:
            cmd.extend(["--context", self.context])
        cmd.extend(args)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                return None
            if parse_json and "-o" in args and "json" in args:
                return json.loads(result.stdout)
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            print(f"Warning: kubectl command failed: {' '.join(args[:3])}... - {e}", file=sys.stderr)
            return None

    def _add_finding(self, category: str, severity: str, title: str,
                     description: str, resources: List[str] = None,
                     remediation: str = ""):
        """Add a security finding."""
        self.findings.append(Finding(
            category=category,
            severity=severity,
            title=title,
            description=description,
            resources=resources,
            remediation=remediation
        ))

    def validate_access(self) -> bool:
        """Validate cluster access and permissions."""
        print("[*] Validating cluster access...")
        
        cluster_info = self._kubectl("cluster-info", parse_json=False)
        if not cluster_info:
            print("ERROR: Cannot connect to cluster", file=sys.stderr)
            return False
        
        can_admin = self._kubectl("auth", "can-i", "*", "*", "--all-namespaces", parse_json=False)
        if can_admin != "yes":
            print("WARNING: Limited permissions detected. Some checks may be incomplete.", file=sys.stderr)
        
        self.cluster_info["context"] = self._kubectl("config", "current-context", parse_json=False)
        return True

    def gather_cluster_info(self):
        """Gather basic cluster information."""
        print("[*] Gathering cluster information...")
        
        version = self._kubectl("version", "-o", "json")
        if version:
            server_version = version.get("serverVersion", {})
            self.cluster_info["version"] = server_version.get("gitVersion", "unknown")
            self.cluster_info["version_major"] = server_version.get("major", "")
            self.cluster_info["version_minor"] = server_version.get("minor", "").rstrip("+")
        
        nodes = self._kubectl("get", "nodes", "-o", "json")
        if nodes:
            self.cluster_info["nodes"] = len(nodes.get("items", []))
            self.cluster_info["node_list"] = [
                {
                    "name": n["metadata"]["name"],
                    "os": n["status"]["nodeInfo"].get("operatingSystem", "unknown"),
                    "kubelet": n["status"]["nodeInfo"].get("kubeletVersion", "unknown")
                }
                for n in nodes.get("items", [])
            ]
        
        namespaces = self._kubectl("get", "namespaces", "-o", "json")
        if namespaces:
            self.cluster_info["namespaces"] = [
                ns["metadata"]["name"] for ns in namespaces.get("items", [])
            ]

    def audit_rbac(self):
        """Audit RBAC configurations."""
        print("[*] Auditing RBAC...")
        
        clusterroles = self._kubectl("get", "clusterroles", "-o", "json")
        if clusterroles:
            for cr in clusterroles.get("items", []):
                name = cr["metadata"]["name"]
                for rule in cr.get("rules", []):
                    resources = rule.get("resources", [])
                    verbs = rule.get("verbs", [])
                    
                    if "*" in resources and "*" in verbs:
                        if not name.startswith("system:"):
                            self._add_finding(
                                "RBAC", "Critical",
                                f"Wildcard ClusterRole: {name}",
                                "ClusterRole grants full permissions on all resources",
                                [name],
                                "Review and restrict to specific resources and verbs"
                            )
                    
                    if "secrets" in resources and ("get" in verbs or "list" in verbs or "*" in verbs):
                        if not name.startswith("system:"):
                            self._add_finding(
                                "RBAC", "High",
                                f"ClusterRole with secrets access: {name}",
                                "ClusterRole can read secrets cluster-wide",
                                [name],
                                "Use namespaced Roles or restrict to specific secrets via resourceNames"
                            )

        crb = self._kubectl("get", "clusterrolebindings", "-o", "json")
        if crb:
            for binding in crb.get("items", []):
                if binding.get("roleRef", {}).get("name") == "cluster-admin":
                    subjects = binding.get("subjects", [])
                    for subj in subjects:
                        if subj.get("kind") == "ServiceAccount":
                            self._add_finding(
                                "RBAC", "High",
                                f"ServiceAccount with cluster-admin: {subj.get('namespace', 'default')}/{subj.get('name')}",
                                "ServiceAccount has full cluster-admin privileges",
                                [binding["metadata"]["name"]],
                                "Use least-privilege roles instead of cluster-admin"
                            )

    def audit_pod_security(self):
        """Audit pod security configurations."""
        print("[*] Auditing pod security...")
        
        pods = self._kubectl("get", "pods", "-A", "-o", "json")
        if not pods:
            return
        
        for pod in pods.get("items", []):
            ns = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            spec = pod.get("spec", {})
            pod_id = f"{ns}/{name}"
            
            for container in spec.get("containers", []) + spec.get("initContainers", []):
                sc = container.get("securityContext", {})
                if sc.get("privileged"):
                    self._add_finding(
                        "Pod Security", "Critical",
                        f"Privileged container: {pod_id}",
                        f"Container '{container['name']}' runs in privileged mode",
                        [pod_id],
                        "Set securityContext.privileged: false and use specific capabilities"
                    )
            
            if spec.get("hostNetwork"):
                self._add_finding(
                    "Pod Security", "High",
                    f"hostNetwork enabled: {pod_id}",
                    "Pod shares host network namespace",
                    [pod_id],
                    "Remove hostNetwork: true unless absolutely required"
                )
            
            if spec.get("hostPID"):
                self._add_finding(
                    "Pod Security", "High",
                    f"hostPID enabled: {pod_id}",
                    "Pod shares host PID namespace",
                    [pod_id],
                    "Remove hostPID: true unless absolutely required"
                )
            
            for vol in spec.get("volumes", []):
                if vol.get("hostPath"):
                    path = vol["hostPath"].get("path", "")
                    if path in ["/", "/etc", "/var", "/root"]:
                        self._add_finding(
                            "Pod Security", "High",
                            f"Sensitive hostPath mount: {pod_id}",
                            f"Pod mounts sensitive host path: {path}",
                            [pod_id],
                            "Avoid hostPath volumes or restrict to specific subdirectories"
                        )

    def audit_network_policies(self):
        """Audit network policies."""
        print("[*] Auditing network policies...")
        
        netpols = self._kubectl("get", "networkpolicies", "-A", "-o", "json")
        namespaces = self.cluster_info.get("namespaces", [])
        
        ns_with_policies = set()
        if netpols:
            for pol in netpols.get("items", []):
                ns_with_policies.add(pol["metadata"]["namespace"])
        
        system_ns = {"kube-system", "kube-public", "kube-node-lease"}
        user_ns = [ns for ns in namespaces if ns not in system_ns]
        
        for ns in user_ns:
            if ns not in ns_with_policies:
                self._add_finding(
                    "Network", "High",
                    f"No NetworkPolicy in namespace: {ns}",
                    "Namespace has no network policies, allowing unrestricted traffic",
                    [ns],
                    "Apply default-deny ingress/egress policy"
                )

    def audit_secrets(self):
        """Audit secrets management."""
        print("[*] Auditing secrets...")
        
        configmaps = self._kubectl("get", "configmaps", "-A", "-o", "json")
        if configmaps:
            suspicious_keys = ["password", "secret", "key", "token", "credential", "api_key"]
            for cm in configmaps.get("items", []):
                ns = cm["metadata"]["namespace"]
                name = cm["metadata"]["name"]
                data = cm.get("data", {})
                
                for key in data.keys():
                    if any(s in key.lower() for s in suspicious_keys):
                        self._add_finding(
                            "Secrets", "Medium",
                            f"Potential secret in ConfigMap: {ns}/{name}",
                            f"ConfigMap contains key '{key}' that may be a secret",
                            [f"{ns}/{name}"],
                            "Move sensitive data to Secrets with proper encryption"
                        )

    def audit_workloads(self):
        """Audit workload configurations."""
        print("[*] Auditing workloads...")
        
        pods = self._kubectl("get", "pods", "-A", "-o", "json")
        if not pods:
            return
        
        latest_images = set()
        no_limits = set()
        
        for pod in pods.get("items", []):
            ns = pod["metadata"]["namespace"]
            name = pod["metadata"]["name"]
            pod_id = f"{ns}/{name}"
            
            for container in pod.get("spec", {}).get("containers", []):
                image = container.get("image", "")
                
                if image.endswith(":latest") or ":" not in image.split("/")[-1]:
                    latest_images.add(image)
                
                resources = container.get("resources", {})
                if not resources.get("limits"):
                    no_limits.add(pod_id)
        
        if latest_images:
            self._add_finding(
                "Workloads", "Medium",
                f"Images using :latest or no tag ({len(latest_images)} found)",
                "Using latest/untagged images makes deployments non-deterministic",
                list(latest_images)[:10],
                "Pin images to specific versions or digests"
            )
        
        if no_limits:
            self._add_finding(
                "Workloads", "Low",
                f"Pods without resource limits ({len(no_limits)} found)",
                "Missing resource limits can lead to resource exhaustion",
                list(no_limits)[:10],
                "Define CPU and memory limits for all containers"
            )

    def audit_pss(self):
        """Check Pod Security Standards enforcement."""
        print("[*] Checking Pod Security Standards...")
        
        namespaces = self._kubectl("get", "namespaces", "-o", "json")
        if not namespaces:
            return
        
        system_ns = {"kube-system", "kube-public", "kube-node-lease"}
        
        for ns in namespaces.get("items", []):
            name = ns["metadata"]["name"]
            if name in system_ns:
                continue
                
            labels = ns["metadata"].get("labels", {})
            enforce = labels.get("pod-security.kubernetes.io/enforce")
            
            if not enforce:
                self._add_finding(
                    "Pod Security", "Medium",
                    f"No Pod Security Standard enforcement: {name}",
                    "Namespace lacks PSS enforcement label",
                    [name],
                    "Add pod-security.kubernetes.io/enforce label with 'restricted' or 'baseline'"
                )

    def run_audit(self) -> bool:
        """Run the complete security audit."""
        if not self.validate_access():
            return False
        
        self.gather_cluster_info()
        self.audit_rbac()
        self.audit_pod_security()
        self.audit_network_policies()
        self.audit_secrets()
        self.audit_workloads()
        self.audit_pss()
        
        return True

    def generate_report(self) -> str:
        """Generate markdown report."""
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        
        if counts.get("Critical", 0) > 0:
            overall_risk = "Critical"
        elif counts.get("High", 0) > 0:
            overall_risk = "High"
        elif counts.get("Medium", 0) > 0:
            overall_risk = "Medium"
        else:
            overall_risk = "Low"
        
        report = []
        report.append("# Kubernetes Security Audit Report\n")
        report.append(f"**Cluster**: {self.cluster_info.get('context', 'unknown')}")
        report.append(f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Auditor**: Claude AI\n")
        
        report.append("## Executive Summary\n")
        report.append("| Category | Critical | High | Medium | Low |")
        report.append("|----------|----------|------|--------|-----|")
        
        categories = set(f.category for f in self.findings)
        for cat in sorted(categories):
            cat_findings = [f for f in self.findings if f.category == cat]
            c = sum(1 for f in cat_findings if f.severity == "Critical")
            h = sum(1 for f in cat_findings if f.severity == "High")
            m = sum(1 for f in cat_findings if f.severity == "Medium")
            l = sum(1 for f in cat_findings if f.severity == "Low")
            report.append(f"| {cat} | {c} | {h} | {m} | {l} |")
        
        report.append(f"\n**Overall Risk Level**: {overall_risk}\n")
        
        report.append("## Cluster Information\n")
        report.append(f"- **Kubernetes Version**: {self.cluster_info.get('version', 'unknown')}")
        report.append(f"- **Nodes**: {self.cluster_info.get('nodes', 'unknown')}")
        report.append(f"- **Namespaces**: {len(self.cluster_info.get('namespaces', []))}\n")
        
        for sev in ["Critical", "High", "Medium", "Low"]:
            sev_findings = [f for f in self.findings if f.severity == sev]
            if sev_findings:
                report.append(f"## {sev} Findings\n")
                for i, f in enumerate(sev_findings, 1):
                    report.append(f"### {sev[0]}{i}. {f.title}\n")
                    report.append(f"**Category**: {f.category}\n")
                    report.append(f"{f.description}\n")
                    if f.resources:
                        report.append(f"**Affected Resources**: {', '.join(f.resources[:5])}")
                        if len(f.resources) > 5:
                            report.append(f" (and {len(f.resources) - 5} more)")
                        report.append("\n")
                    if f.remediation:
                        report.append(f"**Remediation**: {f.remediation}\n")
                    report.append("")
        
        report.append("## Remediation Priority\n")
        report.append("1. Address all Critical findings immediately")
        report.append("2. Schedule High findings for next sprint")
        report.append("3. Plan Medium findings for upcoming releases")
        report.append("4. Track Low findings in backlog\n")
        
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Security Audit")
    parser.add_argument("--kubeconfig", help="Path to kubeconfig file")
    parser.add_argument("--context", help="Kubernetes context to use")
    parser.add_argument("--output", "-o", help="Output file path", default="audit_report.md")
    args = parser.parse_args()
    
    auditor = K8sSecurityAuditor(kubeconfig=args.kubeconfig, context=args.context)
    
    print("=" * 50)
    print("Kubernetes Security Audit")
    print("=" * 50)
    
    if not auditor.run_audit():
        sys.exit(1)
    
    report = auditor.generate_report()
    
    with open(args.output, "w") as f:
        f.write(report)
    
    print(f"\n[✓] Audit complete. Report written to: {args.output}")
    print(f"    Total findings: {len(auditor.findings)}")
    
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sum(1 for f in auditor.findings if f.severity == sev)
        if count:
            print(f"    - {sev}: {count}")


if __name__ == "__main__":
    main()
