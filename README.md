# Kubernetes Security Audit Agent

An AI-powered Kubernetes security audit agent that leverages the Claude Agent SDK to perform comprehensive security assessments of your Kubernetes clusters.

## What It Does

This agent automatically performs a thorough security audit of your Kubernetes cluster, including:

- RBAC analysis and privilege escalation detection
- Network policy assessment
- Pod security evaluation
- Secrets management review
- CIS benchmark compliance checks
- Container security analysis
- Ingress/egress configuration review

Upon completion, it generates a detailed security audit report in markdown format.

## Prerequisites

Before running the agent, ensure you have the following:

1. **Python 3.13+** - Required for the project
2. **uv** - Python package manager ([install uv](https://docs.astral.sh/uv/getting-started/installation/))
3. **kubectl** - Kubernetes CLI tool, installed and configured
4. **kubeconfig** - Valid kubeconfig file in your `$HOME/.kube/config` (or `KUBECONFIG` env var set)
5. **Cluster access** - Administrative permissions to the target Kubernetes cluster
6. **Node.js/npm** - Required for the MCP memory server

## Installation

1. **Clone the repository:**

   ```bash
   git clone <repository-url>
   cd kube-claude-agent
   ```

2. **Install dependencies with uv:**

   ```bash
   uv sync
   ```

## Configuration

1. **Create a `.env` file** in the project root:

   ```bash
   touch .env
   ```

2. **Add your Anthropic API key** to the `.env` file:

   ```env
   ANTHROPIC_API_KEY=your-api-key-here
   ```

3. **Verify kubectl access** to your cluster:

   ```bash
   kubectl cluster-info
   kubectl auth can-i '*' '*' --all-namespaces
   ```

## Running the Agent

Execute the security audit agent using `uv run`:

```bash
uv run python main.py
```

The agent will:

1. Load the `k8s-security-audit` skill
2. Plan the audit steps
3. Execute comprehensive security checks against your cluster
4. Track progress using the MCP memory server
5. Generate a detailed security audit report in the current directory

## Output

Once the audit completes, you'll find a markdown security report in the current working directory containing:

- Executive summary
- Detailed findings organized by category
- Risk ratings and severity levels
- Remediation recommendations
- Compliance status

## Project Structure

```
kube-claude-agent/
├── main.py              # Main agent entrypoint
├── pyproject.toml       # Project dependencies
├── .env                 # Environment variables (create this)
├── README.md            # This file
└── .claude/
    └── skills/
        └── k8s-security-audit/  # Security audit skill
```

## Dependencies

| Package | Purpose |
|---------|---------|
| `claude-agent-sdk` | Claude AI agent framework |
| `loguru` | Logging |
| `python-dotenv` | Environment variable management |

## Troubleshooting

### Common Issues

**"ANTHROPIC_API_KEY not set"**
- Ensure your `.env` file exists and contains a valid API key

**"kubectl: command not found"**
- Install kubectl: https://kubernetes.io/docs/tasks/tools/

**"Unable to connect to the cluster"**
- Verify your kubeconfig: `kubectl config view`
- Test connectivity: `kubectl cluster-info`

**"Permission denied" errors during audit**
- Ensure your kubeconfig has admin-level permissions
- Check RBAC: `kubectl auth can-i '*' '*' --all-namespaces`

## License

MIT
