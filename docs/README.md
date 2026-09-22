# Documentation map

Find the document that owns the task; implementation history stays in Git.

## Use and operate

| Task | Document |
|---|---|
| Install, use the CLI, inject secrets, diagnose routing | [Project README](../README.md) |
| Configure client routing and agent defaults | [Config template](../config.example.toml) |
| Give a command its secrets through a PATH shim | [Command shims](hook.md) |
| Deploy, bootstrap, update, or reset phone approval | [Worker deployment](cf-worker-deploy.md) |
| Replace a pre-v20260915 Worker (breaking upgrade) | [Worker redeploy](worker-redeploy.md) |
| Operate the macOS menu app and agent | [VT.app](app-bundle.md) |
| Install or remove Linux sudo approval | [sudo](sudo.md) |
| Enable local-agent audit delivery | [Agent audit](agent-audit.md) |
| Post approvals to a Slack channel | [Slack Bot channel](slack.md) |

## Design contracts

| Question | Document |
|---|---|
| What does an agent approval authorize, and when does it expire? | [Authorization](unified-authorization-engine.md) |
| Where do SSH keys live, and what can forwarding expose? | [SSH identities](sign-vt-design.md) |
| What do Worker keys, host tokens, and admin sessions authorize? | [Worker trust model](worker-slim.md) |
| What authority does a cached DEK grant? | [DEK cache](dek-cache.md) |
| What must an approver see and trust? | [Approval transparency](approval-transparency.md) |
| What makes the phone/admin interface usable? | [PWA interaction](design/ui-ux.md) |
| How do errors affect exit codes, fallback, and retries? | [Extension errors](structured-errors.md) |
| What sealed-box format must the three implementations share? | [Sealed box](sealed-box-v1.md) |
| What does the Secure Enclave guarantee for the master-key wrap? | [Secure Enclave](secure-enclave.md) |

[AGENTS.md](../AGENTS.md) owns editing rules, documentation standards, and
validation gates.
