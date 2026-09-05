# VT documentation map

This page is the fast path for both humans and coding agents. Start here, then
open only the document relevant to the change.

## Source of truth

The code is authoritative for behavior. Documentation is authoritative for
operator workflows and security decisions. If they disagree, verify the code
and update the relevant document in the same change.

| Need | Read first | Implementation anchor |
|---|---|---|
| Install or use VT | [`README.md`](../README.md) | `src/main.rs` |
| Configure auth/routing | [`config.example.toml`](../config.example.toml) | `src/config.rs` (file hydration), `src/config/client.rs` (`ResolvedConfig`), `src/client.rs` |
| Configure AI-agent hooks | [`hook.md`](hook.md) | `src/hook.rs`, `agent.example.toml` |
| Use VT for Linux sudo/PAM | [`sudo.md`](sudo.md) | `setup-pam.sh`, `src/client.rs` |
| Deploy the phone approval Worker | [`cf-worker-deploy.md`](cf-worker-deploy.md) | `cf-worker/src/index.ts`, `cf-worker/src/do_account.ts` |
| Understand Worker audit and notification lifecycle | [`cf-worker-deploy.md`](cf-worker-deploy.md) | `cf-worker/src/account_audit.ts`, `cf-worker/src/account_notifications.ts` |
| Understand DEK caching | [`dek-cache.md`](dek-cache.md) | `cf-worker/src/do_account.ts`, `src/cf.rs` |
| Use SSH identities | [`README.md` — portable identity](../README.md#portable-ssh-identity-for-git-vt) | `src/ssh_sign.rs`, `src/client.rs` |
| Understand extension errors | [`structured-errors.md`](structured-errors.md) | `src/core/wire.rs`, `src/client.rs` |
| Understand SSH-agent authorization and caching | [`unified-authorization-engine.md`](unified-authorization-engine.md) | `src/core/authorization.rs`, `src/server_macos/authorization.rs`, `src/server_macos/ssh_agent.rs` (dispatcher), `src/server_macos/ssh_agent/handlers.rs` (operations) |
| Understand grant scopes (destination / workspace / relay) | [`authorization-scopes-v2.md`](authorization-scopes-v2.md) | `src/core/authorization.rs` (`GrantScope`), `src/server_macos/ssh_agent/scopes.rs` (`BindState`, `resolve_workspace`), `src/server_macos/ssh_agent/scopes/process.rs` (kernel queries), `src/server_macos/ssh_agent/scopes/paths.rs` (path policy) |
| Enable agent audit push | [`agent-audit.md`](agent-audit.md) | `src/audit.rs`, `src/server_macos/audit.rs` |
| Understand prompt/notification fields and audit context | [`approval-transparency.md`](approval-transparency.md) | `src/server_macos/ssh_agent/handlers.rs` (operation prompts), `src/server_macos/ssh_agent/scopes.rs` (truth lines), `cf-worker/src/notify.ts`, `cf-worker/pwa/approve.js` |
| Diagnose config/routing/caching (`vt doctor`) | [`diag-design.md`](diag-design.md) | `src/client/doctor.rs`, `src/config/client.rs` (shared routing), `src/server_macos/ssh_agent/handlers.rs` (`handle_diag`) |
| Build/install VT.app, menu bar UI, native notifications, key-wrap rebind | [`app-bundle.md`](app-bundle.md) | `app/VTShell.swift`, `src/server_macos/security.rs` (`notify_macos`), `src/core/crypto.rs` (`derive_passphrase_secret`) |
| Configure Slack App notifications | [`slack-app.md`](slack-app.md) | `cf-worker/src/slack_app.ts` |
| Configure Feishu/Lark notifications | [`feishu.md`](feishu.md) | `cf-worker/src/feishu.ts` |

## Current versus historical documents

The following are implementation history and decision records, not step-by-step
implementation plans:

- [`ssh-vt-design.md`](ssh-vt-design.md)
- [`sign-vt-design.md`](sign-vt-design.md)
- [`feishu-design.md`](feishu-design.md)

Read the status note at the top and the security section first. Ignore review
rounds, PR breakdowns, and superseded alternatives when changing code; verify
the current behavior against the implementation anchors in the table.

## Fast path for coding agents

1. Find the command, config key, route, or protocol symbol with `rg`.
2. Read the matching row above and its implementation anchor.
3. Make the smallest coherent code + documentation change.
4. Run the narrow test first, then the repository gate:

   ```bash
   cargo test
   just check
   just check-worker
   ```

5. If behavior, config, routes, secrets, or security boundaries changed, update
   the matching operator document and this map if the ownership changed.

## Change routing

| Change | Update |
|---|---|
| CLI command or flag | `README.md`, `src/main.rs` help, and the feature doc |
| `VT_*` variable or config-file behavior | `config.example.toml`, `README.md`, `src/config.rs` |
| Worker secret, route, or admin page | `cf-worker-deploy.md`, `cf-worker/wrangler.toml.example`, relevant channel/cache doc |
| Wire format or exit code | `structured-errors.md` and protocol tests |
| Security invariant | the relevant design doc plus a code comment/test |

Do not treat `CLAUDE.md` as a second product manual. It contains repository
navigation, invariants, and test gates; user-facing procedures belong here or
in the linked feature documents.
