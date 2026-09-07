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
| Understand record parsing and decrypt batches | [`README.md` — protocol](../README.md#vt-protocol-format) | `src/core.rs` (`VtUrl`), `src/client/records.rs` (`DecryptBatch`), `src/core/crypto.rs` |
| Migrate legacy records (`vt rewrap`) | [`README.md` — commands](../README.md#commands) | `src/client/rewrap.rs`, `src/core/compat.rs` |
| Configure AI-agent hooks | [`hook.md`](hook.md) | `src/hook.rs`, `agent.example.toml` |
| Use VT for Linux sudo/PAM | [`sudo.md`](sudo.md) | `setup-pam.sh`, `src/client.rs` |
| Deploy the phone approval Worker | [`cf-worker-deploy.md`](cf-worker-deploy.md) | `cf-worker/src/index.ts`, `cf-worker/src/do_account.ts` |
| Understand Worker audit and notification lifecycle | [`cf-worker-deploy.md`](cf-worker-deploy.md) | `cf-worker/src/account_audit.ts`, `cf-worker/src/account_notifications.ts` |
| Understand DEK caching | [`dek-cache.md`](dek-cache.md) | `cf-worker/src/do_account.ts` (ceremony and audit), `cf-worker/src/account_cache.ts` (cache storage), `cf-worker/src/storage_batch.ts` (shared batch deletion and prefix paging), `src/cf.rs` |
| Use SSH identities | [`README.md` — portable identity](../README.md#portable-ssh-identity-for-git-vt) | `src/ssh_sign.rs`, `src/client.rs` |
| Understand agent signing, identity selection, and decrypt-then-sign fallback | [`sign-vt-design.md`](sign-vt-design.md) | `src/ssh_sign.rs` (`resolve_identities`, `decide_sign_route`), `src/client.rs` (`VTClient::sign_vt`), `src/server_macos/ssh_agent/handlers.rs` (`handle_sign_vt`) |
| Understand extension errors | [`structured-errors.md`](structured-errors.md) | `src/core/wire.rs`, `src/client.rs` |
| Understand SSH-agent authorization and caching | [`unified-authorization-engine.md`](unified-authorization-engine.md) | `src/core/authorization.rs`, `src/server_macos/authorization.rs`, `src/server_macos/ssh_agent.rs` (dispatcher), `src/server_macos/ssh_agent/handlers.rs` (operations) |
| Understand grant scopes (destination / workspace / relay) | [`authorization-scopes-v2.md`](authorization-scopes-v2.md) | `src/core/authorization.rs` (`GrantScope`), `src/server_macos/ssh_agent/scopes.rs` (`BindState`, `resolve_workspace`), `src/server_macos/ssh_agent/scopes/process.rs` (kernel queries), `src/server_macos/ssh_agent/scopes/paths.rs` (path policy) |
| Enable agent audit push | [`agent-audit.md`](agent-audit.md) | `src/audit.rs`, `src/server_macos/audit.rs` |
| Understand prompt/notification fields and audit context | [`approval-transparency.md`](approval-transparency.md) | `src/caller_meta.rs` (client-claimed display fields), `src/server_macos/ssh_agent/handlers.rs` (operation prompts), `src/server_macos/ssh_agent/scopes.rs` (truth lines), `cf-worker/src/notify.ts`, `cf-worker/pwa/approve.js` |
| Diagnose config/routing/caching (`vt doctor`) | [`diag-design.md`](diag-design.md) | `src/client/doctor.rs`, `src/config/client.rs` (shared routing), `src/server_macos/ssh_agent/handlers.rs` (`handle_diag`) |
| Build/install VT.app, menu bar UI, native notifications, key-wrap rebind | [`app-bundle.md`](app-bundle.md) | `app/VTShell.swift`, `src/server_macos/security.rs` (`notify_macos`, `upgrade_wrap_v2_if_needed`), `src/core/crypto.rs` (`derive_passphrase_secret_v2`) |
| Configure Slack App notifications | [`slack-app.md`](slack-app.md) | `cf-worker/src/slack_app.ts` |
| Configure Feishu/Lark notifications | [`feishu.md`](feishu.md) | `cf-worker/src/feishu.ts` |

## Reading guide

Each feature document owns its current contract; filenames ending in `-design`
do not imply pending work. In particular:

- [`sign-vt-design.md`](sign-vt-design.md) owns SSH identity selection and fallback;
  [`ssh-vt-design.md`](ssh-vt-design.md) covers portable storage and relay rationale.
- [`feishu.md`](feishu.md) owns setup;
  [`feishu-design.md`](feishu-design.md) covers delivery lifecycle and API boundaries.

Implementation history belongs in Git. Verify older decision notes against code
before treating them as current requirements.

## Editing workflow

Find the symbol with `rg`, read its owning document and implementation, then
update that document with the smallest coherent change. Run focused tests before
the relevant [repository gates](../AGENTS.md#validation-and-deployment-entry-points).
Linux checks do not validate macOS-only behavior. Update this map only when
ownership or entry points change.

## Change routing

| Change | Update |
|---|---|
| CLI command or flag | `README.md`, `src/main.rs` help, and the feature doc |
| `VT_*` variable or config-file behavior | `config.example.toml`, `README.md`, `src/config.rs` |
| Worker secret, route, or admin page | `cf-worker-deploy.md`, `cf-worker/wrangler.toml.example`, relevant channel/cache doc |
| Wire format or exit code | `structured-errors.md` and protocol tests |
| Security invariant | the relevant design doc plus a code comment/test |

[`AGENTS.md`](../AGENTS.md) is the canonical agent guide; `CLAUDE.md` is its
compatibility symlink. Keep red lines and test gates there, not a second product
manual; user-facing procedures belong here or in the linked feature documents.
