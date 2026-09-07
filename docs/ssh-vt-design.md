# SSH-over-`vt://` design

Implemented reference for portable key storage and the optional forwarded relay.
Setup is in [README.md](../README.md#portable-ssh-identity-for-git-vt);
[sign-vt-design.md](sign-vt-design.md) owns identity resolution, signing routes,
fallback errors, and provisioning. Implementation history is in Git.

## Portable record

`vt ssh keygen` generates an Ed25519 key in memory and encrypts its 32-byte
seed as a normal `SecretType::RAW` v2 record. The plaintext is exactly
`BASE64_URL_SAFE_NO_PAD(seed)`: 43 ASCII characters, no padding or new type byte.
Envelope parsing and encryption remain the shared implementation in
`src/core.rs` and `src/core/crypto.rs`; the Worker needs no SSH-specific storage.

Default output:

```text
~/.config/vt/git-ssh        # ciphertext vt://0 record, mode 0600
~/.config/vt/git-ssh.pub    # matching OpenSSH public key, mode 0644
```

`--key-file` changes keygen's output path. Files are created exclusively with
`O_NOFOLLOW`; existing files are refused, not overwritten. The two writes are
not atomic as a pair: a public-key write failure can leave the ciphertext file.
Keygen prints the public key and ciphertext, never the plaintext seed, and does
not import the identity into the macOS agent.

Connect reads raw content from `VT_GIT_SSH_PRIVATE_KEY` / `VT_GIT_SSH_PUB`, with
default-file fallback. These variables are not paths or keygen destinations.
Copy both files when distributing an identity; ciphertext possession alone does
not authorize decryption. A custom keygen path is not automatically discovered
by connect. See the signing contract for precedence and agent discovery.

Prefer the default file: unrestricted `vt inject` scans inherited environment
values for `vt://` and could decrypt `VT_GIT_SSH_PRIVATE_KEY` into the child's
environment. Keep it out of that environment or restrict injection with
`--only-env`. Never store the plaintext seed in a file or environment variable.

## Signing lifetime and platform

`src/ssh_sign.rs` implements keygen/connect on Unix, including macOS and Linux.
Local vault and agent management remain macOS-only. System `ssh` owns transport,
`known_hosts`, SSH configuration, and exit status; VT supplies an ephemeral
signer in a mode-0700 directory with a mode-0600 socket.

The child alone receives `SSH_AUTH_SOCK` and a leading
`-o IdentityAgent=<ephemeral socket>`. The parent retains the upstream socket,
preventing signer self-connection and SSH-config bypass of the signer.

Agent signing keeps the private key on the Mac. Eligible fallback with a
portable record decrypts and signs in the caller, including on a remote host.
The decoded seed is held in `OnceCell<Zeroizing<[u8; 32]>>` per identity until
connect exits; failed initialization is retriable. Revoking an agent grant does
not erase this already-exported seed. Temporary decrypt strings and decode
buffers are not all zeroizing, so this is not a complete memory-erasure guarantee.
No plaintext seed is written to disk by keygen/connect.

Backend pins and explicit refusal behavior apply to both paths; do not infer
unconditional Worker fallback or one approval per signature. See
[sign-vt-design.md](sign-vt-design.md#4-fallback-contract-and-security-differences).

## 11. Forwarded relay: `vt ssh connect --forward-real-agent`

Off by default. The flag must precede SSH arguments. It enables a filtering
extension relay through the ephemeral socket and pins the child's
`ForwardAgent` to that socket (OpenSSH >= 8.2 path form), preventing SSH config
from forwarding the real agent unfiltered. Standard forwarding gives each SSH
connection its own remote socket and automatic cleanup.

The upstream path is captured at startup from `SSH_AUTH_SOCK`, otherwise
`~/.ssh/vt.sock`. Each relayed request opens a fresh upstream connection.
`route_extension` filters the cleartext extension name; the relay does not use
VT_AUTH to decrypt payloads and forwards request/response payloads unchanged.
The remote CLI needs the shared VT_AUTH and an agent-enabled route.

| Extension | Action |
|---|---|
| `encrypt@vt`, `decrypt@vt`, `auth@vt`, `sign@vt`, `diag@vt` | Relay |
| `run@vt`, `ui-status@vt`, `session-bind@openssh.com`, unknown names | Refuse |

Without the flag all extensions are refused. Refusal or unreachable upstream
returns `SSH_AGENT_FAILURE`; any client fallback remains subject to its error
classification, configured backend, and available portable record.

Security boundaries:

- The relay cannot filter encrypted `sign@vt` payloads by key. An authenticated
  remote can request any upstream key, not just the advertised git identity.
  The agent authorizes the operation and shows its own key label and relay origin.
- Relay/SSH-carried VT grants remain connection-confined; they cannot reuse
  local workspace grants. Relay detection uses kernel-derived argv and scopes
  to the relay process `(pid, start)`. Spoofing a relay match only narrows scope.
  Forwarding-capable raw signs never cache. Exact policy belongs to
  [authorization-scopes-v2.md](authorization-scopes-v2.md).
- `auth@vt` stays fresh; `diag@vt` is read-only, prompt-free, and never resets
  idle. Encrypt is approval-free. `run@vt` is deliberately blocked, unlike
  direct forwarding of the real agent.
- Any remote process able to open the forwarded socket can request operations
  or reuse that connection's approved grants. Enable forwarding only for trusted
  hosts. Agent signing avoids exporting a seed only when the agent holds the key;
  a portable fallback still exposes it to remote memory.

## Verification

`src/ssh_sign.rs` contains seed-encoding, path, argument parsing, identity,
sign-route, relay-filter, and relay-classification tests. Notification and grant
behavior also require the native checks linked from the
[signing contract](sign-vt-design.md#6-verification-entry-points).

```bash
cargo test --locked ssh_sign::tests
just check
```

Linux checks cover the portable implementation, not macOS Keychain, Touch ID,
or native process classification. Repository-wide gates are in
[AGENTS.md](../AGENTS.md#validation-and-deployment-entry-points).
