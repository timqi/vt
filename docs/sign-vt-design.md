# SSH identity and forwarding

This document defines how vt supplies SSH identities without requiring every
host to retain a plaintext private key. System SSH owns connection setup,
`known_hosts`, SSH configuration, and exit status.

## Key custody

| Identity | Where signing happens | Exposure |
|---|---|---|
| Keychain-backed key | macOS agent after authorization | Caller receives a signature, not the private key |
| Portable `vt://` record | Connecting process after decryption | Seed remains in caller memory until connect exits |

`vt ssh add` imports an Ed25519 key into the Mac store. `vt ssh keygen` creates
a portable identity on macOS or Linux without importing it into that store.
These may be separate identities; distributing a portable copy is an explicit
choice to permit private-key decryption outside the agent.

An agent-held key is ordinary decrypted memory, not a Secure Enclave
non-exportable key. Standard SSH signing can also use it; client-supplied vt
context is not mandatory provenance for every use of the key.

## Identity selection

- `VT_GIT_SSH_PUB`, otherwise the default public-key file, selects one identity;
  malformed explicit keys fail rather than triggering discovery.
- Without an explicit public key, an agent-enabled route discovers all upstream
  identities; discovery failure is fatal.
- Discovered keys have no portable fallback. A private record alone is not a
  source of the public identity.
- An explicit public key may pair with `VT_GIT_SSH_PRIVATE_KEY`, otherwise the
  default ciphertext file. These variables contain values, not paths.
- Backend pins remain authoritative: `passkey` skips agent discovery/signing;
  `agent` prohibits Worker decryption.

The ephemeral signer advertises only the resolved identities. Its private socket
is pinned for the SSH child so SSH configuration cannot bypass it; the parent
retains the upstream socket. This restriction does not filter relayed extension
payloads, whose upstream authorization is separate.

## Portable records

Keygen writes `~/.config/vt/git-ssh` (ciphertext, mode 600) and `git-ssh.pub`
(public key, mode 644). A custom `--key-file` destination is not automatically
discovered by connect. Existing files and symlinks are refused; failure writing
the public file can leave the ciphertext file, since the pair is not atomic.

The portable seed is a base64url-without-padding 32-byte Ed25519 seed in an
ordinary raw v2 record. Copy both files and keep their pairing: connect does not
independently compare the decrypted seed's public key to the advertised key.
Ciphertext possession alone does not authorize decrypting it.

Prefer the default files. Unrestricted `vt inject` scans environment values for
`vt://`; keep the private record out of inherited environment variables or use
`--only-env` to limit decryption. Keygen/connect never write the plaintext seed
to disk, but temporary buffers do not provide a complete memory-erasure guarantee.

## Fallback

Agent signing is preferred when the route permits it. A fallback-eligible error
allows decrypt-then-sign only when the selected identity has a portable record;
the decrypt uses the same configured backend policy.

- Explicit rejection and bad requests are terminal; never retry them by decrypting.
- Other classified agent/transport failures can allow fallback; malformed sign
  responses and unclassified client failures remain errors.
- Eligibility does not prove that no prompt occurred: an operation can fail
  after approval, so a second approval is possible.
- A successfully decrypted seed is reused for that connect process, independently
  of agent grant TTLs. Revoking a grant cannot erase an already-exported seed.

The shared error classification belongs to
[structured-errors.md](structured-errors.md); agent reuse policy belongs to
[unified-authorization-engine.md](unified-authorization-engine.md).

## Forwarded relay

`vt ssh connect --forward-real-agent` enables a filtering relay through the
child's ephemeral socket. The flag must precede SSH arguments; it requires
OpenSSH's socket-path forwarding support (8.2+). It pins the forwarded socket
so SSH configuration cannot expose the upstream agent unfiltered.

| Extension | Relay action |
|---|---|
| `encrypt@vt`, `decrypt@vt`, `auth@vt`, `sign@vt`, `diag@vt` | Forward unchanged |
| `run@vt`, `ui-status@vt`, `session-bind@openssh.com`, unknown names | Refuse |

Without the flag, the ephemeral agent refuses all extensions. The relay opens
an upstream connection for each request and never parses the payload. The
remote CLI needs an agent-enabled route; any fallback remains subject to its
backend pin and available portable record.

- A process that can open the forwarded socket can request any upstream key,
  including keys the ephemeral signer did not advertise; the upstream agent
  still authorizes each request.
- Forwarded vt grants remain connection-confined; raw forwarding-capable signs
  never cache. Neither can reuse local activity grants.
- `auth@vt` is always fresh; diagnostics are read-only; encryption needs no
  operation approval. Direct `ssh -A` of the real agent exposes a broader surface.
- Portable fallback may export a seed into remote memory. Enable forwarding
  only for hosts whose processes should be able to request these operations.

## Use

For a portable identity, configure an approval backend and run:

```bash
vt ssh keygen -l github
git config --global core.sshCommand "vt ssh connect"
```

Register the printed public key with the server. For a Mac-only identity,
import an existing Ed25519 key with `vt ssh add -f <file>` and register its
public key; omit portable ciphertext to require agent signing. An explicit
public-key file selects one key, while omitting it enables agent discovery.

Implementation and focused tests: [src/ssh_sign.rs](../src/ssh_sign.rs).
