# Secure Enclave master-key wrap

This document records the verified platform facts for wrapping the local
master key under a Secure Enclave (SE) key instead of the passcode-derived
wrap v2 ([app-bundle.md](app-bundle.md#master-key-wrap-v2)). It is design
input, not a shipped contract: no store writes wrap v3 today.

## Threat model

- The master key is a symmetric secret shared with the phone (PRF-wrapped
  copy) and is the HKDF IKM for every DEK. It must enter process memory on
  every use; SE wrapping does not hide it from a live kernel or in-process
  attacker.
- SE wrapping gains: a Keychain dump, disk image, or backup yields an
  SE-bound blob that is useless off this device and unusable on it without a
  live biometric match, which the SEP verifies itself.
- Making the master never leave the SE would require sealing each record to
  an SE public key and a phone key (new `vt://` record format across CLI,
  Worker, and PWA); out of scope.

## Verified facts

Measured on Apple Silicon macOS, 2026-09-22, with the `#[ignore]` test
`spike_se_wrap_v3` in [security.rs](../src/server_macos/security.rs).

### Key storage

- A permanent SE key lives in the data-protection keychain and needs the
  restricted `keychain-access-groups` entitlement. Without it generation
  fails with `-34018`; with it, ad-hoc and self-signed binaries are killed by
  AMFI (`-424` "adhoc signed but contains restricted entitlements",
  `-413` "No matching profile found"). Only an Apple-issued signing identity
  can take that path.
- A non-permanent SE key (`kSecAttrIsPermanent = false`, no keychain
  location) needs no entitlement. `SecKeyCopyAttributes` exposes the
  SE-wrapped private key as `kSecAttrTokenOID` (`toid`, ~570 bytes); this is
  what CryptoKit calls `dataRepresentation`. The access control
  (`biometryCurrentSet | privateKeyUsage`,
  `WhenUnlockedThisDeviceOnly`) travels inside the blob.
- Reload with `SecKeyCreateWithData(empty, {kSecAttrTokenOID: blob,
  kSecAttrTokenID: SecureEnclave, kSecAttrKeyType: ECSECPrimeRandom,
  kSecAttrKeyClass: private[, kSecUseAuthenticationContext: ctx]})`. Passing
  the blob as the key-data argument instead makes the token mint a new key
  silently; the mismatch surfaces only as an AES-GCM failure on unwrap.
- The blob is bound to the device, not to the code signature: a rebuilt
  binary with a new ad-hoc cdhash reloads it.
- Wrap: ECIES `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM`
  with the public key; 32 bytes → 113 bytes (65-byte ephemeral key, 32-byte
  ciphertext, 16-byte tag).

### Authorization context

- A handle built without a context prompts through the system UI on every
  unwrap.
- A handle built with an evaluated `LAContext` (policy
  `DeviceOwnerAuthenticationWithBiometrics`) unwraps repeatedly in about
  5 ms with no further prompt for as long as the process holds it; 40 s of
  idle showed no expiry.
- `invalidate()` and dropping the context do not close a warm handle. ctkd
  keeps the last context used on the token authorized until another context
  performs an operation on that token; only then does the invalidated
  context fail (`LAContext.externalizedContext failed`).
- A never-evaluated context always prompts: there is no SEP-side grace
  window shared across contexts.

## Design constraints for wrap v3

- Store the `toid` blob and the ECIES ciphertext in the existing
  `rusty.vault.store` item; the passcode half of `passcode_and_auth_token`
  stops participating in derivation.
- Bind the engine's approval `LAContext` to the SE handle so one Touch ID is
  both the vt approval and the unwrap. A reusable grant holds `(LAContext,
  SecKey)` in memory and revocation drops both; `invalidate()` is advisory,
  never the boundary.
- Fresh-approval operations build a new context per operation.
- No SE (Intel without T2, VMs, CI) fails closed. Wrap v2 stays readable for
  one release as the migration source, then its test becomes a
  rejected-input test.
- Dependencies already present: `security-framework` with `OSX_10_13`
  (`kSecUseAuthenticationContext`, `SecKeyCreateWithData`),
  `security-framework-sys`, `core-foundation`.

## Not verified

- Intel/T2 hardware and virtual machines.
- Behavior of `biometryCurrentSet` after fingerprint enrollment changes
  (expected: blob becomes permanently unusable; recovery is the phone copy).
- Whether ctkd's warm-context cache is per process or per token session.
