//! Secure Enclave custody of the master key (wrap v3, docs/app-bundle.md#master-key-wrap-v3):
//! key generation, `kSecAttrTokenOID` blob export/import, ECIES wrap/unwrap.
//!
//! The SE key is non-permanent: nothing is written to any keychain, so no
//! restricted entitlement is needed; the SE-wrapped private key travels in
//! the store as an opaque device-bound blob. Verified platform facts are in
//! docs/secure-enclave.md.

use core_foundation::base::{CFType, TCFType, ToVoid};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFMutableDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::string::CFString;
use objc2::rc::Retained;
use objc2_local_authentication::LAContext;
use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, kSecAccessControlPrivateKeyUsage,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrTokenID, kSecAttrTokenIDSecureEnclave, kSecUseAuthenticationContext,
};
use security_framework_sys::key::SecKeyCreateWithData;
use zeroize::Zeroizing;

const ALG: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
/// `kSecAttrTokenOID` is not declared by security-framework-sys.
const TOKEN_OID: &str = "toid";
/// ECIES output for a 32-byte plaintext: 65-byte ephemeral public key,
/// 32-byte ciphertext, 16-byte GCM tag.
pub const WRAPPED_MASTER_LEN: usize = 65 + 32 + 16;

/// Stable operator-facing failure codes (docs/structured-errors.md#secure-enclave).
#[derive(Debug)]
pub enum SeError {
    /// No usable Secure Enclave: key generation refused.
    Unavailable(String),
    /// The stored blob could not be turned back into a key handle.
    BlobRejected(String),
    /// The SE refused to unwrap: biometry not satisfied by this context, the
    /// enrolled fingerprint set changed, or the ciphertext is not this key's.
    UnwrapFailed(String),
    /// Wrapped or stored material has the wrong shape.
    Malformed,
}

impl SeError {
    pub fn code(&self) -> &'static str {
        match self {
            SeError::Unavailable(_) => "se.unavailable",
            SeError::BlobRejected(_) => "se.blob_rejected",
            SeError::UnwrapFailed(_) => "se.unwrap_failed",
            SeError::Malformed => "se.malformed",
        }
    }
}

impl std::fmt::Display for SeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeError::Unavailable(e) => write!(
                f,
                "{}: Secure Enclave key generation failed ({e}); wrap v3 needs Apple Silicon or T2",
                self.code()
            ),
            SeError::BlobRejected(e) => write!(f, "{}: SE key blob rejected ({e})", self.code()),
            SeError::UnwrapFailed(e) => write!(
                f,
                "{}: Secure Enclave refused to unwrap the master key ({e}); if Touch ID enrollment \
                 changed, recover with `vt secret import`",
                self.code()
            ),
            SeError::Malformed => write!(f, "{}: SE store fields malformed", self.code()),
        }
    }
}

impl std::error::Error for SeError {}

/// An `LAContext` that evaluated `DeviceOwnerAuthenticationWithBiometrics`.
/// Held only to keep the SE authorization alive; never messaged again except
/// `invalidate()` on drop.
pub struct BiometricContext(Retained<LAContext>);

// SAFETY: the context is retained, bound once into `SecKeyCreateWithData`,
// and invalidated on drop; it is never messaged concurrently.
unsafe impl Send for BiometricContext {}

impl BiometricContext {
    /// Caller guarantees the context evaluated the biometric policy successfully.
    pub(super) fn from_evaluated(ctx: Retained<LAContext>) -> Self {
        // Custody operations run under a live permit. A cold or expired
        // platform context must fail, never start another system prompt.
        unsafe { ctx.setInteractionNotAllowed(true) };
        Self(ctx)
    }
}

impl Drop for BiometricContext {
    /// Advisory: ctkd keeps the last context warm until another context uses
    /// the token. Dropping the handle is the boundary; this only shortens it.
    fn drop(&mut self) {
        unsafe { self.0.invalidate() };
    }
}

fn cf_err(err: CFErrorRef) -> String {
    if err.is_null() {
        return "unknown".into();
    }
    format!("{:?}", unsafe { CFError::wrap_under_create_rule(err) })
}

fn cf_str(r: core_foundation::string::CFStringRef) -> CFType {
    unsafe { CFString::wrap_under_get_rule(r).as_CFType() }
}

/// Generate a non-permanent SE P-256 key gated by the current biometric set
/// and return `(toid blob, ECIES ciphertext of master)`.
pub fn generate_and_wrap(master: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>), SeError> {
    let ac = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
    )
    .map_err(|e| SeError::Unavailable(e.to_string()))?;
    let mut opts = GenerateKeyOptions::default();
    // No `set_location`: `kSecAttrIsPermanent` false, nothing hits a keychain.
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(ac);
    let key = SecKey::new(&opts).map_err(|e| SeError::Unavailable(format!("{e:?}")))?;
    let blob = key
        .attributes()
        .find(CFString::from_static_string(TOKEN_OID).to_void())
        .map(|v| unsafe { CFData::wrap_under_get_rule(v.cast()) }.to_vec())
        .ok_or_else(|| SeError::Unavailable("key has no kSecAttrTokenOID".into()))?;
    let wrapped = key
        .public_key()
        .ok_or_else(|| SeError::Unavailable("no public key".into()))?
        .encrypt_data(ALG, master)
        .map_err(|e| SeError::Unavailable(format!("{e:?}")))?;
    if wrapped.len() != WRAPPED_MASTER_LEN {
        return Err(SeError::Malformed);
    }
    Ok((blob, wrapped))
}

/// Shape check for stored material, usable before any prompt.
pub fn check_material(blob: &[u8], wrapped: &[u8]) -> Result<(), SeError> {
    if blob.is_empty() || wrapped.len() != WRAPPED_MASTER_LEN {
        return Err(SeError::Malformed);
    }
    Ok(())
}

/// One biometric approval bound to the SE key handle: unwraps without a
/// further prompt for as long as it is held. Memory-only, never cloned;
/// dropping it is the revocation boundary (docs/secure-enclave.md).
pub struct SeSession {
    key: SecKey,
    _ctx: BiometricContext,
}

impl SeSession {
    /// Rebuild the private-key handle from the stored blob under `ctx`. The
    /// blob travels as `kSecAttrTokenOID`; passing it as the key data would
    /// mint a new key.
    pub fn open(blob: &[u8], ctx: BiometricContext) -> Result<Self, SeError> {
        let mut attrs = CFMutableDictionary::<CFType, CFType>::new();
        let key = unsafe {
            attrs.set(
                CFString::from_static_string(TOKEN_OID).as_CFType(),
                CFData::from_buffer(blob).as_CFType(),
            );
            attrs.set(
                cf_str(kSecAttrKeyType),
                cf_str(kSecAttrKeyTypeECSECPrimeRandom),
            );
            attrs.set(cf_str(kSecAttrKeyClass), cf_str(kSecAttrKeyClassPrivate));
            attrs.set(
                cf_str(kSecAttrTokenID),
                cf_str(kSecAttrTokenIDSecureEnclave),
            );
            let raw = Retained::as_ptr(&ctx.0) as *const std::os::raw::c_void;
            attrs.set(
                cf_str(kSecUseAuthenticationContext),
                CFType::wrap_under_get_rule(raw),
            );
            let mut err: CFErrorRef = std::ptr::null_mut();
            let k = SecKeyCreateWithData(
                CFData::from_buffer(&[]).as_concrete_TypeRef(),
                attrs.to_immutable().as_concrete_TypeRef(),
                &mut err,
            );
            if k.is_null() {
                return Err(SeError::BlobRejected(cf_err(err)));
            }
            SecKey::wrap_under_create_rule(k)
        };
        Ok(Self { key, _ctx: ctx })
    }

    /// Unwrap the 32-byte master. Callers derive from it and drop it in the
    /// same scope; it never crosses an await or a prompt.
    pub fn unwrap_master(&self, wrapped: &[u8]) -> Result<Zeroizing<[u8; 32]>, SeError> {
        let plain = Zeroizing::new(
            self.key
                .decrypt_data(ALG, wrapped)
                .map_err(|e| SeError::UnwrapFailed(format!("{e:?}")))?,
        );
        let mut master = Zeroizing::new([0u8; 32]);
        let slice: &[u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| SeError::Malformed)?;
        master.copy_from_slice(slice);
        Ok(master)
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use super::*;

    pub(crate) fn software_store(
        master: &[u8; 32],
    ) -> (crate::server_macos::store::KeychainStore, SeSession) {
        let session = software_session();
        let wrapped = session
            .key
            .public_key()
            .unwrap()
            .encrypt_data(ALG, master)
            .unwrap();
        (
            crate::server_macos::store::KeychainStore::new_v3(&[1; 8], &wrapped),
            session,
        )
    }

    /// A session over a software EC key and a never-evaluated context: enough
    /// to exercise slot lifecycle without Secure Enclave hardware.
    pub(crate) fn software_session() -> SeSession {
        let mut opts = GenerateKeyOptions::default();
        opts.set_key_type(KeyType::ec()).set_size_in_bits(256);
        let key = SecKey::new(&opts).expect("software EC key");
        let ctx = unsafe { LAContext::new() };
        SeSession {
            key,
            _ctx: BiometricContext(ctx),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_context_cannot_prompt_during_unwrap() {
        // No policy evaluation: this only tests the context's UI setting.
        let ctx = BiometricContext::from_evaluated(unsafe { LAContext::new() });
        assert!(unsafe { ctx.0.interactionNotAllowed() });
    }

    #[test]
    fn check_material_rejects_wrong_shapes() {
        assert!(check_material(&[1], &[0u8; WRAPPED_MASTER_LEN]).is_ok());
        assert!(matches!(
            check_material(&[], &[0u8; WRAPPED_MASTER_LEN]),
            Err(SeError::Malformed)
        ));
        assert!(matches!(
            check_material(&[1], &[0u8; 32]),
            Err(SeError::Malformed)
        ));
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(SeError::Unavailable(String::new()).code(), "se.unavailable");
        assert_eq!(
            SeError::BlobRejected(String::new()).code(),
            "se.blob_rejected"
        );
        assert_eq!(
            SeError::UnwrapFailed(String::new()).code(),
            "se.unwrap_failed"
        );
        assert_eq!(SeError::Malformed.code(), "se.malformed");
        assert!(SeError::Malformed.to_string().starts_with("se.malformed"));
    }

    /// Hardware: generate, wrap, reopen the blob under a fresh biometric
    /// context (one Touch ID), unwrap twice without a second prompt, and
    /// refuse a foreign ciphertext.
    #[test]
    #[ignore]
    fn se_generate_wrap_reopen_unwrap() {
        use crate::server_macos::security::authenticate_ctx;
        let master = crate::core::crypto::AesGcmCrypto::generate_key();
        let (blob, wrapped) = generate_and_wrap(&master).expect("SE available");
        eprintln!("blob {} bytes, wrapped {} bytes", blob.len(), wrapped.len());
        check_material(&blob, &wrapped).unwrap();

        let (outcome, ctx) = authenticate_ctx("vt se test: unwrap master");
        assert!(outcome.is_success(), "Touch ID failed: {outcome:?}");
        let session = SeSession::open(&blob, ctx.expect("biometric context")).expect("open");
        for i in 1..=2 {
            let t = std::time::Instant::now();
            let got = session.unwrap_master(&wrapped).expect("unwrap");
            eprintln!("unwrap #{i} in {:?}", t.elapsed());
            assert_eq!(got.as_slice(), &master);
        }
        let mut foreign = wrapped.clone();
        foreign[70] ^= 1;
        assert!(matches!(
            session.unwrap_master(&foreign),
            Err(SeError::UnwrapFailed(_))
        ));
        eprintln!("expect exactly one Touch ID prompt above");
    }
}
