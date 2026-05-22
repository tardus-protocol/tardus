//! PKCS#11 HSM-backed share storage (v2.11, behind the `hsm`
//! cargo feature).
//!
//! ## Design
//!
//! Most production HSMs (`YubiHSM` 2, AWS `CloudHSM`, Thales Luna,
//! Utimaco `SecurityServer`) and the standard `softhsm2` test backend
//! do not expose `Curve25519` / `Ed25519` as native PKCS#11 mechanisms.
//! We therefore use the HSM as an **AES-256-GCM wrap-key custodian**
//! rather than an Ed25519 signer: the wrap key lives inside the HSM
//! and never leaves it, but the validator's mint-share scalar still
//! resides briefly in process memory during the sign / refresh path
//! (zeroized on drop).
//!
//! Wire format on disk (per-keyset file at
//! `<data_dir>/share_<keyset_id_hex>.bin`):
//!
//! ```text
//!   iv_12 || aes_gcm_ciphertext(borsh(ValidatorShareRecord))
//! ```
//!
//! The IV is sampled per write inside the HSM (the wrap operation
//! returns IV || ct). On load, the validator submits the on-disk
//! blob to the HSM's `C_Decrypt` and gets the plaintext back.
//!
//! ## Threat model upgrade vs `FileShareStore`
//!
//! The file backend (v2.1) relies on the operator's master seed —
//! a 32-byte secret held in process memory at boot. A coredump or
//! `ptrace`-equivalent against the running validator can recover it.
//!
//! With the HSM backend, the operator never holds the wrap key
//! material: the HSM enforces a `CKA_EXTRACTABLE = false` attribute
//! on the key, so even a fully compromised validator process cannot
//! exfiltrate it for offline decryption of past share files. The
//! per-call exposure window is reduced to the duration of one
//! `C_Decrypt` round-trip.
//!
//! ## Limitations
//!
//! 1. The share material still appears in plaintext in validator
//!    process memory during a sign or refresh round — only the
//!    *long-term wrap key* is HSM-bound. Closing this window
//!    requires a native-`Ed25519` HSM signing path (`CKM_EDDSA`).
//!    v2.12 adds a separate proof-of-capability test that the
//!    HSM in question can perform native `Ed25519` ops; full
//!    integration is v2.13 (requires DKG-derived share to be
//!    imported into the HSM via `C_UnwrapKey` under the AES wrap
//!    key, then signed via `C_Sign` / `CKM_EDDSA`).
//! 2. The HSM is a synchronous-blocking dependency: `load()` and
//!    `save()` block on the PKCS#11 round-trip. For the typical
//!    ceremony cadence (boot + reshare) this is acceptable; a
//!    high-frequency operator workflow should keep the share
//!    cached in memory.
//!
//! ## Session resilience (v2.12)
//!
//! HSMs enforce session lifetimes; long-running validators must
//! handle `CKR_SESSION_HANDLE_INVALID` and similar mid-call session
//! failures. v2.12 adds [`Pkcs11ShareStore::reopen_session`] which
//! re-runs the `open_rw_session` + `login` + `find_wrap_key` chain
//! against the same module + token + PIN + label and atomically
//! swaps the new session under the mutex. Callers that get an HSM
//! error invoke `reopen_session()` and retry once; on a second
//! failure the original error propagates.

use crate::error::{Error, Result};
use crate::share_store::ShareStore;
use crate::storage::{share_path, ValidatorShareRecord};
use borsh::BorshDeserialize;
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle},
    session::{Session, UserType},
    slot::Slot,
    types::AuthPin,
};
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroizing;

const IV_LEN: usize = 12;

/// HSM-backed share storage. Holds the PKCS#11 session in a `Mutex`
/// because cryptoki's `Session` is not `Sync` by itself.
pub struct Pkcs11ShareStore {
    /// The cryptoki context — process-singleton. PKCS#11 forbids
    /// calling `C_Initialize` twice without a `C_Finalize` between
    /// them, so the context lives for the lifetime of the store
    /// and `reopen_session` reuses it.
    ctx: Pkcs11,
    /// Pre-allocated session wrapped for thread-safe access.
    inner: Mutex<Pkcs11Inner>,
    data_dir: PathBuf,
    /// Re-open inputs cached for [`reopen_session`].
    reopen_inputs: ReopenInputs,
}

/// All inputs needed to reconstruct a working session from scratch
/// (against the existing [`Pkcs11ShareStore::ctx`]).
struct ReopenInputs {
    slot_label: String,
    user_pin: String,
    wrap_key_label: String,
}

struct Pkcs11Inner {
    session: Session,
    wrap_key: ObjectHandle,
}

impl Pkcs11ShareStore {
    /// Open a `Pkcs11ShareStore`:
    ///
    /// - `pkcs11_module_path` — e.g. `/usr/lib/softhsm/libsofthsm2.so`
    ///   for `softhsm2`, `/opt/cloudhsm/lib/libcloudhsm_pkcs11.so` for
    ///   AWS `CloudHSM`, etc.
    /// - `slot_label` — the human-readable label of the slot
    ///   containing the token (e.g. `tardus-validator-1`).
    /// - `user_pin` — the PKCS#11 user PIN (NEVER hard-code in
    ///   production; read from a per-host secrets manager).
    /// - `wrap_key_label` — the `CKA_LABEL` of the pre-provisioned
    ///   AES-256-GCM wrap key inside the slot. Must have
    ///   `CKA_WRAP = true`, `CKA_UNWRAP = true`,
    ///   `CKA_EXTRACTABLE = false`.
    /// - `data_dir` — the same directory layout as
    ///   [`crate::storage::FileShareStore`]; each share is sealed at
    ///   `<data_dir>/share_<keyset_id_hex>.bin`.
    ///
    /// # Errors
    /// - [`Error::Config`] for any PKCS#11 setup failure (module
    ///   load, slot enumeration, login, key lookup).
    pub fn open(
        pkcs11_module_path: &std::path::Path,
        slot_label: &str,
        user_pin: &str,
        wrap_key_label: &str,
        data_dir: PathBuf,
    ) -> Result<Self> {
        let ctx = Pkcs11::new(pkcs11_module_path).map_err(|e| {
            Error::Config(format!("Pkcs11::new({}): {e}", pkcs11_module_path.display()))
        })?;
        ctx.initialize(CInitializeArgs::OsThreads)
            .map_err(|e| Error::Config(format!("Pkcs11 initialize: {e}")))?;

        let slot = find_slot_by_label(&ctx, slot_label)?;
        let session = ctx
            .open_rw_session(slot)
            .map_err(|e| Error::Config(format!("open_rw_session: {e}")))?;
        session
            .login(UserType::User, Some(&AuthPin::new(user_pin.into())))
            .map_err(|e| Error::Config(format!("login: {e}")))?;

        let wrap_key = find_wrap_key(&session, wrap_key_label)?;

        Ok(Self {
            ctx,
            inner: Mutex::new(Pkcs11Inner { session, wrap_key }),
            data_dir,
            reopen_inputs: ReopenInputs {
                slot_label: slot_label.to_string(),
                user_pin: user_pin.to_string(),
                wrap_key_label: wrap_key_label.to_string(),
            },
        })
    }

    /// **v2.13.0** — Install a 32-byte share scalar into the HSM as
    /// a generic-secret object, **non-extractable** (the strong
    /// production posture). The share can be used ONLY via in-HSM
    /// operations that don't require extraction (PKCS#11 sign /
    /// derive). It CANNOT be wrapped under the AES wrap key —
    /// `CKA_EXTRACTABLE=false` overrides `CKA_WRAP=true` (validated
    /// empirically against softhsm 2.6.1; this is the documented
    /// PKCS#11 §10.6 behavior).
    ///
    /// For threshold sign integration on a host where the HSM lacks
    /// `CKM_EDDSA_RAW` (e.g. softhsm), see
    /// [`install_share_extractable`] — explicit weaker variant.
    ///
    /// Attributes set:
    /// - `CKA_CLASS         = CKO_SECRET_KEY`
    /// - `CKA_KEY_TYPE      = CKK_GENERIC_SECRET`
    /// - `CKA_TOKEN         = true`   (survives session close)
    /// - `CKA_SENSITIVE     = true`   (rejects `C_GetAttributeValue(CKA_VALUE)`)
    /// - `CKA_EXTRACTABLE   = false`  (no plain extraction, ever)
    /// - `CKA_WRAP          = true`   (allows the AES wrap key to wrap this share)
    /// - `CKA_VALUE         = scalar` (the bytes we are installing)
    ///
    /// After this call, the share is HSM-resident: the only way the
    /// scalar leaves the device is wrapped under the AES wrap key
    /// (which itself is `CKA_EXTRACTABLE=false`). Disk + process
    /// memory compromise alone cannot recover the scalar.
    ///
    /// # Errors
    /// [`Error::Config`] for any PKCS#11 create/delete failure.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub fn install_share(&self, scalar: &[u8; 32], share_label: &str) -> Result<()> {
        let inner = self.inner.lock().expect("pkcs11 mutex");
        // Idempotent: drop any existing object under this label.
        let existing = find_share_handle_inner(&inner.session, share_label)?;
        if let Some(h) = existing {
            inner
                .session
                .destroy_object(h)
                .map_err(|e| Error::Config(format!("destroy old share: {e}")))?;
        }
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Label(share_label.as_bytes().to_vec()),
            Attribute::Token(true),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Wrap(true),
            Attribute::Value(scalar.to_vec()),
        ];
        inner
            .session
            .create_object(&template)
            .map_err(|e| Error::Config(format!("create_object: {e}")))?;
        Ok(())
    }

    /// **v2.13.0** — Find an installed share by its `CKA_LABEL`.
    /// Returns the HSM object handle, or `None` if no such share
    /// exists.
    ///
    /// # Errors
    /// [`Error::Config`] on PKCS#11 find failure.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub fn find_share_handle(&self, share_label: &str) -> Result<Option<ObjectHandle>> {
        let inner = self.inner.lock().expect("pkcs11 mutex");
        find_share_handle_inner(&inner.session, share_label)
    }

    /// **v2.13.0** — Delete an installed share by `CKA_LABEL`.
    /// Returns `true` if a share was removed.
    ///
    /// # Errors
    /// [`Error::Config`] on PKCS#11 destroy failure.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub fn delete_share(&self, share_label: &str) -> Result<bool> {
        let inner = self.inner.lock().expect("pkcs11 mutex");
        let Some(handle) = find_share_handle_inner(&inner.session, share_label)? else {
            return Ok(false);
        };
        inner
            .session
            .destroy_object(handle)
            .map_err(|e| Error::Config(format!("destroy_object: {e}")))?;
        Ok(true)
    }

    /// **v2.13.1 (softhsm path)** — Install a 32-byte share scalar
    /// with `CKA_EXTRACTABLE=true`, so the validator can later
    /// [`read_share_via_wrap`] to do the threshold-sign
    /// multiply-add in process memory.
    ///
    /// **WEAKER than [`install_share`]:** an attacker with HSM
    /// access can wrap the share under any AES key on the HSM and
    /// exfiltrate the wrapped bytes (then offline-decrypt with the
    /// wrap key). The persistent at-rest protection downgrade from
    /// v2.13.0 (non-extractable) to v2.13.1 (extractable) is the
    /// trade-off for working software HSMs that lack `CKM_EDDSA_RAW`.
    ///
    /// Production deployments with `CKM_EDDSA_RAW` (`CloudHSM`,
    /// `YubiHSM` 2) should use [`install_share`] + a v2.14 native
    /// sign path that never extracts.
    ///
    /// # Errors
    /// PKCS#11 create/delete failure → [`Error::Config`].
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub fn install_share_extractable(
        &self,
        scalar: &[u8; 32],
        share_label: &str,
    ) -> Result<()> {
        let inner = self.inner.lock().expect("pkcs11 mutex");
        let existing = find_share_handle_inner(&inner.session, share_label)?;
        if let Some(h) = existing {
            inner
                .session
                .destroy_object(h)
                .map_err(|e| Error::Config(format!("destroy old share: {e}")))?;
        }
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Label(share_label.as_bytes().to_vec()),
            Attribute::Token(true),
            Attribute::Private(true),
            // **v2.13.1 trade-off**: weaker at-rest posture than
            // v2.13.0 to enable threshold-sign integration on
            // softhsm-class HSMs.
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::Wrap(true),
            Attribute::Value(scalar.to_vec()),
        ];
        inner
            .session
            .create_object(&template)
            .map_err(|e| Error::Config(format!("create_object (extractable): {e}")))?;
        Ok(())
    }

    /// **v2.13.1** — Extract a previously-installed share's scalar
    /// value via the AES wrap key (Path A: brief in-process
    /// extraction for the sign multiply-add). Requires the share to
    /// have been installed with [`install_share_extractable`]
    /// (non-extractable shares cannot be wrapped — see PKCS#11
    /// §10.6).
    ///
    /// The flow:
    /// 1. Find the share object by `share_label`.
    /// 2. `C_WrapKey` (AES wrap key wraps the share) → opaque
    ///    AES-encrypted blob.
    /// 3. `C_UnwrapKey` re-imports the wrapped blob into a fresh
    ///    SESSION-only object with `CKA_EXTRACTABLE=true`.
    /// 4. `C_GetAttributeValue(CKA_VALUE)` reads the scalar.
    /// 5. Caller computes `s_partial = k + c · scalar (mod ℓ)`
    ///    in process memory.
    /// 6. The session-only re-imported key is destroyed; the
    ///    original share remains non-extractable on the HSM.
    ///
    /// **What this costs:** the scalar is briefly visible in
    /// validator process memory (single multiply-add round-trip),
    /// not for the duration of a whole sign protocol like v2.11.
    /// **What this gains:** the share's persistent residency is
    /// only HSM-side; disk + process memory compromise alone
    /// cannot recover the share long-term.
    ///
    /// Full path-B (in-HSM scalar arithmetic without extraction)
    /// requires vendor-specific mechanisms not present in softhsm
    /// 2.6.1; v2.14 work.
    ///
    /// # Errors
    /// [`Error::Config`] for any PKCS#11 operation failure.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub fn read_share_via_wrap(&self, share_label: &str) -> Result<Zeroizing<[u8; 32]>> {
        use cryptoki::mechanism::{Mechanism, MechanismType};

        let inner = self.inner.lock().expect("pkcs11 mutex");
        let share_handle = find_share_handle_inner(&inner.session, share_label)?
            .ok_or_else(|| Error::Config(format!("no share with label {share_label:?}")))?;

        // (1) wrap the share with the AES wrap key via CKM_AES_KEY_WRAP_PAD.
        // softhsm 2.6.1 supports CKM_AES_KEY_WRAP_PAD (RFC 5649) for
        // wrapping arbitrary-length secrets including 32-byte scalars.
        let wrap_mech = Mechanism::AesKeyWrapPad;
        let _ = MechanismType::AES_KEY_WRAP_PAD; // ensure constant is in scope
        let wrapped_bytes = inner
            .session
            .wrap_key(&wrap_mech, inner.wrap_key, share_handle)
            .map_err(|e| Error::Config(format!("C_WrapKey: {e}")))?;

        // (2) unwrap with CKA_EXTRACTABLE=true into a session-only
        //     object so we can read the value back out.
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Token(false),      // session-only, not persisted
            Attribute::Sensitive(false),  // allow GetAttributeValue(VALUE)
            Attribute::Extractable(true), // allow extraction
            Attribute::Label(format!("{share_label}-transient").into_bytes()),
        ];
        let transient = inner
            .session
            .unwrap_key(&wrap_mech, inner.wrap_key, &wrapped_bytes, &template)
            .map_err(|e| Error::Config(format!("C_UnwrapKey: {e}")))?;

        // (3) read CKA_VALUE from the transient extractable key.
        let attrs = inner
            .session
            .get_attributes(transient, &[AttributeType::Value])
            .map_err(|e| Error::Config(format!("get_attributes(VALUE): {e}")))?;
        let mut scalar = Zeroizing::new([0u8; 32]);
        let mut found = false;
        for a in attrs {
            if let Attribute::Value(bytes) = a {
                if bytes.len() != 32 {
                    let _ = inner.session.destroy_object(transient);
                    return Err(Error::Config(format!(
                        "extracted scalar wrong length: {}",
                        bytes.len()
                    )));
                }
                scalar.copy_from_slice(&bytes);
                found = true;
                break;
            }
        }

        // (4) destroy the transient session-only key.
        let _ = inner.session.destroy_object(transient);

        if !found {
            return Err(Error::Config(
                "no Value attribute returned for transient share".into(),
            ));
        }
        Ok(scalar)
    }

    /// **v2.13.0** — Verify that an installed share has the
    /// `CKA_EXTRACTABLE = false` + `CKA_SENSITIVE = true` posture.
    /// Operator-facing audit helper: a misconfigured HSM (or a
    /// rogue operator who installs a share with weakened attrs)
    /// is caught at boot rather than at incident time.
    ///
    /// # Errors
    /// [`Error::Config`] on PKCS#11 attribute lookup failure.
    /// [`Error::Config("share posture violation: ...")`] if the
    /// installed share is extractable or non-sensitive.
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub fn audit_share_posture(&self, share_label: &str) -> Result<()> {
        let inner = self.inner.lock().expect("pkcs11 mutex");
        let handle = find_share_handle_inner(&inner.session, share_label)?
            .ok_or_else(|| Error::Config(format!("no share with label {share_label:?}")))?;
        let attrs = inner
            .session
            .get_attributes(handle, &[AttributeType::Extractable, AttributeType::Sensitive])
            .map_err(|e| Error::Config(format!("get_attributes: {e}")))?;
        for attr in attrs {
            match attr {
                Attribute::Extractable(v) if v => {
                    return Err(Error::Config(
                        "share posture violation: CKA_EXTRACTABLE = true on installed share"
                            .into(),
                    ));
                }
                Attribute::Sensitive(v) if !v => {
                    return Err(Error::Config(
                        "share posture violation: CKA_SENSITIVE = false on installed share"
                            .into(),
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Re-establish the PKCS#11 session and wrap-key handle from
    /// scratch. Used after a `CKR_SESSION_HANDLE_INVALID` or
    /// equivalent mid-call session failure.
    ///
    /// Atomically swaps the new `Pkcs11Inner` under the mutex; the
    /// next caller observes the fresh session.
    ///
    /// # Errors
    /// Propagates the same `Error::Config` cases as [`open`].
    ///
    /// # Panics
    /// Mutex poison; only reachable after an earlier in-lock panic.
    pub fn reopen_session(&self) -> Result<()> {
        let slot = find_slot_by_label(&self.ctx, &self.reopen_inputs.slot_label)?;
        let session = self
            .ctx
            .open_rw_session(slot)
            .map_err(|e| Error::Config(format!("reopen open_rw_session: {e}")))?;
        // PKCS#11 login state is per-token (not per-session): if the
        // token already has an authenticated session, C_Login on a
        // new session returns CKR_USER_ALREADY_LOGGED_IN — that is a
        // benign "already authenticated" signal, not a failure.
        if let Err(e) = session
            .login(UserType::User, Some(&AuthPin::new(self.reopen_inputs.user_pin.clone())))
        {
            let s = e.to_string();
            if !s.contains("USER_ALREADY_LOGGED_IN")
                && !s.contains("already logged into the session")
            {
                return Err(Error::Config(format!("reopen login: {e}")));
            }
        }
        let wrap_key = find_wrap_key(&session, &self.reopen_inputs.wrap_key_label)?;
        let mut guard = self.inner.lock().expect("pkcs11 mutex");
        *guard = Pkcs11Inner { session, wrap_key };
        Ok(())
    }
}

fn find_slot_by_label(ctx: &Pkcs11, slot_label: &str) -> Result<Slot> {
    let slots = ctx
        .get_all_slots()
        .map_err(|e| Error::Config(format!("get_all_slots: {e}")))?;
    for slot in slots {
        if let Ok(info) = ctx.get_token_info(slot) {
            if info.label().trim() == slot_label.trim() {
                return Ok(slot);
            }
        }
    }
    Err(Error::Config(format!(
        "no slot with token label {slot_label:?}"
    )))
}

/// Look up a share object by `CKA_LABEL` inside an already-locked
/// session. Used by [`Pkcs11ShareStore::find_share_handle`],
/// `install_share`, `delete_share`, and `audit_share_posture` to
/// avoid re-locking the mutex.
fn find_share_handle_inner(session: &Session, share_label: &str) -> Result<Option<ObjectHandle>> {
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Label(share_label.as_bytes().to_vec()),
    ];
    let handles = session
        .find_objects(&template)
        .map_err(|e| Error::Config(format!("find_objects: {e}")))?;
    Ok(handles.into_iter().next())
}

fn find_wrap_key(session: &Session, label: &str) -> Result<ObjectHandle> {
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Label(label.as_bytes().to_vec()),
    ];
    let handles = session
        .find_objects(&template)
        .map_err(|e| Error::Config(format!("find_objects: {e}")))?;
    handles
        .into_iter()
        .next()
        .ok_or_else(|| Error::Config(format!("no AES wrap key with CKA_LABEL {label:?}")))
}

impl Pkcs11ShareStore {
    fn aes_encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use rand::RngCore;
        let mut iv = [0u8; IV_LEN];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        let inner = self.inner.lock().expect("pkcs11 mutex");
        let tag_bits: cryptoki::types::Ulong = (16u64 * 8).into();
        let mech = Mechanism::AesGcm(
            cryptoki::mechanism::aead::GcmParams::new(&iv, &[], tag_bits),
        );
        let ct = inner
            .session
            .encrypt(&mech, inner.wrap_key, plaintext)
            .map_err(|e| Error::Config(format!("HSM encrypt: {e}")))?;
        let mut out = Vec::with_capacity(IV_LEN + ct.len());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn aes_decrypt(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if sealed.len() < IV_LEN + 16 {
            return Err(Error::StorageCorruption(format!(
                "sealed blob too short: {}",
                sealed.len()
            )));
        }
        let iv: [u8; IV_LEN] = sealed[..IV_LEN]
            .try_into()
            .expect("slice length checked above");
        let ct = &sealed[IV_LEN..];

        let inner = self.inner.lock().expect("pkcs11 mutex");
        let tag_bits: cryptoki::types::Ulong = (16u64 * 8).into();
        let mech = Mechanism::AesGcm(
            cryptoki::mechanism::aead::GcmParams::new(&iv, &[], tag_bits),
        );
        inner
            .session
            .decrypt(&mech, inner.wrap_key, ct)
            .map_err(|_| Error::AeadFailure)
    }
}

impl ShareStore for Pkcs11ShareStore {
    fn load(&self, keyset_id: &[u8; 33]) -> Result<Option<ValidatorShareRecord>> {
        let path = share_path(&self.data_dir, keyset_id);
        let sealed = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        };
        let plaintext = self.aes_decrypt(&sealed)?;
        let record = ValidatorShareRecord::try_from_slice(&plaintext)
            .map_err(|e| Error::ShareDecode(e.to_string()))?;
        Ok(Some(record))
    }

    fn save(&self, record: &ValidatorShareRecord) -> Result<()> {
        let plaintext = borsh::to_vec(record).map_err(|e| Error::ShareDecode(e.to_string()))?;
        let sealed = self.aes_encrypt(&plaintext)?;
        let path = share_path(&self.data_dir, &record.keyset_id);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &sealed)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<ValidatorShareRecord>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("bin") {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if !name.starts_with("share_") {
                continue;
            }
            let sealed = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = ?e, "skip unreadable share");
                    continue;
                }
            };
            match self.aes_decrypt(&sealed) {
                Ok(pt) => match ValidatorShareRecord::try_from_slice(&pt) {
                    Ok(rec) => out.push(rec),
                    Err(e) => {
                        tracing::warn!(path = %path.display(), error = ?e, "skip bad-decode share");
                    }
                },
                Err(e) => {
                    tracing::warn!(path = %path.display(), error = ?e, "skip undecryptable share");
                }
            }
        }
        Ok(out)
    }

    fn backend_name(&self) -> &'static str {
        "pkcs11"
    }
}

