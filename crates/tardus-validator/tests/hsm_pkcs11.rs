//! v2.11 PKCS#11 HSM backend integration test (softhsm2).
//!
//! Run with:
//! ```sh
//! cargo test -p tardus-validator --features hsm --test hsm_pkcs11 -- \
//!     --ignored --test-threads=1
//! ```
//!
//! `#[ignore]` because the test mutates `SOFTHSM2_CONF` (process-wide
//! env var) and spawns `softhsm2-util`. CI must run with
//! `--test-threads=1` to avoid token-init races.

#![cfg(feature = "hsm")]
#![allow(clippy::similar_names, clippy::doc_markdown)]

use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, KeyType, ObjectClass},
    session::UserType,
    types::AuthPin,
};
use std::path::{Path, PathBuf};
use std::process::Command;
use tardus_validator::{
    pkcs11_store::Pkcs11ShareStore,
    share_store::ShareStore,
    storage::ValidatorShareRecord,
};
use tempfile::TempDir;

const SOFTHSM_MODULE: &str = "/usr/lib/softhsm/libsofthsm2.so";
const TOKEN_LABEL: &str = "tardus-hsm-test";
const USER_PIN: &str = "1234";
const SO_PIN: &str = "5678";
const WRAP_KEY_LABEL: &str = "tardus-wrap-v1";

/// Create a softhsm2 config file pointing at a temp token dir and
/// initialise a fresh token under that config. Returns the path to
/// the softhsm2 module and sets `SOFTHSM2_CONF` for the rest of the
/// test (single-threaded).
fn setup_softhsm(tmp: &Path) -> PathBuf {
    let token_dir = tmp.join("tokens");
    std::fs::create_dir_all(&token_dir).unwrap();
    let conf_path = tmp.join("softhsm2.conf");
    std::fs::write(
        &conf_path,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            token_dir.display()
        ),
    )
    .unwrap();
    // Process-global env var; single-threaded harness enforced via
    // `--test-threads=1` in the test invocation.
    std::env::set_var("SOFTHSM2_CONF", &conf_path);

    let out = Command::new("softhsm2-util")
        .args([
            "--init-token", "--free",
            "--label", TOKEN_LABEL,
            "--pin", USER_PIN,
            "--so-pin", SO_PIN,
        ])
        .env("SOFTHSM2_CONF", &conf_path)
        .output()
        .expect("softhsm2-util");
    assert!(
        out.status.success(),
        "softhsm2-util --init-token failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    PathBuf::from(SOFTHSM_MODULE)
}

/// Generate an AES-256 wrap key inside the just-initialised token.
fn provision_wrap_key(module: &Path) {
    let ctx = Pkcs11::new(module).expect("load module");
    ctx.initialize(CInitializeArgs::OsThreads).expect("init");
    let slot = ctx
        .get_all_slots()
        .unwrap()
        .into_iter()
        .find(|s| {
            ctx.get_token_info(*s)
                .is_ok_and(|t| t.label().trim() == TOKEN_LABEL)
        })
        .expect("find slot");
    let session = ctx.open_rw_session(slot).expect("open session");
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .expect("login");

    let value_len: cryptoki::types::Ulong = 32u64.into();
    let template = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(value_len),
        Attribute::Label(WRAP_KEY_LABEL.as_bytes().to_vec()),
        Attribute::Token(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(true),
        Attribute::Extractable(false),
        Attribute::Sensitive(true),
    ];
    session
        .generate_key(&Mechanism::AesKeyGen, &template)
        .expect("generate AES wrap key");
}

fn fresh_record(seed_byte: u8) -> ValidatorShareRecord {
    ValidatorShareRecord {
        keyset_id: [seed_byte; 33],
        my_index: u16::from(seed_byte),
        n: 5,
        t: 3,
        epoch: 1,
        joint_pk_bytes: [seed_byte; 32],
        my_share_bytes: [seed_byte.wrapping_add(1); 32],
        qual: vec![1, 2, 3, 4, 5],
    }
}

/// **v2.13.0 security regression guard**: confirm a
/// non-extractable share CANNOT be wrapped under the AES wrap key.
/// This is the security property of v2.13.0 install_share — if
/// softhsm ever loosens this and allows wrapping non-extractable
/// keys, the test fails LOUD and we know to investigate.
#[test]
#[ignore = "needs softhsm2; run with cargo test ... -- --ignored --test-threads=1"]
fn pkcs11_v2_13_0_non_extractable_cannot_be_wrapped() {
    let tmp = TempDir::new().unwrap();
    let module = setup_softhsm(tmp.path());
    provision_wrap_key(&module);
    let data_dir = tmp.path().join("shares");
    std::fs::create_dir_all(&data_dir).unwrap();

    let store = Pkcs11ShareStore::open(&module, TOKEN_LABEL, USER_PIN, WRAP_KEY_LABEL, data_dir)
        .expect("open");
    let scalar = [0xAA; 32];
    store
        .install_share(&scalar, "non-extractable")
        .expect("install_share (non-extractable)");
    let r = store.read_share_via_wrap("non-extractable");
    assert!(
        r.is_err(),
        "non-extractable share MUST NOT be wrappable (PKCS#11 §10.6); \
         test broken or softhsm regressed if this passes"
    );
    let err_msg = format!("{:?}", r.unwrap_err());
    assert!(
        err_msg.contains("EXTRACTABLE") || err_msg.contains("WRAPPABLE"),
        "expected CKR_KEY_NOT_WRAPPABLE-class error; got {err_msg}"
    );
}

/// **v2.13.1 (softhsm path)** — Install an EXTRACTABLE share,
/// extract it via the AES wrap key, verify roundtrip preserves
/// the exact 32-byte scalar. Required by the threshold-sign
/// multiply-add when CKM_EDDSA_RAW is unavailable.
#[test]
#[ignore = "needs softhsm2; run with cargo test ... -- --ignored --test-threads=1"]
fn pkcs11_v2_13_1_extractable_share_wrap_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let module = setup_softhsm(tmp.path());
    provision_wrap_key(&module);
    let data_dir = tmp.path().join("shares");
    std::fs::create_dir_all(&data_dir).unwrap();

    let store = Pkcs11ShareStore::open(&module, TOKEN_LABEL, USER_PIN, WRAP_KEY_LABEL, data_dir)
        .expect("open");

    let scalar: [u8; 32] = {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = u8::try_from((0x77 + i) & 0xff).unwrap();
        }
        a
    };
    store
        .install_share_extractable(&scalar, "share-extractable-A")
        .expect("install_share_extractable");

    let extracted = store
        .read_share_via_wrap("share-extractable-A")
        .expect("read_share_via_wrap");
    assert_eq!(
        &*extracted, &scalar,
        "wrap-unwrap roundtrip MUST return the exact same 32 scalar bytes"
    );

    let extracted2 = store.read_share_via_wrap("share-extractable-A").unwrap();
    assert_eq!(
        &*extracted, &*extracted2,
        "second extraction must produce the same scalar"
    );

    let r = store.read_share_via_wrap("ghost");
    assert!(r.is_err(), "non-existent share extraction must error");
}

#[test]
#[ignore = "needs softhsm2; run with cargo test ... -- --ignored --test-threads=1"]
fn pkcs11_v2_13_share_install_with_non_extractable_posture() {
    let tmp = TempDir::new().unwrap();
    let module = setup_softhsm(tmp.path());
    provision_wrap_key(&module);
    let data_dir = tmp.path().join("shares");
    std::fs::create_dir_all(&data_dir).unwrap();

    let store = Pkcs11ShareStore::open(&module, TOKEN_LABEL, USER_PIN, WRAP_KEY_LABEL, data_dir)
        .expect("open");

    // Initially nothing installed
    assert!(store.find_share_handle("share-keyset-0").expect("find").is_none());

    // Install a 32-byte scalar
    let scalar: [u8; 32] = {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xff).unwrap() + 1;
        }
        a
    };
    store
        .install_share(&scalar, "share-keyset-0")
        .expect("install_share");

    // Now find returns a handle
    let h = store
        .find_share_handle("share-keyset-0")
        .expect("find")
        .expect("present");
    assert!(!format!("{h:?}").is_empty());

    // Audit posture: must be non-extractable + sensitive
    store
        .audit_share_posture("share-keyset-0")
        .expect("share posture must pass (extractable=false, sensitive=true)");

    // The `audit_share_posture()` call above is the cross-check
    // that CKA_EXTRACTABLE=false AND CKA_SENSITIVE=true. softhsm
    // enforces both attributes for `CKK_GENERIC_SECRET` objects
    // installed via `C_CreateObject` with the corresponding flags.

    // Re-install under the same label is idempotent (delete-then-create).
    let scalar_v2: [u8; 32] = [0xAA; 32];
    store
        .install_share(&scalar_v2, "share-keyset-0")
        .expect("re-install under same label");
    store
        .audit_share_posture("share-keyset-0")
        .expect("posture still holds after re-install");
    // The handle changed (object was replaced), but the label still
    // resolves.
    let h2 = store
        .find_share_handle("share-keyset-0")
        .expect("find")
        .expect("present after re-install");
    let _ = h2;

    // Delete is idempotent: delete twice; second returns false.
    assert!(store.delete_share("share-keyset-0").expect("first delete"));
    assert!(!store.delete_share("share-keyset-0").expect("second delete"));
    assert!(
        store
            .find_share_handle("share-keyset-0")
            .expect("find post-delete")
            .is_none()
    );

    // Audit on a missing share returns Config error
    let r = store.audit_share_posture("share-keyset-0");
    assert!(r.is_err(), "audit on missing share must error");
}

#[test]
#[ignore = "needs softhsm2; run with cargo test ... -- --ignored --test-threads=1"]
fn pkcs11_session_auto_reopen_recovers() {
    let tmp = TempDir::new().unwrap();
    let module = setup_softhsm(tmp.path());
    provision_wrap_key(&module);
    let data_dir = tmp.path().join("shares");
    std::fs::create_dir_all(&data_dir).unwrap();

    let store = Pkcs11ShareStore::open(&module, TOKEN_LABEL, USER_PIN, WRAP_KEY_LABEL, data_dir)
        .expect("open");
    let rec = fresh_record(0xA1);
    store.save(&rec).expect("initial save");

    // Simulate F3d: force a fresh session by calling reopen_session
    // directly. After reopen, subsequent load() and save() MUST still
    // succeed against the same on-disk file (the wrap key is the same
    // HSM-resident key).
    store.reopen_session().expect("reopen_session must succeed");

    let loaded = store
        .load(&rec.keyset_id)
        .expect("load after reopen")
        .expect("present after reopen");
    assert_eq!(loaded.my_share_bytes, rec.my_share_bytes);

    let rec_b = fresh_record(0xB2);
    store.save(&rec_b).expect("save after reopen");
    assert_eq!(store.list().expect("list").len(), 2);
}

#[test]
#[ignore = "needs softhsm2 with CKM_EDDSA support (>= 2.6.0)"]
fn ckm_eddsa_native_sign_capability() {
    // Faz 2.12.B: Proof-of-capability that the deployed HSM can
    // perform native Ed25519 signing through PKCS#11. The full
    // integration (importing a DKG-derived share into the HSM via
    // C_UnwrapKey then signing via CKM_EDDSA) is v2.13.
    use cryptoki::mechanism::Mechanism;

    let tmp = TempDir::new().unwrap();
    let module = setup_softhsm(tmp.path());

    let ctx = cryptoki::context::Pkcs11::new(&module).expect("load module");
    ctx.initialize(cryptoki::context::CInitializeArgs::OsThreads)
        .expect("init");
    let slot = ctx
        .get_all_slots()
        .unwrap()
        .into_iter()
        .find(|s| {
            ctx.get_token_info(*s)
                .is_ok_and(|t| t.label().trim() == TOKEN_LABEL)
        })
        .expect("find slot");

    // Probe the mechanism list — bail with a clear skip message if
    // CKM_EDDSA isn't supported (older softhsm or non-Ed25519 HSM).
    let mechs = ctx.get_mechanism_list(slot).expect("get_mechanism_list");
    let supports_eddsa = mechs.contains(&cryptoki::mechanism::MechanismType::EDDSA);
    if !supports_eddsa {
        eprintln!(
            "skip: HSM at {} does not advertise CKM_EDDSA \
             (need softhsm >= 2.6.0 or native-EdDSA HSM); \
             v2.13 integration deferred until target HSM",
            module.display()
        );
        return;
    }

    let session = ctx.open_rw_session(slot).expect("open session");
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.into())))
        .expect("login");

    // Generate an Ed25519 keypair INSIDE the HSM. CKA_SIGN on the
    // private key + CKA_VERIFY on the public key; private key is
    // not extractable (would be `CKA_EXTRACTABLE = false` in
    // production — softhsm's behaviour here matches the spec).
    let curve_oid = vec![0x06, 0x03, 0x2b, 0x65, 0x70]; // RFC 8410 §3 (Ed25519 OID)
    let pub_template = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::Verify(true),
        Attribute::EcParams(curve_oid.clone()),
        Attribute::Label(b"tardus-eddsa-probe-pub".to_vec()),
    ];
    let priv_template = vec![
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::Sign(true),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(b"tardus-eddsa-probe-priv".to_vec()),
    ];
    let (pub_h, priv_h) = session
        .generate_key_pair(&Mechanism::EccEdwardsKeyPairGen, &pub_template, &priv_template)
        .expect("generate Ed25519 keypair inside HSM");

    // Native sign via the HSM (the private key never leaves).
    let message = b"TARDUS v2.12 native HSM Ed25519 sign proof";
    let signature = session
        .sign(&Mechanism::Eddsa, priv_h, message)
        .expect("HSM C_Sign with CKM_EDDSA");
    assert_eq!(
        signature.len(),
        64,
        "Ed25519 signature must be 64 bytes; got {}",
        signature.len()
    );

    // Verify INSIDE the HSM too — round-trips proves the keypair is
    // a real Ed25519 keypair, not just bytes that happen to look
    // signature-shaped.
    session
        .verify(&Mechanism::Eddsa, pub_h, message, &signature)
        .expect("HSM C_Verify with CKM_EDDSA");

    // Wrong-message verify must fail.
    let r = session.verify(&Mechanism::Eddsa, pub_h, b"different message", &signature);
    assert!(r.is_err(), "wrong-message verify must fail");
}

#[test]
#[ignore = "needs softhsm2; run with cargo test ... -- --ignored --test-threads=1"]
fn pkcs11_store_roundtrip_with_softhsm() {
    let tmp = TempDir::new().unwrap();
    let module = setup_softhsm(tmp.path());
    provision_wrap_key(&module);

    let data_dir = tmp.path().join("shares");
    std::fs::create_dir_all(&data_dir).unwrap();

    let store = Pkcs11ShareStore::open(
        &module,
        TOKEN_LABEL,
        USER_PIN,
        WRAP_KEY_LABEL,
        data_dir,
    )
    .expect("open Pkcs11ShareStore");

    assert_eq!(store.backend_name(), "pkcs11");

    // Empty backend → list() returns empty.
    assert!(store.list().unwrap().is_empty());

    // save() → list() → load() roundtrip.
    let rec_a = fresh_record(0xA1);
    let rec_b = fresh_record(0xB2);
    store.save(&rec_a).expect("save A");
    store.save(&rec_b).expect("save B");

    let all = store.list().expect("list");
    assert_eq!(all.len(), 2);

    let loaded_a = store.load(&rec_a.keyset_id).expect("load A").expect("present");
    assert_eq!(loaded_a.keyset_id, rec_a.keyset_id);
    assert_eq!(loaded_a.my_share_bytes, rec_a.my_share_bytes);
    assert_eq!(loaded_a.epoch, rec_a.epoch);

    // load of nonexistent → Ok(None)
    let missing = store.load(&[0xCC; 33]).expect("load missing");
    assert!(missing.is_none(), "absent keyset must be Ok(None)");
}
