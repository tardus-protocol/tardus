//! `tardus coin` subcommand: standalone coin verification.

use anyhow::{anyhow, Context, Result};
use tardus_core::{schnorr_verify, PublicKey, Signature};

/// Verify a coin given the on-wire packed format
/// `secret_hex32 || pubkey_hex32 || signature_hex64` and a joint
/// public key. Exit code 0 on valid, non-zero on invalid.
pub fn verify(coin_hex: &str, joint_pk_hex: &str) -> Result<()> {
    let coin_bytes = hex::decode(coin_hex).context("--coin not valid hex")?;
    if coin_bytes.len() != 32 + 32 + 64 {
        return Err(anyhow!(
            "expected --coin to be {} bytes, got {}",
            32 + 32 + 64,
            coin_bytes.len()
        ));
    }
    let pubkey_bytes: [u8; 32] = coin_bytes[32..64]
        .try_into()
        .expect("slice has 32 bytes by construction");
    let sig_bytes: [u8; 64] = coin_bytes[64..128]
        .try_into()
        .expect("slice has 64 bytes by construction");

    let joint_pk_arr = decode_hex_32(joint_pk_hex).context("--joint-pk")?;
    let joint_pk = PublicKey::from_bytes(&joint_pk_arr).map_err(|e| anyhow!("joint-pk: {e}"))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let ok = schnorr_verify(&joint_pk, &pubkey_bytes, &sig).map_err(|e| anyhow!("verify: {e}"))?;
    println!("{{");
    println!("  \"verify\": {ok},");
    println!("  \"coin_pubkey\": \"{}\",", hex::encode(pubkey_bytes));
    println!("  \"joint_pk\": \"{joint_pk_hex}\"");
    println!("}}");
    if ok {
        Ok(())
    } else {
        std::process::exit(2);
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("not valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
