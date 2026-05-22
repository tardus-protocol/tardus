//! Wallet-side refresh orchestrator.
//!
//! Drives the full 6-round κ-fold cut-and-choose refresh across all
//! validators in the pool, parallelising the per-validator HTTP
//! round-trips via `futures::try_join_all`, and returns the freshly
//! issued (unlinkable) [`tardus_refresh::coin::Coin`].

use crate::{
    client_pool::WalletClientPool,
    error::{Error, Result},
};
use futures::future::try_join_all;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tardus_core::PublicKey;
use tardus_mint::transcript::SessionId;
use tardus_refresh::{
    coin::Coin,
    refresh::{
        aggregate_refresh_round1, aggregate_refresh_round5, mint_refresh_round3,
        mint_refresh_verify_reveal, user_refresh_round2, user_refresh_round4, user_refresh_round6,
        ValidatorRefreshR1Output, ValidatorRefreshR5Output, DEFAULT_KAPPA,
    },
};

// Wire types matching validator's API.
#[derive(Serialize)]
struct R1Req<'a> {
    session_id_hex: &'a str,
    kappa: u8,
}

#[derive(Deserialize)]
struct R1Resp {
    from_index: u16,
    #[allow(dead_code)]
    session_id_hex: String,
    #[allow(dead_code)]
    kappa: u8,
    r_per_candidate_hex: Vec<String>,
}

#[derive(Serialize)]
struct R5Req<'a> {
    session_id_hex: &'a str,
    signing_set: Vec<u16>,
    gamma_star: u8,
    user_challenges_hex: Vec<String>,
    melted_coin_pubkey_hex: String,
    melted_coin_signature_hex: String,
}

#[derive(Deserialize)]
struct R5Resp {
    from_index: u16,
    #[allow(dead_code)]
    session_id_hex: String,
    s_partial_hex: String,
}

fn decode_hex32(hex_str: &str, label: &'static str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(Error::BadLength {
            label,
            expected: 32,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Refresh `melted_coin` into a fresh, unlinkable [`Coin`] under the
/// same `joint_pk` via the validator pool.
///
/// Implements all six rounds of `tardus_refresh::refresh`:
///   1. parallel `/refresh/round1` ⇒ κ commitments per validator
///   2. `aggregate_refresh_round1` ⇒ aggregated commit
///   3. `user_refresh_round2` (in-proc) ⇒ blinded challenges + reveal data
///   4. `mint_refresh_round3` (in-proc, deterministic) ⇒ γ* challenge
///   5. `user_refresh_round4` (in-proc) ⇒ κ−1 reveal
///      + `mint_refresh_verify_reveal` (in-proc consistency check)
///   6. parallel `/refresh/round5` ⇒ partial sigs for γ*
///   7. `aggregate_refresh_round5` ⇒ aggregated sig
///   8. `user_refresh_round6` (in-proc) ⇒ new [`Coin`]
///
/// # Errors
/// Any HTTP / Borsh / cryptographic failure from the underlying
/// validator handlers or the in-proc `tardus_refresh` calls.
pub async fn refresh_coin(
    pool: &WalletClientPool,
    melted_coin: &Coin,
    joint_pk: &PublicKey,
    session_id: SessionId,
) -> Result<Coin> {
    let kappa = DEFAULT_KAPPA;
    let signing_set = pool.signing_set();
    let session_id_hex = hex::encode(session_id.to_bytes());

    // === Round 1: parallel /refresh/round1 ===
    let r1_calls: Vec<_> = pool
        .endpoints()
        .iter()
        .map(|ep| {
            let body = R1Req {
                session_id_hex: &session_id_hex,
                kappa,
            };
            async move {
                let resp: R1Resp = ep.post("/refresh/round1", &body).await?;
                if resp.from_index != ep.my_index {
                    return Err(Error::UnexpectedIndex {
                        expected: ep.my_index,
                        got: resp.from_index,
                    });
                }
                let mut r_per_candidate = Vec::with_capacity(resp.r_per_candidate_hex.len());
                for hx in &resp.r_per_candidate_hex {
                    r_per_candidate.push(decode_hex32(hx, "r_per_candidate")?);
                }
                Ok::<ValidatorRefreshR1Output, Error>(ValidatorRefreshR1Output {
                    session_id,
                    from_index: ep.my_index,
                    r_per_candidate,
                })
            }
        })
        .collect();
    let r1_outputs: Vec<ValidatorRefreshR1Output> = try_join_all(r1_calls).await?;

    let mint_r1 =
        aggregate_refresh_round1(session_id, kappa, &signing_set, &r1_outputs)?;

    // === Rounds 2-4: user-side, in-proc ===
    let mut rng = OsRng;
    let (user_r2, user_state) =
        user_refresh_round2(session_id, &mint_r1, joint_pk, melted_coin, &mut rng)?;
    let challenge = mint_refresh_round3(session_id, &user_r2, joint_pk)?;
    let reveal = user_refresh_round4(&user_state, &challenge)?;
    // Local consistency check before going back to the network.
    mint_refresh_verify_reveal(&user_r2, &mint_r1, &challenge, &reveal, joint_pk)?;

    // === Round 5: parallel /refresh/round5 ===
    let user_challenges_hex: Vec<String> =
        user_r2.challenges.iter().map(hex::encode).collect();
    let melted_pk_hex = hex::encode(user_r2.melted_coin_pubkey);
    let melted_sig_hex = hex::encode(user_r2.melted_coin_signature.to_bytes());
    let r5_calls: Vec<_> = pool
        .endpoints()
        .iter()
        .map(|ep| {
            let body = R5Req {
                session_id_hex: &session_id_hex,
                signing_set: signing_set.clone(),
                gamma_star: challenge.gamma_star,
                user_challenges_hex: user_challenges_hex.clone(),
                melted_coin_pubkey_hex: melted_pk_hex.clone(),
                melted_coin_signature_hex: melted_sig_hex.clone(),
            };
            async move {
                let resp: R5Resp = ep.post("/refresh/round5", &body).await?;
                if resp.from_index != ep.my_index {
                    return Err(Error::UnexpectedIndex {
                        expected: ep.my_index,
                        got: resp.from_index,
                    });
                }
                let s_partial = decode_hex32(&resp.s_partial_hex, "s_partial_hex")?;
                Ok::<ValidatorRefreshR5Output, Error>(ValidatorRefreshR5Output {
                    session_id,
                    from_index: ep.my_index,
                    s_partial,
                })
            }
        })
        .collect();
    let r5_outputs: Vec<ValidatorRefreshR5Output> = try_join_all(r5_calls).await?;

    let mint_r5 = aggregate_refresh_round5(session_id, &signing_set, &r5_outputs)?;

    // === Round 6: user-side unblind ===
    let new_coin = user_refresh_round6(&user_state, &challenge, &mint_r5, joint_pk)?;
    Ok(new_coin)
}
