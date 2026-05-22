//! Wallet-side issuance orchestrator.
//!
//! Drives the full 4-round threshold blind sign across all validators
//! in the pool, parallelising the per-validator HTTP round-trips, and
//! returns a fully verified [`tardus_refresh::coin::Coin`].

use crate::{
    client_pool::WalletClientPool,
    error::{Error, Result},
};
use futures::future::try_join_all;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tardus_core::{
    blind_request, unblind, BlindCommit, BlindResponse, PublicKey, SecretKey,
};
use tardus_mint::{
    sign::{aggregate_commitments, aggregate_responses, ValidatorR1Output, ValidatorR3Output},
    transcript::SessionId,
};
use tardus_refresh::coin::Coin;

// Wire types matching the validator's API surface.
#[derive(Serialize)]
struct SignRound1Req<'a> {
    session_id_hex: &'a str,
}

#[derive(Deserialize)]
struct SignRound1Resp {
    from_index: u16,
    #[allow(dead_code)]
    session_id_hex: String,
    r_i_hex: String,
}

#[derive(Serialize)]
struct SignRound3Req<'a> {
    session_id_hex: &'a str,
    signing_set: Vec<u16>,
    challenge_hex: String,
}

#[derive(Deserialize)]
struct SignRound3Resp {
    from_index: u16,
    #[allow(dead_code)]
    session_id_hex: String,
    s_i_hex: String,
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

/// Issue a fresh coin under `joint_pk` via the validator pool.
///
/// 1. Pool's signing set = all validators in the pool (assumes t = pool size).
/// 2. Round 1 in parallel: every validator's `/sign/round1` ⇒ commitment.
/// 3. Aggregate ⇒ [`BlindCommit`].
/// 4. User Round 2 (in-proc): `blind_request` ⇒ challenge + state.
/// 5. Round 3 in parallel: every validator's `/sign/round3` ⇒ partial sig.
/// 6. Aggregate ⇒ [`BlindResponse`].
/// 7. User Round 4 (in-proc): `unblind` ⇒ final signature.
/// 8. Construct + verify [`Coin`].
///
/// # Errors
/// Any HTTP / JSON / cryptographic failure from the underlying calls.
pub async fn issue_coin(
    pool: &WalletClientPool,
    joint_pk: &PublicKey,
    session_id: SessionId,
) -> Result<Coin> {
    let signing_set = pool.signing_set();
    let session_id_hex = hex::encode(session_id.to_bytes());

    // === Round 1: parallel per-validator round trips ===
    let r1_calls: Vec<_> = pool
        .endpoints()
        .iter()
        .map(|ep| {
            let body = SignRound1Req {
                session_id_hex: &session_id_hex,
            };
            async move {
                let resp: SignRound1Resp = ep.post("/sign/round1", &body).await?;
                if resp.from_index != ep.my_index {
                    return Err(Error::UnexpectedIndex {
                        expected: ep.my_index,
                        got: resp.from_index,
                    });
                }
                let r_i = decode_hex32(&resp.r_i_hex, "r_i_hex")?;
                Ok::<ValidatorR1Output, Error>(ValidatorR1Output {
                    from_index: ep.my_index,
                    session_id,
                    r_i,
                })
            }
        })
        .collect();
    let r1_outputs: Vec<ValidatorR1Output> = try_join_all(r1_calls).await?;
    let blind_commit: BlindCommit = aggregate_commitments(session_id, &signing_set, &r1_outputs)?;

    // === Round 2: user-side, in-proc ===
    let mut rng = OsRng;
    let coin_secret = SecretKey::random(&mut rng);
    let coin_pk = PublicKey::from_secret(&coin_secret);
    let coin_pk_bytes = coin_pk.to_bytes();
    let (challenge, user_state) =
        blind_request(&blind_commit, joint_pk, &coin_pk_bytes, &mut rng)?;
    let challenge_hex = hex::encode(challenge.c);

    // === Round 3: parallel per-validator round trips ===
    let r3_calls: Vec<_> = pool
        .endpoints()
        .iter()
        .map(|ep| {
            let body = SignRound3Req {
                session_id_hex: &session_id_hex,
                signing_set: signing_set.clone(),
                challenge_hex: challenge_hex.clone(),
            };
            async move {
                let resp: SignRound3Resp = ep.post("/sign/round3", &body).await?;
                if resp.from_index != ep.my_index {
                    return Err(Error::UnexpectedIndex {
                        expected: ep.my_index,
                        got: resp.from_index,
                    });
                }
                let s_i = decode_hex32(&resp.s_i_hex, "s_i_hex")?;
                Ok::<ValidatorR3Output, Error>(ValidatorR3Output {
                    from_index: ep.my_index,
                    session_id,
                    s_i,
                })
            }
        })
        .collect();
    let r3_outputs: Vec<ValidatorR3Output> = try_join_all(r3_calls).await?;
    let blind_response: BlindResponse = aggregate_responses(session_id, &signing_set, &r3_outputs)?;

    // === Round 4: user-side unblind ===
    let signature = unblind(&user_state, &blind_response)?;
    let coin = Coin::new(coin_secret, coin_pk_bytes, signature)?;

    Ok(coin)
}

