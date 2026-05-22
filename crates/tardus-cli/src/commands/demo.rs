//! `tardus demo` subcommand: protocol simulation showcases.

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use tardus_client::issue::{issue_finalize, issue_request};
use tardus_core::{schnorr_sign, Keypair as TKeypair, PublicKey as TPublicKey, SecretKey as TSecretKey};
use tardus_mint::{
    dkg::{dkg_finalize, dkg_start, DkgFinalised, PeerContribution},
    sign::{
        aggregate_commitments, aggregate_responses, partial_sign, validator_round1,
        ValidatorR1Output, ValidatorR1State, ValidatorR3Output,
    },
    transcript::{CeremonyId, SessionId},
    vss::{h_generator, VssParameters},
};
use tardus_refresh::{
    coin::Coin,
    refresh::{
        aggregate_refresh_round1, aggregate_refresh_round5, mint_refresh_round3,
        mint_refresh_verify_reveal, user_refresh_round2, user_refresh_round4, user_refresh_round6,
        validator_refresh_round1, validator_refresh_round5, DEFAULT_KAPPA,
    },
};

const DKG_CEREMONY: CeremonyId = CeremonyId::from_bytes([0x42; 16]);
const ISSUE_SESSION: SessionId = SessionId::from_bytes([0x43; 16]);
const REFRESH_SESSION: SessionId = SessionId::from_bytes([0x44; 16]);

/// `tardus demo issue-coin` — single-mint coin issuance for devnet
/// testing. Generates a fresh mint keypair and a fresh coin signed
/// under it. Prints JSON ready for the `tardus devnet` flow.
#[allow(clippy::similar_names, clippy::unnecessary_wraps)]
pub fn issue_coin_demo() -> Result<()> {
    let mut rng = OsRng;
    let mint = TKeypair::random(&mut rng);
    let coin_secret = TSecretKey::random(&mut rng);
    let coin_pubkey = TPublicKey::from_secret(&coin_secret);
    let coin_pk_bytes = coin_pubkey.to_bytes();
    let coin_sig = schnorr_sign(&mint.secret, &mint.public, &coin_pk_bytes, &mut rng);

    println!("{{");
    println!(
        "  \"mint_pk\": \"{}\",",
        hex::encode(mint.public.to_bytes())
    );
    println!("  \"coin_pubkey\": \"{}\",", hex::encode(coin_pk_bytes));
    println!(
        "  \"coin_signature\": \"{}\"",
        hex::encode(coin_sig.to_bytes())
    );
    println!("}}");
    Ok(())
}

/// `tardus demo dkg-sim`
pub fn dkg_sim(n: u16, t: u16) -> Result<()> {
    if t == 0 || t > n {
        return Err(anyhow!("threshold t must be 1..={n}"));
    }
    let finalised = run_dkg(n, t)?;
    println!("{{");
    println!("  \"n\": {n},");
    println!("  \"t\": {t},");
    println!(
        "  \"joint_pk\": \"{}\",",
        hex::encode(finalised[0].joint_pk.to_bytes())
    );
    println!("  \"qual\": [");
    for (i, q) in finalised[0].qual.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{q}");
    }
    println!("\n  ]");
    println!("}}");
    Ok(())
}

/// `tardus demo lifecycle-sim` — full Faz 1.5 crown jewel as a binary.
pub fn lifecycle_sim() -> Result<()> {
    let finalised = run_dkg(4, 3)?;
    let joint_pk = finalised[0].joint_pk;
    let denom: u64 = 10_000_000;

    let initial_coin = issue_coin(&finalised, 3, ISSUE_SESSION)?;
    let initial_ok = initial_coin
        .verify(&joint_pk)
        .map_err(|e| anyhow!("initial verify: {e}"))?;
    if !initial_ok {
        return Err(anyhow!("initial issued coin failed verification"));
    }

    let refreshed = refresh_coin(&finalised, 3, REFRESH_SESSION, &initial_coin)?;
    let refresh_ok = refreshed
        .verify(&joint_pk)
        .map_err(|e| anyhow!("refresh verify: {e}"))?;
    if !refresh_ok {
        return Err(anyhow!("refreshed coin failed verification"));
    }

    let initial_nullifier = initial_coin.nullifier();
    let refreshed_nullifier = refreshed.nullifier();

    println!("{{");
    println!("  \"dkg\": {{");
    println!("    \"n\": 4,");
    println!("    \"t\": 3,");
    println!(
        "    \"joint_pk\": \"{}\"",
        hex::encode(joint_pk.to_bytes())
    );
    println!("  }},");
    println!("  \"denom\": {denom},");
    println!("  \"initial_coin\": {{");
    println!(
        "    \"pubkey\": \"{}\",",
        hex::encode(initial_coin.pubkey_bytes())
    );
    println!(
        "    \"nullifier\": \"{}\",",
        hex::encode(initial_nullifier)
    );
    println!("    \"verify\": {initial_ok}");
    println!("  }},");
    println!("  \"refreshed_coin\": {{");
    println!(
        "    \"pubkey\": \"{}\",",
        hex::encode(refreshed.pubkey_bytes())
    );
    println!(
        "    \"nullifier\": \"{}\",",
        hex::encode(refreshed_nullifier)
    );
    println!("    \"verify\": {refresh_ok}");
    println!("  }},");
    println!(
        "  \"unlinkable\": {}",
        initial_coin.pubkey_bytes() != refreshed.pubkey_bytes()
    );
    println!("}}");
    Ok(())
}

// =====================================================================
// Internal: DKG, issue, refresh helpers
// =====================================================================

fn run_dkg(n: u16, t: u16) -> Result<Vec<DkgFinalised>> {
    let mut rng = OsRng;
    let h = h_generator();
    let params = VssParameters::new(n, t).map_err(|e| anyhow!("vss params: {e}"))?;
    let outputs: Vec<_> = (1..=n)
        .map(|i| dkg_start(DKG_CEREMONY, i, params, &h, &mut rng))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("dkg_start: {e}"))?;
    let mut finalisations = Vec::with_capacity(n as usize);
    for i in 1..=n {
        let i_idx = (i - 1) as usize;
        let received: Vec<PeerContribution> = (1..=n)
            .filter(|&k| k != i)
            .map(|k| {
                let k_idx = (k - 1) as usize;
                PeerContribution {
                    broadcast: outputs[k_idx].broadcast.clone(),
                    share_for_me: outputs[k_idx].shares[(i - 1) as usize].clone(),
                }
            })
            .collect();
        let final_ =
            dkg_finalize(&outputs[i_idx], &received, &h).map_err(|e| anyhow!("dkg_finalize: {e}"))?;
        finalisations.push(final_);
    }
    Ok(finalisations)
}

fn issue_coin(finalised: &[DkgFinalised], t: u16, session_id: SessionId) -> Result<Coin> {
    let mut rng = OsRng;
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = finalised.iter().take(t as usize).map(|f| f.my_index).collect();

    let r1: Vec<(ValidatorR1Output, ValidatorR1State)> = signing_set
        .iter()
        .map(|&i| validator_round1(session_id, i, &mut rng))
        .collect();
    let r1_outputs: Vec<ValidatorR1Output> = r1.iter().map(|(out, _)| *out).collect();
    let blind_commit = aggregate_commitments(session_id, &signing_set, &r1_outputs)
        .map_err(|e| anyhow!("aggregate_commitments: {e}"))?;

    let (challenge, session) = issue_request(&joint_pk, &blind_commit, &mut rng)
        .map_err(|e| anyhow!("issue_request: {e}"))?;

    let mut r3_outputs: Vec<ValidatorR3Output> = Vec::with_capacity(t as usize);
    for (_, state) in &r1 {
        let f_i = finalised
            .iter()
            .find(|f| f.my_index == state.my_index)
            .ok_or_else(|| anyhow!("missing finalised share"))?;
        let r3 = partial_sign(state, &challenge, &f_i.my_share, &signing_set)
            .map_err(|e| anyhow!("partial_sign: {e}"))?;
        r3_outputs.push(r3);
    }
    let blind_response = aggregate_responses(session_id, &signing_set, &r3_outputs)
        .map_err(|e| anyhow!("aggregate_responses: {e}"))?;

    issue_finalize(session, &blind_response).map_err(|e| anyhow!("issue_finalize: {e}"))
}

fn refresh_coin(
    finalised: &[DkgFinalised],
    t: u16,
    session_id: SessionId,
    melted: &Coin,
) -> Result<Coin> {
    let mut rng = OsRng;
    let joint_pk = finalised[0].joint_pk;
    let signing_set: Vec<u16> = finalised.iter().take(t as usize).map(|f| f.my_index).collect();
    let kappa = DEFAULT_KAPPA;

    let mut val_r1: Vec<_> = Vec::new();
    for &i in &signing_set {
        let (out, state) = validator_refresh_round1(session_id, i, kappa, &mut rng)
            .map_err(|e| anyhow!("validator_refresh_round1: {e}"))?;
        val_r1.push((out, state));
    }
    let r1_outputs: Vec<_> = val_r1.iter().map(|(o, _)| o.clone()).collect();
    let mint_r1 = aggregate_refresh_round1(session_id, kappa, &signing_set, &r1_outputs)
        .map_err(|e| anyhow!("aggregate_refresh_round1: {e}"))?;
    let (user_r2, user_state) = user_refresh_round2(session_id, &mint_r1, &joint_pk, melted, &mut rng)
        .map_err(|e| anyhow!("user_refresh_round2: {e}"))?;
    let challenge = mint_refresh_round3(session_id, &user_r2, &joint_pk)
        .map_err(|e| anyhow!("mint_refresh_round3: {e}"))?;
    let reveal = user_refresh_round4(&user_state, &challenge)
        .map_err(|e| anyhow!("user_refresh_round4: {e}"))?;
    mint_refresh_verify_reveal(&user_r2, &mint_r1, &challenge, &reveal, &joint_pk)
        .map_err(|e| anyhow!("mint_refresh_verify_reveal: {e}"))?;

    let mut r5_outputs = Vec::new();
    for (_, state) in &val_r1 {
        let f_i = finalised
            .iter()
            .find(|f| f.my_index == state.my_index)
            .ok_or_else(|| anyhow!("missing finalised share"))?;
        let r5 = validator_refresh_round5(state, &user_r2, &challenge, &f_i.my_share, &signing_set)
            .map_err(|e| anyhow!("validator_refresh_round5: {e}"))?;
        r5_outputs.push(r5);
    }
    let mint_r5 = aggregate_refresh_round5(session_id, &signing_set, &r5_outputs)
        .map_err(|e| anyhow!("aggregate_refresh_round5: {e}"))?;
    user_refresh_round6(&user_state, &challenge, &mint_r5, &joint_pk)
        .map_err(|e| anyhow!("user_refresh_round6: {e}"))
}
