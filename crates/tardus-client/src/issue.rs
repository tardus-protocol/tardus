//! User-side coin issuance helper (wraps the threshold blind sign of §3.6
//! for a single coin).
//!
//! The mint runs the validator side via `tardus_mint::sign::*`. The
//! user runs the four off-chain steps via `tardus_core::blind` plus
//! the secret-derivation + coin-construction helpers in this module.
//!
//! Flow:
//!
//! 1. Mint produces `BlindCommit` via the threshold protocol.
//! 2. User calls [`issue_request`] with the `BlindCommit` and joint
//!    public key to derive a fresh coin secret `x`, compute the
//!    blinded challenge `c`, and stash the unblinding state.
//! 3. User submits `c` to mint; mint returns `BlindResponse`.
//! 4. User calls [`issue_finalize`] with the response to unblind and
//!    construct the [`Coin`].

use rand_core::{CryptoRngCore, RngCore};
use tardus_core::{
    blind_request, unblind, BlindChallenge, BlindCommit, BlindResponse, PublicKey, SecretKey,
    UserState,
};
use tardus_refresh::{coin::Coin, derivation::derive_coin_secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// User's private state across the two issue round-trips.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IssueSession {
    pub(crate) seed: [u8; 32],
    pub(crate) user_state: UserState,
    #[zeroize(skip)]
    pub(crate) cp_bytes: [u8; 32],
}

impl IssueSession {
    /// Coin public commitment that the mint is blind-signing.
    #[must_use]
    pub fn cp_bytes(&self) -> [u8; 32] {
        self.cp_bytes
    }
}

/// User Round 2 — derive a fresh coin secret and produce the blinded
/// challenge for the mint to sign.
///
/// # Panics
/// Cannot panic: `SecretKey::from_bytes` is only fed canonical scalar
/// bytes derived via HKDF mod-l reduction.
///
/// # Errors
/// - [`Error::Core`] if the user-side blind request fails.
pub fn issue_request<R: CryptoRngCore + RngCore + ?Sized>(
    joint_pk: &PublicKey,
    mint_commit: &BlindCommit,
    rng: &mut R,
) -> Result<(BlindChallenge, IssueSession)> {
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let x = derive_coin_secret(&seed);
    let sk = SecretKey::from_bytes(&x.to_bytes())
        .expect("derived scalar is canonical by construction");
    let pk = PublicKey::from_secret(&sk);
    let cp_bytes = pk.to_bytes();

    let (challenge, user_state) =
        blind_request(mint_commit, joint_pk, &cp_bytes, rng).map_err(Error::Core)?;

    Ok((
        challenge,
        IssueSession {
            seed,
            user_state,
            cp_bytes,
        },
    ))
}

/// User Round 4 — unblind the mint's response and construct the coin.
///
/// Takes `session` by value intentionally so that the secret material
/// inside (`UserState`, `seed`) is `Drop`ped and zeroised at the end
/// of the function, preventing the caller from accidentally reusing
/// a stale session.
///
/// # Panics
/// Cannot panic: `SecretKey::from_bytes` is fed the same canonical
/// scalar derived in [`issue_request`].
///
/// # Errors
/// - [`Error::Core`] if the unblind step fails.
/// - [`Error::Refresh`] if the resulting `Coin::new` invariant fails
///   (which is mathematically impossible given consistent inputs).
#[allow(clippy::needless_pass_by_value)]
pub fn issue_finalize(session: IssueSession, response: &BlindResponse) -> Result<Coin> {
    let sig = unblind(&session.user_state, response).map_err(Error::Core)?;
    let x = derive_coin_secret(&session.seed);
    let sk = SecretKey::from_bytes(&x.to_bytes())
        .expect("derived scalar is canonical by construction");
    Coin::new(sk, session.cp_bytes, sig).map_err(Error::Refresh)
}
