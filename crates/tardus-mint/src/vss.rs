//! Pedersen Verifiable Secret Sharing (spec §2.6, §3.4.2).
//!
//! Implements the dealer + verifier sides of Pedersen VSS over
//! edwards25519. The dealer splits a secret `s ∈ F_l` into `n` shares
//! (one per participant), with reconstruction threshold `t`. Each
//! share is publicly verifiable against the dealer's commitments.
//!
//! The Pedersen `H` generator is derived deterministically from
//! `H_DOMAIN` via the try-and-increment construction in
//! [`h_generator`]. The derivation is reproducible across all
//! participants and contains no trapdoor.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::IsIdentity,
};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{Error, Result},
    transcript::H_DOMAIN,
};

// =====================================================================
// Pedersen H generator
// =====================================================================

/// Derive the Pedersen `H` generator from the constant `H_DOMAIN`.
///
/// Uses try-and-increment over `SHA-512(H_DOMAIN || counter_le_u32)`:
/// decode the first 32 bytes as a compressed edwards25519 point,
/// multiply by the cofactor (`8`) to land in the prime-order subgroup,
/// and reject the identity. The first counter that succeeds yields `H`.
///
/// The derivation is deterministic: every honest party computes the
/// same `H`. There is no trapdoor — no participant knows
/// `log_G H`, by construction.
///
/// # Panics
/// Panics if the `u32` counter overflows without finding a valid
/// point. This is statistically impossible — each iteration succeeds
/// with probability ≈ 1/2, so the expected number of iterations is 2
/// and the probability of reaching 2^32 iterations is 2^{-2^32},
/// utterly negligible.
#[must_use]
pub fn h_generator() -> EdwardsPoint {
    let mut counter: u32 = 0;
    loop {
        let mut hasher = Sha512::new();
        hasher.update(H_DOMAIN);
        hasher.update(counter.to_le_bytes());
        let h = hasher.finalize();
        let mut compressed = [0u8; 32];
        compressed.copy_from_slice(&h[..32]);
        if let Some(point) = CompressedEdwardsY(compressed).decompress() {
            let lifted = point.mul_by_cofactor();
            if !lifted.is_identity() {
                return lifted;
            }
        }
        counter = counter
            .checked_add(1)
            .expect("h_generator: try-and-increment counter overflowed");
        debug_assert!(
            counter < 1_000_000,
            "h_generator: try-and-increment failed catastrophically"
        );
    }
}

// =====================================================================
// Types
// =====================================================================

/// VSS parameters: committee size `n`, reconstruction threshold `t`.
/// Must satisfy `1 <= t <= n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct VssParameters {
    pub n: u16,
    pub t: u16,
}

impl VssParameters {
    /// Construct parameters.
    ///
    /// # Errors
    /// Returns `Error::InvalidSigningSet` if `t == 0` or `t > n`.
    pub fn new(n: u16, t: u16) -> Result<Self> {
        if t == 0 || t > n {
            return Err(Error::InvalidSigningSet);
        }
        Ok(Self { n, t })
    }
}

/// A single VSS share `(f(j), g(j))` for participant `index = j`.
///
/// Wiped on drop; secret-bearing.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VssShare {
    pub index: u16,
    pub(crate) f_share: Scalar,
    pub(crate) g_share: Scalar,
}

// Manual `Debug` impl that redacts secret material. The `f_share` and
// `g_share` scalars are never printed in plain form.
impl core::fmt::Debug for VssShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VssShare")
            .field("index", &self.index)
            .field("f_share", &"<REDACTED>")
            .field("g_share", &"<REDACTED>")
            .finish()
    }
}

impl VssShare {
    #[must_use]
    pub fn index(&self) -> u16 {
        self.index
    }

    /// Extract the `f`-polynomial share (the actual secret-share component).
    #[must_use]
    pub fn f_share_bytes(&self) -> [u8; 32] {
        self.f_share.to_bytes()
    }

    /// Extract the `g`-polynomial blinding share.
    #[must_use]
    pub fn g_share_bytes(&self) -> [u8; 32] {
        self.g_share.to_bytes()
    }
}

impl BorshSerialize for VssShare {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&self.index.to_le_bytes())?;
        writer.write_all(&self.f_share.to_bytes())?;
        writer.write_all(&self.g_share.to_bytes())?;
        Ok(())
    }
}

impl BorshDeserialize for VssShare {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut idx_bytes = [0u8; 2];
        reader.read_exact(&mut idx_bytes)?;
        let index = u16::from_le_bytes(idx_bytes);

        let mut f_bytes = [0u8; 32];
        reader.read_exact(&mut f_bytes)?;
        let f_share = Option::<Scalar>::from(Scalar::from_canonical_bytes(f_bytes))
            .ok_or_else(|| {
                borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "non-canonical f_share scalar",
                )
            })?;

        let mut g_bytes = [0u8; 32];
        reader.read_exact(&mut g_bytes)?;
        let g_share = Option::<Scalar>::from(Scalar::from_canonical_bytes(g_bytes))
            .ok_or_else(|| {
                borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "non-canonical g_share scalar",
                )
            })?;

        Ok(Self {
            index,
            f_share,
            g_share,
        })
    }
}

/// Pedersen commitments `[C_0, C_1, ..., C_{t-1}]` for one VSS dealing.
///
/// `C_k = a_k · G + b_k · H`. Used for share verification (statistical
/// hiding of intermediate state).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VssCommitments {
    pub(crate) coeffs: Vec<EdwardsPoint>,
}

impl VssCommitments {
    /// The "secret" commitment `C_0 = s·G + r·H` — publicly readable.
    #[must_use]
    pub fn secret_commitment(&self) -> &EdwardsPoint {
        &self.coeffs[0]
    }

    /// Number of coefficient commitments (equals threshold `t`).
    #[must_use]
    pub fn t(&self) -> usize {
        self.coeffs.len()
    }
}

impl BorshSerialize for VssCommitments {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        serialize_point_vec(&self.coeffs, writer)
    }
}

impl BorshDeserialize for VssCommitments {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        deserialize_point_vec(reader).map(|coeffs| Self { coeffs })
    }
}

/// Feldman commitments `[A_0, A_1, ..., A_{t-1}]` for one VSS dealing.
///
/// `A_k = a_k · G`. Used for joint key derivation in DKG (§3.4) and
/// as the public key against which Schnorr proofs of knowledge of
/// the secret `s = a_0` are verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeldmanCommitments {
    pub(crate) coeffs: Vec<EdwardsPoint>,
}

impl FeldmanCommitments {
    /// The "secret" commitment `A_0 = s · G` — the public key
    /// corresponding to the dealer's secret contribution.
    #[must_use]
    pub fn secret_commitment(&self) -> &EdwardsPoint {
        &self.coeffs[0]
    }

    /// Number of coefficient commitments (equals threshold `t`).
    #[must_use]
    pub fn t(&self) -> usize {
        self.coeffs.len()
    }
}

impl BorshSerialize for FeldmanCommitments {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        serialize_point_vec(&self.coeffs, writer)
    }
}

impl BorshDeserialize for FeldmanCommitments {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        deserialize_point_vec(reader).map(|coeffs| Self { coeffs })
    }
}

fn serialize_point_vec<W: borsh::io::Write>(
    coeffs: &[EdwardsPoint],
    writer: &mut W,
) -> borsh::io::Result<()> {
    let count: u16 = u16::try_from(coeffs.len()).map_err(|_| {
        borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "coeffs > u16::MAX")
    })?;
    writer.write_all(&count.to_le_bytes())?;
    for pt in coeffs {
        writer.write_all(&pt.compress().to_bytes())?;
    }
    Ok(())
}

fn deserialize_point_vec<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Vec<EdwardsPoint>> {
    let mut count_bytes = [0u8; 2];
    reader.read_exact(&mut count_bytes)?;
    let count = u16::from_le_bytes(count_bytes) as usize;
    let mut coeffs = Vec::with_capacity(count);
    for _ in 0..count {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let pt = CompressedEdwardsY(bytes).decompress().ok_or_else(|| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid commitment point",
            )
        })?;
        coeffs.push(pt);
    }
    Ok(coeffs)
}

// =====================================================================
// Dealer
// =====================================================================

/// Deal a secret `s` into `n` Pedersen+Feldman VSS shares with threshold `t`.
///
/// Returns three artifacts:
/// - Pedersen commitments `[C_k]` for share verification.
/// - Feldman commitments `[A_k]` for joint key derivation in DKG (§3.4).
/// - One share `(f(j), g(j))` per participant, indexed `1..=n`.
///
/// The Pedersen and Feldman commitments are derived from the same
/// `f`-polynomial (so `A_k` is the `G`-component of `C_k`).
///
/// # Panics
/// Panics only if internal `u16` casting fails, which is impossible
/// given the loop bound `j ∈ 1..=n` and `n: u16`.
pub fn deal<R: CryptoRngCore + ?Sized>(
    secret: &Scalar,
    params: VssParameters,
    h: &EdwardsPoint,
    rng: &mut R,
) -> (VssCommitments, FeldmanCommitments, Vec<VssShare>) {
    let t = params.t as usize;
    let n = params.n as usize;

    // f(x) = s + a_1 x + ... + a_{t-1} x^{t-1}
    let mut f_coeffs: Vec<Scalar> = Vec::with_capacity(t);
    f_coeffs.push(*secret);
    for _ in 1..t {
        f_coeffs.push(Scalar::random(rng));
    }

    // g(x) = r + b_1 x + ... + b_{t-1} x^{t-1}
    let mut g_coeffs: Vec<Scalar> = Vec::with_capacity(t);
    for _ in 0..t {
        g_coeffs.push(Scalar::random(rng));
    }

    // C_k = a_k · G + b_k · H   (Pedersen)
    // A_k = a_k · G              (Feldman; the G-component of C_k)
    let mut pedersen_coeffs: Vec<EdwardsPoint> = Vec::with_capacity(t);
    let mut feldman_coeffs: Vec<EdwardsPoint> = Vec::with_capacity(t);
    for k in 0..t {
        let a_k = f_coeffs[k] * ED25519_BASEPOINT_POINT;
        let c_k = a_k + g_coeffs[k] * h;
        feldman_coeffs.push(a_k);
        pedersen_coeffs.push(c_k);
    }

    // Evaluate at j = 1..=n
    let mut shares: Vec<VssShare> = Vec::with_capacity(n);
    for j in 1..=n {
        let j_scalar = Scalar::from(j as u64);
        let f_j = horner_eval_scalar(&f_coeffs, &j_scalar);
        let g_j = horner_eval_scalar(&g_coeffs, &j_scalar);
        shares.push(VssShare {
            index: u16::try_from(j).expect("n is u16, j ≤ n"),
            f_share: f_j,
            g_share: g_j,
        });
    }

    (
        VssCommitments {
            coeffs: pedersen_coeffs,
        },
        FeldmanCommitments {
            coeffs: feldman_coeffs,
        },
        shares,
    )
}

// =====================================================================
// Verifier
// =====================================================================

/// Verify a VSS share against the dealer's public commitments.
///
/// Checks `f(j) · G + g(j) · H = Σ_{k=0}^{t-1} j^k · C_k` via Horner on
/// the group elements.
///
/// # Errors
/// - `Error::InvalidSigningSet` if `share.index == 0`.
/// - `Error::VssShareInvalid` if the equation does not hold.
pub fn verify_share(
    share: &VssShare,
    commitments: &VssCommitments,
    h: &EdwardsPoint,
) -> Result<()> {
    if share.index == 0 {
        return Err(Error::InvalidSigningSet);
    }
    let j_scalar = Scalar::from(u64::from(share.index));

    // lhs = f_share · G + g_share · H
    let lhs = share.f_share * ED25519_BASEPOINT_POINT + share.g_share * h;

    // rhs = Σ_{k=0}^{t-1} j^k · C_k, via Horner:
    //   rhs := 0
    //   for c in coeffs.iter().rev():
    //       rhs := rhs · j + c
    let mut rhs = EdwardsPoint::default(); // identity
    for c_k in commitments.coeffs.iter().rev() {
        rhs = rhs * j_scalar + c_k;
    }

    if lhs == rhs {
        Ok(())
    } else {
        Err(Error::VssShareInvalid)
    }
}

// =====================================================================
// Internal helpers
// =====================================================================

/// Horner polynomial evaluation in `F_l`.
fn horner_eval_scalar(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for c in coeffs.iter().rev() {
        acc = acc * x + c;
    }
    acc
}
