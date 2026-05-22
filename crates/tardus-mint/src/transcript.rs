//! Domain-separated identifiers and signatures for the mint protocol (§3.4.5).
//!
//! - [`CeremonyId`] binds all messages in a DKG or reshare ceremony to a
//!   unique session, preventing cross-ceremony replay.
//! - [`SessionId`] binds the four-round blind signing protocol together.
//! - [`TranscriptSignature`] is a newtype wrapper over a `tardus-core`
//!   `Signature` produced under a constant domain separator string;
//!   the type system prevents accidental cross-protocol confusion
//!   between transcript signatures and coin signatures.

use borsh::{BorshDeserialize, BorshSerialize};
use tardus_core::Signature;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separator prefix for ceremony transcript signatures.
/// Constant; never serialised. Used as a prefix in the signed message.
pub const CEREMONY_DOMAIN: &[u8] = b"tardus-ceremony-v1";

/// Domain separator string for the Pedersen `H` generator derivation
/// (§3.4.2). The `H` generator is computed once at startup as
/// `hash_to_point(H_DOMAIN)`.
pub const H_DOMAIN: &[u8] = b"tardus-pedersen-H-v1";

/// A 128-bit ceremony identifier (§3.4.1).
///
/// Computed as `HKDF(epoch || nonce_64bit_random)` during ceremony
/// initialisation. Two ceremonies must never share an identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct CeremonyId(pub [u8; 16]);

impl CeremonyId {
    /// Construct a CeremonyId from raw bytes. Callers are responsible
    /// for ensuring the bytes were produced by the §3.4.1 derivation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// A 128-bit session identifier for blind signing (§3.6).
///
/// Sampled fresh by the user at the start of each four-round blind
/// signing session. Validators bind their HSM-tracked nonce-reuse
/// invariant to this identifier (§3.6 Remark 3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct SessionId(pub [u8; 16]);

impl SessionId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// A ceremony transcript signature: newtype wrapper around a core
/// `Signature` produced over a domain-separated message
/// (§3.4.5). The cryptographic primitive is identical to a standard
/// Schnorr signature; the type-level distinction prevents accidental
/// cross-protocol use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TranscriptSignature {
    pub(crate) sig: Signature,
}

// Manual Borsh impl: `tardus_core::Signature` does not (and should
// not) depend on borsh, so we serialise via its native 64-byte
// canonical encoding (`r || s`).
impl BorshSerialize for TranscriptSignature {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let bytes = self.sig.to_bytes();
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for TranscriptSignature {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut bytes = [0u8; 64];
        reader.read_exact(&mut bytes)?;
        Ok(Self {
            sig: Signature::from_bytes(&bytes),
        })
    }
}

impl TranscriptSignature {
    /// Wrap a core signature as a transcript signature. The wrapping is
    /// a no-op; the caller is responsible for ensuring the signature
    /// was produced over a message prefixed with `CEREMONY_DOMAIN`.
    #[must_use]
    pub const fn from_signature(sig: Signature) -> Self {
        Self { sig }
    }

    /// Extract the underlying core signature (e.g. for on-chain
    /// verification via the Solana `ed25519` syscall).
    #[must_use]
    pub const fn as_signature(&self) -> &Signature {
        &self.sig
    }
}

/// Build the canonical message to be signed in a ceremony transcript:
/// `CEREMONY_DOMAIN || ceremony_id || epoch || transcript_hash`.
#[must_use]
pub fn ceremony_transcript_message(
    ceremony_id: CeremonyId,
    epoch: u64,
    transcript_hash: &[u8; 32],
) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(CEREMONY_DOMAIN.len() + 16 + 8 + 32);
    out.extend_from_slice(CEREMONY_DOMAIN);
    out.extend_from_slice(&ceremony_id.0);
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(transcript_hash);
    out
}

// CeremonyId/SessionId are PoD but we still want to wipe them when used
// as part of a larger zeroising state (e.g. SignerState carries SessionId).
impl Zeroize for CeremonyId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for CeremonyId {}

impl Zeroize for SessionId {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for SessionId {}
