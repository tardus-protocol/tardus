//! Instruction set (spec §5.3).

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use tardus_core::Signature;

/// A TARDUS program instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instruction {
    /// Register a new keyset (committee-authorized).
    RegisterKeyset {
        keyset_id: [u8; 33],
        denom: u64,
        joint_pk: [u8; 32],
        epoch: u64,
        /// Threshold-signed authorization tuple of `t` transcript signatures.
        /// Serialised as raw bytes; verification at processor entry.
        authorization: Vec<u8>,
    },

    /// User deposit: SOL → vault, off-chain mint then issues a coin.
    Deposit { denom: u64, lamports: u64 },

    /// Refresh: nullify an existing coin. The new coins are NOT carried
    /// on-chain (anonymity preservation, §5.3.3); they emerge off-chain
    /// via the round-6 unblinding of §4.5.
    ///
    /// v1.4.3: nullifier is bound to `coin_pubkey` (Cp), not the
    /// secret `x`. Spending only requires the public commitment +
    /// mint signature (bearer model).
    Refresh {
        /// Public commitment of the surrendered coin (32 bytes).
        coin_pubkey: [u8; 32],
        /// Mint signature on the coin's compressed pubkey.
        coin_signature: Signature,
        /// Denomination of the surrendered coin.
        denom: u64,
    },

    /// Withdraw: redeem a coin for vault collateral.
    Withdraw {
        coin_pubkey: [u8; 32],
        coin_signature: Signature,
        denom: u64,
        recipient: [u8; 32],
    },

    /// Mark a keyset as revoked (committee-authorized).
    Revoke {
        keyset_id: [u8; 33],
        authorization: Vec<u8>,
    },

    /// Bootstrap a program-owned PDA (or system-owned vault PDA).
    /// Self-pays for rent exemption via the signer. Idempotent: if
    /// the target account already exists with lamports > 0, returns
    /// `ProgramError::Custom(15)` (ERR_ACCOUNT_ALREADY_EXISTS) so the
    /// caller knows this was already done.
    ///
    /// v1.4.7: enables off-chain devnet/mainnet bootstrap without
    /// requiring genesis-style account pre-population.
    Bootstrap {
        account_kind: BootstrapKind,
        /// Allocation size in bytes. Ignored for `Vault` (always 0).
        size: u32,
        /// Denomination for `Vault` kind; ignored for others.
        denom: u64,
    },

    /// **v1.4.13 / Faz 9.3** — Deposit SOL into the SponsorPool PDA.
    /// Anyone can deposit; the pool is a community-funded faucet
    /// that decouples the original SOL source from the ephemeral
    /// Refresh signer. After deposit, anyone can call `SponsorPayout`
    /// to drain a fixed amount to a fresh ephemeral pubkey.
    SponsorDeposit { amount: u64 },

    /// **v1.4.14 / Faz G-mini** — Resize an existing program-owned
    /// PDA (registry or nullifier-tree) to a larger allocation.
    /// Top-up rent is transferred from the caller via System CPI
    /// inside the handler. This is the immediate scaling fix for
    /// the 1024-byte registry cap that started rejecting new
    /// `RegisterKeyset` at ~11 entries.
    ///
    /// Full Light Protocol compressed-Merkle-tree integration
    /// remains v1.5+.
    ResizeAccount {
        account_kind: BootstrapKind,
        new_size: u32,
        denom: u64,
    },

    /// **v1.4.13 / Faz 9.3** — Drain `lamports` from SponsorPool PDA
    /// to `recipient`. Rate-limited to 1 payout per 5 slots (~2.5 s)
    /// across all callers via `last_payout_slot` tracking.
    ///
    /// The payout is intentionally unauthenticated: the pool is a
    /// "use-it-or-lose-it" sponsor faucet for the TARDUS ecosystem.
    /// Drain risk is bounded by the rate limit; the pool refills
    /// via SponsorDeposit as long as net inflow > drain rate.
    SponsorPayout {
        lamports: u64,
        recipient: [u8; 32],
    },
}

/// Discriminator for the program's PDA account types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapKind {
    KeysetRegistry = 0,
    NullifierTree = 1,
    Vault = 2,
    /// **v1.4.13** — SponsorPool PDA (program-owned data slot for
    /// rate-limit accounting; the lamports live in a sibling
    /// system-owned PDA).
    SponsorPool = 3,
}

impl BootstrapKind {
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// # Errors
    /// Returns an error if the byte does not correspond to a valid kind.
    pub fn try_from_byte(b: u8) -> Result<Self, borsh::io::Error> {
        match b {
            0 => Ok(Self::KeysetRegistry),
            1 => Ok(Self::NullifierTree),
            2 => Ok(Self::Vault),
            3 => Ok(Self::SponsorPool),
            _ => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unknown BootstrapKind",
            )),
        }
    }
}

/// Manual Borsh impls — borsh derive on enums with fixed-size byte
/// arrays sometimes requires explicit handling for serde-style
/// stability across versions.
impl BorshSerialize for Instruction {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        match self {
            Self::RegisterKeyset {
                keyset_id,
                denom,
                joint_pk,
                epoch,
                authorization,
            } => {
                writer.write_all(&[0u8])?;
                writer.write_all(keyset_id)?;
                writer.write_all(&denom.to_le_bytes())?;
                writer.write_all(joint_pk)?;
                writer.write_all(&epoch.to_le_bytes())?;
                borsh::BorshSerialize::serialize(authorization, writer)
            }
            Self::Deposit { denom, lamports } => {
                writer.write_all(&[1u8])?;
                writer.write_all(&denom.to_le_bytes())?;
                writer.write_all(&lamports.to_le_bytes())
            }
            Self::Refresh {
                coin_pubkey,
                coin_signature,
                denom,
            } => {
                writer.write_all(&[2u8])?;
                writer.write_all(coin_pubkey)?;
                writer.write_all(&coin_signature.to_bytes())?;
                writer.write_all(&denom.to_le_bytes())
            }
            Self::Withdraw {
                coin_pubkey,
                coin_signature,
                denom,
                recipient,
            } => {
                writer.write_all(&[3u8])?;
                writer.write_all(coin_pubkey)?;
                writer.write_all(&coin_signature.to_bytes())?;
                writer.write_all(&denom.to_le_bytes())?;
                writer.write_all(recipient)
            }
            Self::Revoke {
                keyset_id,
                authorization,
            } => {
                writer.write_all(&[4u8])?;
                writer.write_all(keyset_id)?;
                borsh::BorshSerialize::serialize(authorization, writer)
            }
            Self::Bootstrap {
                account_kind,
                size,
                denom,
            } => {
                writer.write_all(&[5u8])?;
                writer.write_all(&[account_kind.as_byte()])?;
                writer.write_all(&size.to_le_bytes())?;
                writer.write_all(&denom.to_le_bytes())
            }
            Self::SponsorDeposit { amount } => {
                writer.write_all(&[6u8])?;
                writer.write_all(&amount.to_le_bytes())
            }
            Self::SponsorPayout { lamports, recipient } => {
                writer.write_all(&[7u8])?;
                writer.write_all(&lamports.to_le_bytes())?;
                writer.write_all(recipient)
            }
            Self::ResizeAccount {
                account_kind,
                new_size,
                denom,
            } => {
                writer.write_all(&[8u8])?;
                writer.write_all(&[account_kind.as_byte()])?;
                writer.write_all(&new_size.to_le_bytes())?;
                writer.write_all(&denom.to_le_bytes())
            }
        }
    }
}

impl BorshDeserialize for Instruction {
    #[allow(clippy::too_many_lines)]
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => {
                let mut keyset_id = [0u8; 33];
                reader.read_exact(&mut keyset_id)?;
                let mut denom_bytes = [0u8; 8];
                reader.read_exact(&mut denom_bytes)?;
                let denom = u64::from_le_bytes(denom_bytes);
                let mut joint_pk = [0u8; 32];
                reader.read_exact(&mut joint_pk)?;
                let mut epoch_bytes = [0u8; 8];
                reader.read_exact(&mut epoch_bytes)?;
                let epoch = u64::from_le_bytes(epoch_bytes);
                let authorization = borsh::BorshDeserialize::deserialize_reader(reader)?;
                Ok(Self::RegisterKeyset {
                    keyset_id,
                    denom,
                    joint_pk,
                    epoch,
                    authorization,
                })
            }
            1 => {
                let mut denom_bytes = [0u8; 8];
                reader.read_exact(&mut denom_bytes)?;
                let mut lamports_bytes = [0u8; 8];
                reader.read_exact(&mut lamports_bytes)?;
                Ok(Self::Deposit {
                    denom: u64::from_le_bytes(denom_bytes),
                    lamports: u64::from_le_bytes(lamports_bytes),
                })
            }
            2 => {
                let mut coin_pubkey = [0u8; 32];
                reader.read_exact(&mut coin_pubkey)?;
                let mut sig_bytes = [0u8; 64];
                reader.read_exact(&mut sig_bytes)?;
                let coin_signature = Signature::from_bytes(&sig_bytes);
                let mut denom_bytes = [0u8; 8];
                reader.read_exact(&mut denom_bytes)?;
                Ok(Self::Refresh {
                    coin_pubkey,
                    coin_signature,
                    denom: u64::from_le_bytes(denom_bytes),
                })
            }
            3 => {
                let mut coin_pubkey = [0u8; 32];
                reader.read_exact(&mut coin_pubkey)?;
                let mut sig_bytes = [0u8; 64];
                reader.read_exact(&mut sig_bytes)?;
                let coin_signature = Signature::from_bytes(&sig_bytes);
                let mut denom_bytes = [0u8; 8];
                reader.read_exact(&mut denom_bytes)?;
                let mut recipient = [0u8; 32];
                reader.read_exact(&mut recipient)?;
                Ok(Self::Withdraw {
                    coin_pubkey,
                    coin_signature,
                    denom: u64::from_le_bytes(denom_bytes),
                    recipient,
                })
            }
            4 => {
                let mut keyset_id = [0u8; 33];
                reader.read_exact(&mut keyset_id)?;
                let authorization = borsh::BorshDeserialize::deserialize_reader(reader)?;
                Ok(Self::Revoke {
                    keyset_id,
                    authorization,
                })
            }
            5 => {
                let mut kind_byte = [0u8; 1];
                reader.read_exact(&mut kind_byte)?;
                let account_kind = BootstrapKind::try_from_byte(kind_byte[0])?;
                let mut size_bytes = [0u8; 4];
                reader.read_exact(&mut size_bytes)?;
                let mut denom_bytes = [0u8; 8];
                reader.read_exact(&mut denom_bytes)?;
                Ok(Self::Bootstrap {
                    account_kind,
                    size: u32::from_le_bytes(size_bytes),
                    denom: u64::from_le_bytes(denom_bytes),
                })
            }
            6 => {
                let mut amount_bytes = [0u8; 8];
                reader.read_exact(&mut amount_bytes)?;
                Ok(Self::SponsorDeposit {
                    amount: u64::from_le_bytes(amount_bytes),
                })
            }
            7 => {
                let mut lamports_bytes = [0u8; 8];
                reader.read_exact(&mut lamports_bytes)?;
                let mut recipient = [0u8; 32];
                reader.read_exact(&mut recipient)?;
                Ok(Self::SponsorPayout {
                    lamports: u64::from_le_bytes(lamports_bytes),
                    recipient,
                })
            }
            8 => {
                let mut kind_byte = [0u8; 1];
                reader.read_exact(&mut kind_byte)?;
                let account_kind = BootstrapKind::try_from_byte(kind_byte[0])?;
                let mut size_bytes = [0u8; 4];
                reader.read_exact(&mut size_bytes)?;
                let mut denom_bytes = [0u8; 8];
                reader.read_exact(&mut denom_bytes)?;
                Ok(Self::ResizeAccount {
                    account_kind,
                    new_size: u32::from_le_bytes(size_bytes),
                    denom: u64::from_le_bytes(denom_bytes),
                })
            }
            _ => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unknown instruction tag",
            )),
        }
    }
}
