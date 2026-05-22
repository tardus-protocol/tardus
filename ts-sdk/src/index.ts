/**
 * @tardus/sdk — TypeScript SDK for the TARDUS privacy payment
 * protocol on Solana. Phantom/Solflare-targetable.
 *
 * Mirrors the Rust reference implementation under `crates/`.
 * Compatible with the same on-chain Solana program at
 * `AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u` (devnet, v1.4.14).
 *
 * License: TARDUS-PROPRIETARY-1.0.
 */

// v0.1 TS-only path (X25519-clamped, internally consistent):
export * from './sealed-box.js';
export * from './mnemonic.js';
export * from './invoice.js';

// v0.2 Rust-compatible path (unclamped Curve25519 Montgomery
// ladder + Ed25519 receiving-identity, wire-format-byte-equal
// with `crates/tardus-wallet/src/sealed_box.rs`):
export { montgomeryLadderRaw } from './montgomery.js';
export { sealRustCompat, openRustCompat } from './sealed-box-rust-compat.js';
export {
  deriveMasterSeedRustCompat,
  deriveReceivingKeypairRustCompat,
} from './mnemonic-rust-compat.js';
