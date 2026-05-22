//! TARDUS wallet CLI binary.
//!
//! Subcommand surface (v3.3):
//!
//! ```text
//! tardus-wallet mnemonic generate [--words 12|24]
//! tardus-wallet mnemonic seed --phrase "..." [--passphrase "..."]
//! tardus-wallet issue   --validator https://v1 --validator https://v2 ... \
//!                       --joint-pk <hex32> [--session-id <hex16>]
//! tardus-wallet refresh --validator https://v1 --validator https://v2 ... \
//!                       --joint-pk <hex32> \
//!                       --coin-secret <hex32> \
//!                       --coin-pubkey <hex32> \
//!                       --coin-signature <hex64> \
//!                       [--session-id <hex16>]
//! ```

#![allow(clippy::doc_markdown)]

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::PathBuf;
use tardus_client::coin_store::{CoinStatus, StoredCoin};
use tardus_core::{PublicKey, SecretKey, Signature};
use tardus_mint::transcript::SessionId;
use tardus_refresh::coin::Coin;
use tardus_wallet::{
    derive_master_seed, derive_receiving_keypair, generate_mnemonic, issue_coin, parse_mnemonic,
    refresh_coin, sealed_box, KeysetDb, KeysetInfo, ValidatorEndpoint, WalletClientPool, WalletDb,
    WordCount,
};

#[derive(Parser)]
#[command(
    name = "tardus-wallet",
    version,
    about = "TARDUS user-side wallet CLI: BIP-39 + multi-validator orchestrator"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// BIP-39 mnemonic operations.
    Mnemonic {
        #[command(subcommand)]
        action: MnemonicAction,
    },
    /// Persistent wallet operations (encrypted on-disk coin store).
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },
    /// Mint a fresh coin by driving threshold blind sign across N validators.
    Issue(IssueArgs),
    /// Refresh an existing coin via κ-fold cut-and-choose across N validators.
    Refresh(RefreshArgs),
    /// Manage saved keyset configurations (named bundles of joint_pk +
    /// validator URLs + denom).
    Keyset {
        #[command(subcommand)]
        action: KeysetAction,
    },
    /// `tardus://` invoice URI utilities (encode + decode).
    Invoice {
        #[command(subcommand)]
        action: InvoiceAction,
    },
    /// Pay an invoice: mint a coin and deliver it to the recipient's
    /// inbox on a relay.
    Pay(PayArgs),
    /// Receive coins from a relay inbox: poll, decode payloads, add
    /// to wallet, delete from relay.
    Receive(ReceiveArgs),
}

#[derive(clap::Args)]
struct ReceiveArgs {
    /// Relay base URL (e.g. `https://relay.tardus.example.com:9799`).
    #[arg(long)]
    relay: String,
    /// Our receiving pubkey as 64-char hex (the same one we shared
    /// with senders via `tardus-wallet invoice make --pubkey ...`).
    #[arg(long = "recipient-pubkey")]
    recipient_pubkey: String,
    #[arg(long)]
    wallet_file: PathBuf,
    #[arg(long)]
    wallet_phrase: String,
    #[arg(long, default_value = "")]
    wallet_passphrase: String,
    /// Label prefix for received coins; the relay's `message_id`
    /// is appended for uniqueness.
    #[arg(long, default_value = "from-relay")]
    label_prefix: String,
    /// Don't delete messages from the relay after adding (default
    /// is to delete — messages have TTL anyway).
    #[arg(long)]
    keep_on_relay: bool,
}

#[derive(clap::Args)]
struct PayArgs {
    /// `tardus://` invoice URI to pay.
    #[arg(long)]
    invoice: String,
    /// Keyset to mint under. Resolves validators + joint_pk from
    /// `--keysets-file`.
    #[arg(long)]
    keyset: String,
    #[arg(long, default_value = "./keysets.bin")]
    keysets_file: PathBuf,
    #[arg(long)]
    wallet_phrase: String,
    #[arg(long, default_value = "")]
    wallet_passphrase: String,
    /// Override the relay URL (otherwise the first `relay=` from the
    /// invoice URI is used).
    #[arg(long)]
    relay: Option<String>,
    /// TTL for the relay inbox entry, seconds. Default = 7 days.
    #[arg(long, default_value = "604800")]
    ttl_secs: u64,
    /// If supplied, also persist the minted (then-spent) coin into the
    /// wallet file as a Spent record for the audit trail.
    #[arg(long)]
    wallet_file: Option<PathBuf>,
    /// Label for the wallet entry (if `--wallet-file` supplied).
    #[arg(long)]
    label: Option<String>,
    /// Encrypt the payload to the invoice's recipient pubkey via the
    /// v5.5 sealed-box AEAD (relay then holds opaque ciphertext).
    #[arg(long)]
    encrypt: bool,
}

#[derive(Subcommand)]
enum InvoiceAction {
    /// Encode an invoice URI from components.
    Make {
        /// Recipient public key as 64-char hex.
        #[arg(long)]
        pubkey: String,
        /// Denomination in lamports.
        #[arg(long)]
        denom: u64,
        /// Relay URL (may be repeated).
        #[arg(long)]
        relay: Vec<String>,
        /// Free-form memo (≤ 128 bytes).
        #[arg(long)]
        memo: Option<String>,
    },
    /// Decode a `tardus://` URI and print fields as JSON.
    Parse {
        uri: String,
    },
}

#[derive(Subcommand)]
enum KeysetAction {
    /// Add or overwrite a keyset entry.
    Add {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "./keysets.bin")]
        file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long = "joint-pk")]
        joint_pk: String,
        #[arg(long)]
        denom: u64,
        #[arg(long = "validator", required = true)]
        validators: Vec<String>,
        #[arg(long = "ca-cert")]
        ca_cert_path: Option<String>,
        #[arg(long = "client-cert")]
        client_cert_path: Option<String>,
    },
    /// List all keysets.
    List {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "./keysets.bin")]
        file: PathBuf,
    },
    /// Remove a keyset by name.
    Remove {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "./keysets.bin")]
        file: PathBuf,
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
enum WalletAction {
    /// Show wallet status (coin count + balance per denom).
    Status {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "./wallet.bin")]
        file: PathBuf,
    },
    /// Add a coin into the wallet store (e.g. one freshly emitted by `issue`).
    AddCoin {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "./wallet.bin")]
        file: PathBuf,
        #[arg(long = "coin-secret")]
        coin_secret: String,
        #[arg(long = "coin-pubkey")]
        coin_pubkey: String,
        #[arg(long = "coin-signature")]
        coin_signature: String,
        #[arg(long)]
        denom: u64,
        #[arg(long)]
        label: Option<String>,
    },
    /// List every stored coin (pubkey, denom, status).
    List {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
        #[arg(long, default_value = "./wallet.bin")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum MnemonicAction {
    /// Generate a fresh mnemonic from OsRng.
    Generate {
        #[arg(long, default_value = "24")]
        words: u8,
    },
    /// Derive the 32-byte master seed from a mnemonic + optional passphrase.
    Seed {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
    },
    /// Show the receiving identity public key derived from the mnemonic.
    /// Share this pubkey with senders via `tardus-wallet invoice make
    /// --pubkey <hex>`.
    Identity {
        #[arg(long)]
        phrase: String,
        #[arg(long, default_value = "")]
        passphrase: String,
    },
}

#[derive(clap::Args)]
struct IssueArgs {
    /// Validator base URL. Pass once per validator (order = signing-set index).
    /// Mutually exclusive with `--keyset`.
    #[arg(long = "validator", conflicts_with = "keyset")]
    validators: Vec<String>,
    /// Joint public key as 64-char hex. Mutually exclusive with `--keyset`.
    #[arg(long = "joint-pk", conflicts_with = "keyset")]
    joint_pk: Option<String>,
    /// Resolve validators + joint_pk + denom from the named keyset in
    /// `--keysets-file` (default `./keysets.bin`). Requires `--wallet-phrase`.
    #[arg(long)]
    keyset: Option<String>,
    /// Keysets file path (only used with `--keyset`).
    #[arg(long, default_value = "./keysets.bin")]
    keysets_file: PathBuf,
    /// Session id as 32-char hex (16 bytes). If omitted, sampled from OsRng.
    #[arg(long = "session-id")]
    session_id: Option<String>,
    /// Optional wallet file to auto-save the minted coin into.
    /// Requires `--wallet-phrase` and `--denom`.
    #[arg(long = "wallet-file")]
    wallet_file: Option<PathBuf>,
    #[arg(long = "wallet-phrase")]
    wallet_phrase: Option<String>,
    #[arg(long = "wallet-passphrase", default_value = "")]
    wallet_passphrase: String,
    /// Denomination to record alongside the coin in the wallet (required
    /// with `--wallet-file`).
    #[arg(long)]
    denom: Option<u64>,
    /// Optional label for the wallet entry.
    #[arg(long)]
    label: Option<String>,
}

#[derive(clap::Args)]
struct RefreshArgs {
    #[arg(long = "validator", conflicts_with = "keyset")]
    validators: Vec<String>,
    #[arg(long = "joint-pk", conflicts_with = "keyset")]
    joint_pk: Option<String>,
    #[arg(long)]
    keyset: Option<String>,
    #[arg(long, default_value = "./keysets.bin")]
    keysets_file: PathBuf,
    /// Surrendered coin material — either pass explicitly OR via
    /// `--wallet-file` + `--coin-label` to load from the store.
    #[arg(long = "coin-secret")]
    coin_secret: Option<String>,
    #[arg(long = "coin-pubkey")]
    coin_pubkey: Option<String>,
    #[arg(long = "coin-signature")]
    coin_signature: Option<String>,
    #[arg(long = "session-id")]
    session_id: Option<String>,
    /// Resolve coin material from a wallet file by label. Requires
    /// `--wallet-phrase`. On success, marks the old coin as Spent
    /// and adds the refreshed coin (with the same label) back to
    /// the wallet.
    #[arg(long = "wallet-file")]
    wallet_file: Option<PathBuf>,
    #[arg(long = "wallet-phrase")]
    wallet_phrase: Option<String>,
    #[arg(long = "wallet-passphrase", default_value = "")]
    wallet_passphrase: String,
    #[arg(long = "coin-label")]
    coin_label: Option<String>,
}

fn parse_hex32(s: &str, label: &str) -> Result<[u8; 32]> {
    let b = hex::decode(s).with_context(|| format!("{label} hex"))?;
    if b.len() != 32 {
        return Err(anyhow!("{label}: expected 32 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

fn parse_hex64(s: &str, label: &str) -> Result<[u8; 64]> {
    let b = hex::decode(s).with_context(|| format!("{label} hex"))?;
    if b.len() != 64 {
        return Err(anyhow!("{label}: expected 64 bytes, got {}", b.len()));
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&b);
    Ok(a)
}

fn parse_session_id(opt: Option<&str>) -> Result<SessionId> {
    if let Some(s) = opt {
        let b = hex::decode(s).context("session-id hex")?;
        if b.len() != 16 {
            return Err(anyhow!("session-id: expected 16 bytes, got {}", b.len()));
        }
        let mut a = [0u8; 16];
        a.copy_from_slice(&b);
        Ok(SessionId::from_bytes(a))
    } else {
        let mut a = [0u8; 16];
        OsRng.fill_bytes(&mut a);
        Ok(SessionId::from_bytes(a))
    }
}

/// Resolve `(validators, joint_pk_hex, default_denom)` for `issue` —
/// either from explicit `--validator`/`--joint-pk` flags or by
/// looking up the named keyset in the keysets file.
fn resolve_issue_inputs(args: &IssueArgs) -> Result<(Vec<String>, String, Option<u64>)> {
    if let Some(name) = args.keyset.as_deref() {
        let phrase = args
            .wallet_phrase
            .as_deref()
            .ok_or_else(|| anyhow!("--keyset requires --wallet-phrase"))?;
        let m = parse_mnemonic(phrase).map_err(|e| anyhow!("{e}"))?;
        let seed = derive_master_seed(&m, &args.wallet_passphrase);
        let db = KeysetDb::open(args.keysets_file.clone(), &seed)
            .map_err(|e| anyhow!("{e}"))?;
        let info = db
            .store()
            .get(name)
            .ok_or_else(|| anyhow!("unknown keyset '{name}' in {}", args.keysets_file.display()))?;
        Ok((info.validators.clone(), info.joint_pk_hex.clone(), Some(info.denom)))
    } else {
        let joint_pk = args
            .joint_pk
            .clone()
            .ok_or_else(|| anyhow!("either --keyset or --joint-pk is required"))?;
        if args.validators.is_empty() {
            return Err(anyhow!("--validator required at least once (or use --keyset)"));
        }
        Ok((args.validators.clone(), joint_pk, None))
    }
}

fn resolve_refresh_inputs(args: &RefreshArgs) -> Result<(Vec<String>, String, Option<u64>)> {
    if let Some(name) = args.keyset.as_deref() {
        let phrase = args
            .wallet_phrase
            .as_deref()
            .ok_or_else(|| anyhow!("--keyset requires --wallet-phrase"))?;
        let m = parse_mnemonic(phrase).map_err(|e| anyhow!("{e}"))?;
        let seed = derive_master_seed(&m, &args.wallet_passphrase);
        let db = KeysetDb::open(args.keysets_file.clone(), &seed)
            .map_err(|e| anyhow!("{e}"))?;
        let info = db
            .store()
            .get(name)
            .ok_or_else(|| anyhow!("unknown keyset '{name}' in {}", args.keysets_file.display()))?;
        Ok((info.validators.clone(), info.joint_pk_hex.clone(), Some(info.denom)))
    } else {
        let joint_pk = args
            .joint_pk
            .clone()
            .ok_or_else(|| anyhow!("either --keyset or --joint-pk is required"))?;
        if args.validators.is_empty() {
            return Err(anyhow!("--validator required at least once (or use --keyset)"));
        }
        Ok((args.validators.clone(), joint_pk, None))
    }
}

fn build_pool(urls: &[String]) -> Result<WalletClientPool> {
    let endpoints: Result<Vec<_>> = urls
        .iter()
        .enumerate()
        .map(|(i, url)| {
            let idx = u16::try_from(i + 1).context("too many validators")?;
            Ok(ValidatorEndpoint::plain(idx, url.clone())?)
        })
        .collect();
    Ok(WalletClientPool::new(endpoints?)?)
}

fn print_coin_json(coin: &Coin) {
    println!("{{");
    println!(
        "  \"coin_secret\": \"{}\",",
        hex::encode(coin.secret().to_bytes())
    );
    println!(
        "  \"coin_pubkey\": \"{}\",",
        hex::encode(coin.pubkey_bytes())
    );
    println!(
        "  \"coin_signature\": \"{}\"",
        hex::encode(coin.signature().to_bytes())
    );
    println!("}}");
}

#[allow(clippy::too_many_lines)]
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Mnemonic { action } => match action {
            MnemonicAction::Generate { words } => {
                let wc = match words {
                    12 => WordCount::Twelve,
                    24 => WordCount::TwentyFour,
                    other => return Err(anyhow!("--words must be 12 or 24, got {other}")),
                };
                let m = generate_mnemonic(wc).map_err(|e| anyhow!("{e}"))?;
                println!("{{");
                println!("  \"word_count\": {words},");
                println!("  \"phrase\": \"{m}\"");
                println!("}}");
            }
            MnemonicAction::Seed { phrase, passphrase } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                println!("{{");
                println!("  \"master_seed_hex\": \"{}\"", hex::encode(*seed));
                println!("}}");
            }
            MnemonicAction::Identity { phrase, passphrase } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                let (_sk, pk) = derive_receiving_keypair(&seed);
                println!("{{");
                println!("  \"identity_pubkey_hex\": \"{}\"", hex::encode(pk));
                println!("}}");
            }
        },
        Command::Wallet { action } => match action {
            WalletAction::Status {
                phrase,
                passphrase,
                file,
            } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                let w = WalletDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                let coins = &w.store().coins;
                let mut by_denom: std::collections::BTreeMap<u64, (u64, u64, u64)> =
                    std::collections::BTreeMap::new();
                for c in coins {
                    let entry = by_denom.entry(c.denom).or_insert((0, 0, 0));
                    match c.status {
                        CoinStatus::Active => entry.0 += 1,
                        CoinStatus::InFlight => entry.1 += 1,
                        CoinStatus::Spent => entry.2 += 1,
                    }
                }
                println!("{{");
                println!("  \"file\": \"{}\",", file.display());
                println!("  \"total_coins\": {},", coins.len());
                println!("  \"by_denom\": {{");
                let mut first = true;
                for (d, (a, i, s)) in &by_denom {
                    if !first {
                        println!(",");
                    }
                    first = false;
                    print!(
                        "    \"{d}\": {{ \"active\": {a}, \"in_flight\": {i}, \"spent\": {s} }}"
                    );
                }
                if !by_denom.is_empty() {
                    println!();
                }
                println!("  }}");
                println!("}}");
            }
            WalletAction::AddCoin {
                phrase,
                passphrase,
                file,
                coin_secret,
                coin_pubkey,
                coin_signature,
                denom,
                label,
            } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                let mut w = WalletDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;

                let secret_bytes = parse_hex32(&coin_secret, "coin-secret")?;
                let pubkey_bytes = parse_hex32(&coin_pubkey, "coin-pubkey")?;
                let sig_bytes = parse_hex64(&coin_signature, "coin-signature")?;
                let stored = StoredCoin {
                    secret_bytes,
                    pubkey_bytes,
                    signature_bytes: sig_bytes,
                    denom,
                    status: CoinStatus::Active,
                    label,
                };
                w.store_mut()
                    .add(stored)
                    .map_err(|e| anyhow!("add: {e:?}"))?;
                w.save(&seed).map_err(|e| anyhow!("{e}"))?;
                println!("{{ \"added\": true, \"file\": \"{}\" }}", file.display());
            }
            WalletAction::List {
                phrase,
                passphrase,
                file,
            } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                let w = WalletDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                println!("[");
                let coins = &w.store().coins;
                for (i, c) in coins.iter().enumerate() {
                    let comma = if i + 1 < coins.len() { "," } else { "" };
                    println!(
                        "  {{ \"pubkey\": \"{}\", \"denom\": {}, \"status\": \"{:?}\", \"label\": {} }}{}",
                        hex::encode(c.pubkey_bytes),
                        c.denom,
                        c.status,
                        c.label
                            .as_ref()
                            .map_or(String::from("null"), |l| format!("\"{l}\"")),
                        comma
                    );
                }
                println!("]");
            }
        },
        Command::Receive(args) => {
            // 1. Open the wallet.
            let m = parse_mnemonic(&args.wallet_phrase).map_err(|e| anyhow!("{e}"))?;
            let seed = derive_master_seed(&m, &args.wallet_passphrase);
            let mut w = WalletDb::open(args.wallet_file.clone(), &seed)
                .map_err(|e| anyhow!("{e}"))?;

            // 2. Poll the relay.
            let relay = args.relay.trim_end_matches('/').to_string();
            let url = format!("{relay}/inbox/{}", args.recipient_pubkey.trim());
            let client = reqwest::Client::new();
            let listed: serde_json::Value = client
                .get(&url)
                .send()
                .await
                .map_err(|e| anyhow!("relay GET: {e}"))?
                .json()
                .await
                .map_err(|e| anyhow!("relay JSON: {e}"))?;
            let messages = listed["messages"].as_array().cloned().unwrap_or_default();
            if messages.is_empty() {
                println!("{{ \"received\": 0 }}");
                return Ok(());
            }

            // 3. Decode each payload, add to wallet, optionally delete.
            let mut added = 0usize;
            let mut deleted = 0usize;
            let mut skipped = 0usize;
            for msg in &messages {
                let id = msg["id"].as_str().unwrap_or("");
                let payload_hex = msg["payload_hex"].as_str().unwrap_or("");
                let Ok(payload_bytes) = hex::decode(payload_hex) else {
                    skipped += 1;
                    continue;
                };
                // v5.6: try sealed_box::open first using mnemonic-derived
                // receiving secret; if it fails, fall back to plain JSON.
                let (recv_sk, _recv_pk) = derive_receiving_keypair(&seed);
                let decoded = sealed_box::open(&payload_bytes, &recv_sk)
                    .ok()
                    .unwrap_or_else(|| payload_bytes.clone());
                let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
                    skipped += 1;
                    continue;
                };
                let (Some(cs), Some(cp), Some(sig), Some(denom)) = (
                    json["coin_secret"].as_str(),
                    json["coin_pubkey"].as_str(),
                    json["coin_signature"].as_str(),
                    json["denom"].as_u64(),
                ) else {
                    skipped += 1;
                    continue;
                };
                let (Ok(secret_bytes), Ok(pubkey_bytes), Ok(sig_bytes)) = (
                    parse_hex32(cs, "coin_secret"),
                    parse_hex32(cp, "coin_pubkey"),
                    parse_hex64(sig, "coin_signature"),
                ) else {
                    skipped += 1;
                    continue;
                };

                let stored = tardus_client::coin_store::StoredCoin {
                    secret_bytes,
                    pubkey_bytes,
                    signature_bytes: sig_bytes,
                    denom,
                    status: tardus_client::coin_store::CoinStatus::Active,
                    label: Some(format!("{}-{id}", args.label_prefix)),
                };
                if w.store_mut().add(stored).is_ok() {
                    added += 1;
                    if !args.keep_on_relay {
                        let del_url = format!("{relay}/inbox/{}/{id}", args.recipient_pubkey.trim());
                        if client.delete(&del_url).send().await.is_ok() {
                            deleted += 1;
                        }
                    }
                } else {
                    skipped += 1;
                }
            }

            // 4. Persist the wallet.
            if added > 0 {
                w.save(&seed).map_err(|e| anyhow!("{e}"))?;
            }

            println!("{{");
            println!("  \"received\": {added},");
            println!("  \"deleted_from_relay\": {deleted},");
            println!("  \"skipped\": {skipped}");
            println!("}}");
        }
        Command::Pay(args) => {
            // 1. Parse invoice URI.
            let invoice = tardus_client::invoice::Invoice::parse(&args.invoice)
                .map_err(|e| anyhow!("invoice parse: {e}"))?;

            // 2. Resolve keyset → validators + joint_pk + denom.
            let m = parse_mnemonic(&args.wallet_phrase).map_err(|e| anyhow!("{e}"))?;
            let seed = derive_master_seed(&m, &args.wallet_passphrase);
            let ks_db = KeysetDb::open(args.keysets_file.clone(), &seed)
                .map_err(|e| anyhow!("{e}"))?;
            let info = ks_db
                .store()
                .get(&args.keyset)
                .ok_or_else(|| anyhow!("unknown keyset '{}'", args.keyset))?;
            if info.denom != invoice.denom {
                return Err(anyhow!(
                    "denom mismatch: keyset = {}, invoice = {}",
                    info.denom,
                    invoice.denom
                ));
            }
            let joint_pk_bytes = parse_hex32(&info.joint_pk_hex, "joint-pk")?;
            let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
                .map_err(|e| anyhow!("joint-pk: {e}"))?;

            // 3. Mint the coin via the validator pool.
            let pool = build_pool(&info.validators)?;
            let session_id = parse_session_id(None)?;
            let coin = issue_coin(&pool, &joint_pk, session_id)
                .await
                .map_err(|e| anyhow!("issue_coin: {e}"))?;

            // 4. Encode payload as JSON; optionally encrypt with v5.5
            //    sealed-box before hex-encoding for the relay.
            let payload_json = serde_json::json!({
                "coin_secret":    hex::encode(coin.secret().to_bytes()),
                "coin_pubkey":    hex::encode(coin.pubkey_bytes()),
                "coin_signature": hex::encode(coin.signature().to_bytes()),
                "denom":          invoice.denom,
                "memo":           invoice.memo.as_ref().and_then(|m| std::str::from_utf8(m).ok()),
            });
            let plaintext = serde_json::to_vec(&payload_json)?;
            let payload_hex = if args.encrypt {
                let sealed = sealed_box::seal(&plaintext, &invoice.recipient_pubkey)
                    .map_err(|e| anyhow!("sealed_box::seal: {e}"))?;
                hex::encode(sealed)
            } else {
                hex::encode(&plaintext)
            };

            // 5. POST to the chosen relay.
            let relay_url = args
                .relay
                .clone()
                .or_else(|| invoice.relays.first().cloned())
                .ok_or_else(|| anyhow!("no relay URL: --relay missing and invoice has none"))?;
            let recipient_hex = hex::encode(invoice.recipient_pubkey);
            let client = reqwest::Client::new();
            let deposit: serde_json::Value = client
                .post(format!("{}/inbox/{recipient_hex}", relay_url.trim_end_matches('/')))
                .json(&serde_json::json!({
                    "payload_hex": payload_hex,
                    "ttl_secs": args.ttl_secs,
                }))
                .send()
                .await
                .map_err(|e| anyhow!("relay POST: {e}"))?
                .json()
                .await
                .map_err(|e| anyhow!("relay JSON: {e}"))?;
            let msg_id = deposit["id"].as_str().unwrap_or("");
            let expires = deposit["expires_at_unix_ms"].as_u64().unwrap_or(0);

            // 6. Optional wallet audit trail: add the coin as Spent.
            if let Some(file) = args.wallet_file.as_ref() {
                let mut w = WalletDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                let stored = tardus_client::coin_store::StoredCoin {
                    secret_bytes: coin.secret().to_bytes(),
                    pubkey_bytes: coin.pubkey_bytes(),
                    signature_bytes: coin.signature().to_bytes(),
                    denom: invoice.denom,
                    status: tardus_client::coin_store::CoinStatus::Spent,
                    label: args.label.clone().or_else(|| {
                        Some(format!("pay-to-{}", &recipient_hex[..12]))
                    }),
                };
                w.store_mut().add(stored).map_err(|e| anyhow!("wallet add: {e:?}"))?;
                w.save(&seed).map_err(|e| anyhow!("{e}"))?;
            }

            println!("{{");
            println!("  \"paid\": true,");
            println!("  \"recipient\": \"{recipient_hex}\",");
            println!("  \"denom\": {},", invoice.denom);
            println!("  \"relay\": \"{relay_url}\",");
            println!("  \"message_id\": \"{msg_id}\",");
            println!("  \"expires_at_unix_ms\": {expires}");
            println!("}}");
        }
        Command::Invoice { action } => match action {
            InvoiceAction::Make {
                pubkey,
                denom,
                relay,
                memo,
            } => {
                let pk = parse_hex32(&pubkey, "pubkey")?;
                let inv = tardus_client::invoice::Invoice {
                    recipient_pubkey: pk,
                    denom,
                    relays: relay,
                    memo: memo.map(String::into_bytes),
                };
                println!("{}", inv.to_uri());
            }
            InvoiceAction::Parse { uri } => {
                let inv = tardus_client::invoice::Invoice::parse(&uri)
                    .map_err(|e| anyhow!("parse: {e}"))?;
                println!("{{");
                println!(
                    "  \"recipient_pubkey\": \"{}\",",
                    hex::encode(inv.recipient_pubkey)
                );
                println!("  \"denom\": {},", inv.denom);
                println!(
                    "  \"relays\": {},",
                    serde_json::to_string(&inv.relays).unwrap_or_default()
                );
                match &inv.memo {
                    Some(m) => match std::str::from_utf8(m) {
                        Ok(s) => println!("  \"memo\": {s:?}"),
                        Err(_) => println!("  \"memo_hex\": \"{}\"", hex::encode(m)),
                    },
                    None => println!("  \"memo\": null"),
                }
                println!("}}");
            }
        },
        Command::Keyset { action } => match action {
            KeysetAction::Add {
                phrase,
                passphrase,
                file,
                name,
                joint_pk,
                denom,
                validators,
                ca_cert_path,
                client_cert_path,
            } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                let mut db = KeysetDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                let info = KeysetInfo {
                    joint_pk_hex: joint_pk,
                    denom,
                    validators,
                    ca_cert_path,
                    client_cert_path,
                };
                db.store_mut().upsert(&name, info);
                db.save(&seed).map_err(|e| anyhow!("{e}"))?;
                println!(
                    "{{ \"added\": true, \"name\": \"{name}\", \"file\": \"{}\" }}",
                    file.display()
                );
            }
            KeysetAction::List {
                phrase,
                passphrase,
                file,
            } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                let db = KeysetDb::open(file, &seed).map_err(|e| anyhow!("{e}"))?;
                println!("[");
                let entries: Vec<_> = db.store().entries.iter().collect();
                for (i, (name, info)) in entries.iter().enumerate() {
                    let comma = if i + 1 < entries.len() { "," } else { "" };
                    println!(
                        "  {{ \"name\": \"{name}\", \"denom\": {}, \"joint_pk_hex\": \"{}\", \"validators\": {} }}{comma}",
                        info.denom,
                        info.joint_pk_hex,
                        serde_json::to_string(&info.validators).unwrap_or_default()
                    );
                }
                println!("]");
            }
            KeysetAction::Remove {
                phrase,
                passphrase,
                file,
                name,
            } => {
                let m = parse_mnemonic(&phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &passphrase);
                let mut db = KeysetDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                let removed = db.store_mut().remove(&name).is_some();
                db.save(&seed).map_err(|e| anyhow!("{e}"))?;
                println!(
                    "{{ \"removed\": {removed}, \"name\": \"{name}\", \"file\": \"{}\" }}",
                    file.display()
                );
            }
        },
        Command::Issue(args) => {
            // Resolve validators + joint_pk + denom either from
            // explicit flags or from a named keyset.
            let (validators, joint_pk_hex, default_denom) =
                resolve_issue_inputs(&args)?;
            let joint_pk_bytes = parse_hex32(&joint_pk_hex, "joint-pk")?;
            let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
                .map_err(|e| anyhow!("joint-pk: {e}"))?;
            let session_id = parse_session_id(args.session_id.as_deref())?;
            let pool = build_pool(&validators)?;
            let coin = issue_coin(&pool, &joint_pk, session_id)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            print_coin_json(&coin);

            // Optional auto-save into the wallet file.
            if let Some(file) = args.wallet_file.as_ref() {
                let phrase = args.wallet_phrase.as_deref().ok_or_else(|| {
                    anyhow!("--wallet-file requires --wallet-phrase")
                })?;
                // Prefer explicit --denom; fall back to keyset's denom.
                let denom = args.denom.or(default_denom).ok_or_else(|| {
                    anyhow!("--wallet-file requires --denom (or --keyset)")
                })?;
                let m = parse_mnemonic(phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &args.wallet_passphrase);
                let mut w = WalletDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                let stored = StoredCoin {
                    secret_bytes: coin.secret().to_bytes(),
                    pubkey_bytes: coin.pubkey_bytes(),
                    signature_bytes: coin.signature().to_bytes(),
                    denom,
                    status: CoinStatus::Active,
                    label: args.label,
                };
                w.store_mut()
                    .add(stored)
                    .map_err(|e| anyhow!("wallet add: {e:?}"))?;
                w.save(&seed).map_err(|e| anyhow!("{e}"))?;
                eprintln!("[wallet] saved to {}", file.display());
            }
        }
        Command::Refresh(args) => {
            let (validators, joint_pk_hex, _denom) = resolve_refresh_inputs(&args)?;
            let joint_pk_bytes = parse_hex32(&joint_pk_hex, "joint-pk")?;
            let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
                .map_err(|e| anyhow!("joint-pk: {e}"))?;

            // Two input modes:
            //   A) explicit hex via --coin-{secret,pubkey,signature}
            //   B) wallet lookup via --wallet-file + --wallet-phrase + --coin-label
            let secret_bytes: [u8; 32];
            let pubkey: [u8; 32];
            let sig_bytes: [u8; 64];
            let mut from_wallet_label: Option<String> = None;
            if let Some(label) = args.coin_label.as_deref() {
                let file = args.wallet_file.as_ref().ok_or_else(|| {
                    anyhow!("--coin-label requires --wallet-file")
                })?;
                let phrase = args.wallet_phrase.as_deref().ok_or_else(|| {
                    anyhow!("--coin-label requires --wallet-phrase")
                })?;
                let m = parse_mnemonic(phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &args.wallet_passphrase);
                let w = WalletDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                let found = w
                    .store()
                    .coins
                    .iter()
                    .find(|c| {
                        c.label.as_deref() == Some(label) && c.status == CoinStatus::Active
                    })
                    .cloned()
                    .ok_or_else(|| anyhow!("no Active coin with label '{label}'"))?;
                secret_bytes = found.secret_bytes;
                pubkey = found.pubkey_bytes;
                sig_bytes = found.signature_bytes;
                from_wallet_label = Some(label.to_string());
            } else {
                let cs = args
                    .coin_secret
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing --coin-secret (or use --coin-label)"))?;
                let cp = args
                    .coin_pubkey
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing --coin-pubkey"))?;
                let csig = args
                    .coin_signature
                    .as_deref()
                    .ok_or_else(|| anyhow!("missing --coin-signature"))?;
                secret_bytes = parse_hex32(cs, "coin-secret")?;
                pubkey = parse_hex32(cp, "coin-pubkey")?;
                sig_bytes = parse_hex64(csig, "coin-signature")?;
            }

            let coin_secret = SecretKey::from_bytes(&secret_bytes)
                .map_err(|e| anyhow!("coin-secret: {e}"))?;
            let coin_pubkey = pubkey;
            let coin_sig = Signature::from_bytes(&sig_bytes);
            let melted = Coin::new(coin_secret, coin_pubkey, coin_sig)
                .map_err(|e| anyhow!("coin reconstruction: {e:?}"))?;
            let session_id = parse_session_id(args.session_id.as_deref())?;
            let pool = build_pool(&validators)?;
            let new_coin = refresh_coin(&pool, &melted, &joint_pk, session_id)
                .await
                .map_err(|e| anyhow!("{e}"))?;
            print_coin_json(&new_coin);

            // If we loaded the old coin from a wallet, mark it Spent
            // and add the new one with the same label.
            if let (Some(file), Some(label)) =
                (args.wallet_file.as_ref(), from_wallet_label)
            {
                let phrase = args.wallet_phrase.as_deref().unwrap();
                let m = parse_mnemonic(phrase).map_err(|e| anyhow!("{e}"))?;
                let seed = derive_master_seed(&m, &args.wallet_passphrase);
                let mut w = WalletDb::open(file.clone(), &seed).map_err(|e| anyhow!("{e}"))?;
                let old_nullifier =
                    tardus_client::coin_store::StoredCoin {
                        secret_bytes: melted.secret().to_bytes(),
                        pubkey_bytes: melted.pubkey_bytes(),
                        signature_bytes: melted.signature().to_bytes(),
                        denom: 0,
                        status: CoinStatus::Active,
                        label: None,
                    }
                    .nullifier();
                w.store_mut()
                    .mark_spent(&old_nullifier)
                    .map_err(|e| anyhow!("mark_spent: {e:?}"))?;
                // Look up old denom from the original entry (already removed
                // from the loaded copy; we need it from disk again).
                let denom = w
                    .store()
                    .coins
                    .iter()
                    .find(|c| c.label.as_deref() == Some(&label))
                    .map_or(0, |c| c.denom);
                let new_stored = StoredCoin {
                    secret_bytes: new_coin.secret().to_bytes(),
                    pubkey_bytes: new_coin.pubkey_bytes(),
                    signature_bytes: new_coin.signature().to_bytes(),
                    denom,
                    status: CoinStatus::Active,
                    label: Some(label.clone()),
                };
                w.store_mut()
                    .add(new_stored)
                    .map_err(|e| anyhow!("wallet add new: {e:?}"))?;
                w.save(&seed).map_err(|e| anyhow!("{e}"))?;
                eprintln!("[wallet] marked old coin spent, added new with label '{label}'");
            }
        }
    }
    Ok(())
}
