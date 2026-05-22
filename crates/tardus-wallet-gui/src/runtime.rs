//! tokio runtime + UI ↔ runtime channel plumbing (Faz 8.1).
//!
//! The eframe app loop is single-threaded and frame-driven; calling
//! `tardus_wallet::issue_coin().await` from inside `App::update`
//! would block every frame on validator HTTP. Instead we spawn a
//! dedicated tokio runtime in a background thread at app boot and
//! exchange messages over `std::sync::mpsc` channels:
//!
//! ```text
//!   UI thread                      tokio runtime thread
//!   ─────────                      ────────────────────
//!   App::update() ──────────────┐
//!     • read mpsc<UiEvent>      │
//!     • render frame            │
//!     • enqueue mpsc<UiCommand> │
//!                               │ (cmd_tx → cmd_rx)
//!                               ▼
//!                          dispatch ─→ async fn
//!                               │       • issue_coin
//!                               │       • refresh_coin
//!                               │       • sealed_box::seal
//!                               │       • reqwest POST/GET
//!                               ▼
//!                          (event_tx → event_rx) ─┐
//!                                                 │
//!   App::update() (next frame) ←──────────────────┘
//!     • try_recv UiEvent
//!     • update App.last_status / last_error
//!     • request_repaint_after(100ms)
//! ```
//!
//! Why `std::sync::mpsc` and not `tokio::sync::mpsc`: the UI side is
//! not async. We use the std channel for both directions so neither
//! side has to ".await" — the UI polls non-blocking with `try_recv`,
//! the runtime side blocks via `recv()` on a tokio-spawned blocking
//! task.
//!
//! Doc terms: `try_recv`, `recv()`.

// Several enum variants + struct fields are wired here as
// scaffolding for Faz 8.2+ (KeysetList, Pay, Receive, Refresh tabs);
// they are constructed by upcoming sub-fazes, not v8.1.
#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;
use tokio::runtime::Builder;
use zeroize::Zeroizing;

/// Commands the UI thread sends to the runtime.
///
/// Variants are kept small (`String`s / `PathBuf`s / `Vec<u8>`) so that
/// sensitive material (`master_seed`, mnemonic) is moved (not
/// borrowed) and dropped in the runtime after use.
#[derive(Debug)]
pub enum UiCommand {
    /// Roundtrip smoke test — verifies the channel pair works.
    Ping {
        nonce: String,
    },

    /// Open a wallet: derive recv-identity, load coin store + keyset
    /// store (best-effort), emit [`UiEvent::WalletOpened`].
    OpenWallet {
        phrase: String,
        passphrase: String,
        wallet_file: Option<PathBuf>,
        keysets_file: Option<PathBuf>,
    },

    /// Re-emit [`UiEvent::KeysetList`] from the on-disk keysets file
    /// using the cached master seed. Used after add / remove to
    /// refresh the UI list.
    KeysetList {
        master_seed: Zeroizing<[u8; 32]>,
        keysets_file: PathBuf,
    },

    /// Add a keyset entry to the on-disk keysets file. Emits
    /// [`UiEvent::KeysetAdded`] on success then re-emits
    /// [`UiEvent::KeysetList`].
    KeysetAdd {
        master_seed: Zeroizing<[u8; 32]>,
        keysets_file: PathBuf,
        name: String,
        joint_pk_hex: String,
        denom: u64,
        validators: Vec<String>,
        ca_cert_path: Option<String>,
        client_cert_path: Option<String>,
    },

    /// Remove a keyset entry by name. Emits [`UiEvent::KeysetRemoved`]
    /// on success then re-emits [`UiEvent::KeysetList`].
    KeysetRemove {
        master_seed: Zeroizing<[u8; 32]>,
        keysets_file: PathBuf,
        name: String,
    },

    /// **Faz 9.6** — Submit a devnet Withdraw TX directly from
    /// the GUI runtime. Looks up the coin by `coin_label`, builds
    /// the ed25519 precompile + `tardus::Withdraw` instructions,
    /// signs with the `solana_keypair_path` keypair, submits via
    /// `solana-client`. The recipient receives `denom` lamports.
    WithdrawOnDevnet {
        master_seed: Zeroizing<[u8; 32]>,
        wallet_file: PathBuf,
        coin_label: String,
        recipient_b58: String,
        rpc_url: String,
        program_id_b58: String,
        solana_keypair_path: String,
        /// **v2.13.2** — Generate a fresh ephemeral keypair to
        /// sign the Withdraw TX (privacy hardening Layer 1 from
        /// Faz 9.1). The `solana_keypair_path` wallet then only
        /// funds the ephemeral (transfer OR on-chain pool payout
        /// based on `use_onchain_pool`), not the Withdraw TX
        /// itself.
        use_ephemeral_payer: bool,
        /// **v2.13.2** — When `use_ephemeral_payer = true`, route
        /// the funding via the on-chain `SponsorPool` PDA
        /// (commingled, multi-depositor source) instead of a
        /// direct sponsor → ephemeral transfer (Faz 9.4).
        use_onchain_pool: bool,
    },

    /// Refresh an Active coin via κ-fold cut-and-choose. Looks up
    /// the coin by `coin_label`, drives `refresh_coin` against the
    /// named keyset's validator pool, then atomically updates the
    /// wallet (old → Spent, new → Active with carry-forward label).
    Refresh {
        master_seed: Zeroizing<[u8; 32]>,
        wallet_file: PathBuf,
        keysets_file: PathBuf,
        keyset_name: String,
        coin_label: String,
    },

    /// Receive coins from a relay inbox: poll `/inbox/{recipient}`,
    /// decode payloads (sealed-box `open` first with `recv_sk` derived
    /// from `master_seed`, fall back to plain JSON for v5.3
    /// senders), add Active coins into the wallet at `wallet_file`,
    /// then DELETE each consumed message from the relay (unless
    /// `keep_on_relay`).
    Receive {
        master_seed: Zeroizing<[u8; 32]>,
        wallet_file: PathBuf,
        recipient_pk_hex: String,
        relay_url: String,
        keep_on_relay: bool,
        label_prefix: String,
    },

    /// Pay an invoice URI using the named keyset.
    ///
    /// Steps the runtime performs (all async, single command):
    ///   1. parse `invoice_uri` (`tardus://...`)
    ///   2. open `keysets_file` with `master_seed`, look up `keyset_name`
    ///   3. validate `keyset.denom == invoice.denom`
    ///   4. build [`tardus_wallet::WalletClientPool`] from the keyset validators
    ///   5. [`tardus_wallet::issue_coin`] (3-round threshold blind sign)
    ///   6. JSON-encode coin material; if `encrypt`, [`tardus_wallet::sealed_box::seal`]
    ///   7. POST to relay `/inbox/{recipient_pk}`
    ///   8. emit [`UiEvent::PaymentSent`]
    Pay {
        master_seed: Zeroizing<[u8; 32]>,
        keysets_file: PathBuf,
        invoice_uri: String,
        keyset_name: String,
        encrypt: bool,
    },

    Shutdown,
}

/// Events the runtime sends back to the UI.
#[derive(Debug)]
pub enum UiEvent {
    Pong {
        nonce: String,
        round_trip: std::time::Duration,
    },

    WalletOpened {
        recv_pubkey_hex: String,
        master_seed: Zeroizing<[u8; 32]>,
        coin_summary: Vec<DenomBucket>,
        coin_total: usize,
        keyset_summary: Vec<KeysetSummary>,
        active_coins: Vec<ActiveCoinSummary>,
    },

    Error {
        op: String,
        message: String,
    },

    /// Result of [`UiCommand::KeysetList`] or a refresh after
    /// [`UiCommand::KeysetAdd`] / [`UiCommand::KeysetRemove`].
    KeysetList(Vec<KeysetSummary>),

    /// Successful add (kept distinct from `KeysetList` so the UI
    /// can show a "added X" toast without re-deriving from list).
    KeysetAdded {
        name: String,
    },

    /// Successful remove.
    KeysetRemoved {
        name: String,
    },

    /// Result of `UiCommand::Receive`. Populates the Receive tab's
    /// results panel.
    ReceiveResult {
        received: usize,
        deleted_from_relay: usize,
        skipped: usize,
        elapsed_ms: u128,
    },

    /// Result of `UiCommand::WithdrawOnDevnet` — Bob got real SOL.
    WithdrawOnDevnetResult {
        coin_label: String,
        denom: u64,
        recipient_b58: String,
        tx_signature: String,
        explorer_url: String,
        elapsed_ms: u128,
        /// **v2.13.2** — Which payer strategy was used (sponsor /
        /// ephemeral / ephemeral-from-pool), so the UI shows the
        /// privacy class in the result panel.
        payer_strategy: String,
        /// Optional: ephemeral signer pubkey (b58) if one was
        /// generated, so the UI can show the fresh signer is
        /// distinct from the funding wallet.
        ephemeral_payer_b58: Option<String>,
    },

    /// Result of `UiCommand::Refresh`. Carries the unlinkability
    /// evidence (old vs new pubkey prefixes) and the updated
    /// wallet snapshot so the Balance tab refreshes without a
    /// manual reload.
    CoinRefreshed {
        old_label: Option<String>,
        new_label: String,
        denom: u64,
        old_pubkey_prefix_hex: String,
        new_pubkey_prefix_hex: String,
        elapsed_ms: u128,
        coin_summary: Vec<DenomBucket>,
        coin_total: usize,
        active_coins: Vec<ActiveCoinSummary>,
    },

    /// Successful pay roundtrip. Returned to populate the Pay tab's
    /// receipt panel.
    PaymentSent {
        recipient_prefix_hex: String,
        denom: u64,
        relay_url: String,
        message_id: String,
        encrypted: bool,
        elapsed_ms: u128,
    },
}

#[derive(Debug, Clone)]
pub struct DenomBucket {
    pub denom: u64,
    pub active: usize,
    pub in_flight: usize,
    pub spent: usize,
}

/// Single active coin row (label + denom + pubkey prefix) used by
/// the Refresh tab's coin picker and the Balance tab's per-coin
/// listing.
#[derive(Debug, Clone)]
pub struct ActiveCoinSummary {
    pub label: String,
    pub denom: u64,
    pub pubkey_prefix_hex: String,
}

#[derive(Debug, Clone)]
pub struct KeysetSummary {
    pub name: String,
    pub denom: u64,
    pub joint_pk_hex: String,
    pub validators: Vec<String>,
}

/// Handle the UI keeps. Sends commands; non-blocking receives events.
pub struct RuntimeHandle {
    cmd_tx: Sender<UiCommand>,
    event_rx: Receiver<UiEvent>,
    _thread: std::thread::JoinHandle<()>,
}

impl RuntimeHandle {
    /// Best-effort enqueue. Dropped if the runtime thread is gone
    /// (which only happens on Shutdown).
    pub fn send(&self, cmd: UiCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Drain all events emitted since the last frame. Caller owns
    /// the dispatch.
    pub fn drain_events(&self, sink: &mut Vec<UiEvent>) {
        while let Ok(ev) = self.event_rx.try_recv() {
            sink.push(ev);
        }
    }
}

/// Spawn the dedicated runtime thread + tokio Runtime on it.
///
/// # Panics
/// Panics only on Tokio runtime build failure (impossible on a
/// healthy host process).
#[must_use]
pub fn spawn_runtime() -> RuntimeHandle {
    let (cmd_tx, cmd_rx) = channel::<UiCommand>();
    let (event_tx, event_rx) = channel::<UiEvent>();

    let thread = std::thread::Builder::new()
        .name("tardus-wallet-gui-runtime".into())
        .spawn(move || {
            let rt = Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("tardus-wallet-gui-tokio")
                .build()
                .expect("tokio runtime build");
            rt.block_on(async move {
                runtime_loop(cmd_rx, event_tx).await;
            });
        })
        .expect("runtime thread spawn");

    RuntimeHandle {
        cmd_tx,
        event_rx,
        _thread: thread,
    }
}

/// Bridge `std::mpsc::Receiver<UiCommand>` into a tokio
/// `unbounded_channel` (a single long-lived `spawn_blocking` owns the
/// std receiver), then dispatch each command on its own tokio task
/// so a slow validator HTTP call never blocks subsequent UI commands.
async fn runtime_loop(cmd_rx: Receiver<UiCommand>, event_tx: Sender<UiEvent>) {
    // Bridge std::mpsc::Receiver into a tokio channel via a
    // single long-lived blocking task.
    let (tx_async, mut rx_async) = tokio::sync::mpsc::unbounded_channel::<UiCommand>();
    let bridge = tokio::task::spawn_blocking(move || {
        while let Ok(cmd) = cmd_rx.recv() {
            if tx_async.send(cmd).is_err() {
                break;
            }
        }
    });

    while let Some(cmd) = rx_async.recv().await {
        let event_tx = event_tx.clone();
        // Dispatch each command in its own task so a slow HTTP call
        // doesn't block subsequent UI commands.
        tokio::spawn(async move {
            dispatch(cmd, event_tx).await;
        });
    }
    let _ = bridge.await;
}

#[allow(clippy::too_many_lines)]
async fn dispatch(cmd: UiCommand, event_tx: Sender<UiEvent>) {
    match cmd {
        UiCommand::Ping { nonce } => {
            let started = Instant::now();
            let _ = event_tx.send(UiEvent::Pong {
                nonce,
                round_trip: started.elapsed(),
            });
        }
        UiCommand::OpenWallet {
            phrase,
            passphrase,
            wallet_file,
            keysets_file,
        } => match open_wallet(&phrase, &passphrase, wallet_file, keysets_file).await {
            Ok(ev) => {
                let _ = event_tx.send(ev);
            }
            Err(e) => {
                let _ = event_tx.send(UiEvent::Error {
                    op: "open_wallet".into(),
                    message: redact(&e.to_string()),
                });
            }
        },
        UiCommand::KeysetList {
            master_seed,
            keysets_file,
        } => match list_keysets(&master_seed, &keysets_file) {
            Ok(list) => {
                let _ = event_tx.send(UiEvent::KeysetList(list));
            }
            Err(e) => {
                let _ = event_tx.send(UiEvent::Error {
                    op: "keyset_list".into(),
                    message: redact(&e.to_string()),
                });
            }
        },
        UiCommand::KeysetAdd {
            master_seed,
            keysets_file,
            name,
            joint_pk_hex,
            denom,
            validators,
            ca_cert_path,
            client_cert_path,
        } => {
            let name_clone = name.clone();
            let kf = keysets_file.clone();
            match add_keyset(
                &master_seed,
                &keysets_file,
                name,
                joint_pk_hex,
                denom,
                validators,
                ca_cert_path,
                client_cert_path,
            ) {
                Ok(()) => {
                    let _ = event_tx.send(UiEvent::KeysetAdded { name: name_clone });
                    match list_keysets(&master_seed, &kf) {
                        Ok(list) => {
                            let _ = event_tx.send(UiEvent::KeysetList(list));
                        }
                        Err(e) => {
                            let _ = event_tx.send(UiEvent::Error {
                                op: "keyset_list_after_add".into(),
                                message: redact(&e.to_string()),
                            });
                        }
                    }
                }
                Err(e) => {
                    let _ = event_tx.send(UiEvent::Error {
                        op: "keyset_add".into(),
                        message: redact(&e.to_string()),
                    });
                }
            }
        }
        UiCommand::KeysetRemove {
            master_seed,
            keysets_file,
            name,
        } => {
            let kf = keysets_file.clone();
            let name_clone = name.clone();
            match remove_keyset(&master_seed, &keysets_file, &name) {
                Ok(true) => {
                    let _ = event_tx.send(UiEvent::KeysetRemoved { name: name_clone });
                    if let Ok(list) = list_keysets(&master_seed, &kf) {
                        let _ = event_tx.send(UiEvent::KeysetList(list));
                    }
                }
                Ok(false) => {
                    let _ = event_tx.send(UiEvent::Error {
                        op: "keyset_remove".into(),
                        message: format!("no keyset named {name_clone:?}"),
                    });
                }
                Err(e) => {
                    let _ = event_tx.send(UiEvent::Error {
                        op: "keyset_remove".into(),
                        message: redact(&e.to_string()),
                    });
                }
            }
        }
        UiCommand::WithdrawOnDevnet {
            master_seed,
            wallet_file,
            coin_label,
            recipient_b58,
            rpc_url,
            program_id_b58,
            solana_keypair_path,
            use_ephemeral_payer,
            use_onchain_pool,
        } => match withdraw_on_devnet(
            &master_seed,
            &wallet_file,
            &coin_label,
            &recipient_b58,
            &rpc_url,
            &program_id_b58,
            &solana_keypair_path,
            use_ephemeral_payer,
            use_onchain_pool,
        )
        .await
        {
            Ok(ev) => {
                let _ = event_tx.send(ev);
            }
            Err(e) => {
                let _ = event_tx.send(UiEvent::Error {
                    op: "withdraw_on_devnet".into(),
                    message: redact(&e.to_string()),
                });
            }
        },
        UiCommand::Refresh {
            master_seed,
            wallet_file,
            keysets_file,
            keyset_name,
            coin_label,
        } => match refresh(
            &master_seed,
            &wallet_file,
            &keysets_file,
            &keyset_name,
            &coin_label,
        )
        .await
        {
            Ok(ev) => {
                let _ = event_tx.send(ev);
            }
            Err(e) => {
                let _ = event_tx.send(UiEvent::Error {
                    op: "refresh".into(),
                    message: redact(&e.to_string()),
                });
            }
        },
        UiCommand::Receive {
            master_seed,
            wallet_file,
            recipient_pk_hex,
            relay_url,
            keep_on_relay,
            label_prefix,
        } => match receive(
            &master_seed,
            &wallet_file,
            &recipient_pk_hex,
            &relay_url,
            keep_on_relay,
            &label_prefix,
        )
        .await
        {
            Ok(ev) => {
                let _ = event_tx.send(ev);
            }
            Err(e) => {
                let _ = event_tx.send(UiEvent::Error {
                    op: "receive".into(),
                    message: redact(&e.to_string()),
                });
            }
        },
        UiCommand::Pay {
            master_seed,
            keysets_file,
            invoice_uri,
            keyset_name,
            encrypt,
        } => match pay(
            &master_seed,
            &keysets_file,
            &invoice_uri,
            &keyset_name,
            encrypt,
        )
        .await
        {
            Ok(ev) => {
                let _ = event_tx.send(ev);
            }
            Err(e) => {
                let _ = event_tx.send(UiEvent::Error {
                    op: "pay".into(),
                    message: redact(&e.to_string()),
                });
            }
        },
        UiCommand::Shutdown => {
            // Runtime exit handled by closing the channel; this is a
            // no-op marker for symmetry.
        }
    }
}

// Currently sync (BIP-39 PBKDF2 + AEAD seal are CPU work, no I/O);
// kept `async` so Faz 8.X can add async HTTP probes (e.g. validator
// reachability check at open time) without API churn.
#[allow(clippy::unused_async)]
async fn open_wallet(
    phrase: &str,
    passphrase: &str,
    wallet_file: Option<PathBuf>,
    _keysets_file: Option<PathBuf>,
) -> anyhow::Result<UiEvent> {
    use tardus_wallet::{
        derive_master_seed, derive_receiving_keypair, parse_mnemonic, WalletDb,
    };

    let m = parse_mnemonic(phrase).map_err(|e| anyhow::anyhow!("mnemonic: {e}"))?;
    let seed = derive_master_seed(&m, passphrase);
    let master_seed: Zeroizing<[u8; 32]> = Zeroizing::new(*seed);

    let (_recv_sk, recv_pk) = derive_receiving_keypair(&master_seed);
    let recv_pubkey_hex = hex::encode(recv_pk);

    let (coin_summary, coin_total, active_coins) = if let Some(ref file) = wallet_file {
        let db = WalletDb::open(file.clone(), &master_seed)
            .map_err(|e| anyhow::anyhow!("wallet open: {e:?}"))?;
        summarize_store(db.store())
    } else {
        (Vec::new(), 0, Vec::new())
    };

    // Keyset list is best-effort; we defer the actual file read to
    // the dedicated KeysetList command so the OpenWallet path stays
    // fast.
    Ok(UiEvent::WalletOpened {
        recv_pubkey_hex,
        master_seed,
        coin_summary,
        coin_total,
        keyset_summary: Vec::new(),
        active_coins,
    })
}

/// Summarize a `CoinStore` for the GUI: denom buckets + total + the
/// Active-coin picker rows (label + denom + pubkey prefix).
fn summarize_store(
    store: &tardus_client::coin_store::CoinStore,
) -> (Vec<DenomBucket>, usize, Vec<ActiveCoinSummary>) {
    use tardus_client::coin_store::CoinStatus;
    let coins = &store.coins;
    let total = coins.len();
    let mut buckets: std::collections::BTreeMap<u64, DenomBucket> =
        std::collections::BTreeMap::new();
    let mut active: Vec<ActiveCoinSummary> = Vec::new();
    for c in coins {
        let entry = buckets.entry(c.denom).or_insert(DenomBucket {
            denom: c.denom,
            active: 0,
            in_flight: 0,
            spent: 0,
        });
        match c.status {
            CoinStatus::Active => {
                entry.active += 1;
                let pubkey_hex = hex::encode(c.pubkey_bytes);
                let label = c.label.clone().unwrap_or_else(|| {
                    format!("unlabeled-{}", &pubkey_hex[..8.min(pubkey_hex.len())])
                });
                active.push(ActiveCoinSummary {
                    label,
                    denom: c.denom,
                    pubkey_prefix_hex: pubkey_hex[..16.min(pubkey_hex.len())].to_string(),
                });
            }
            CoinStatus::InFlight => entry.in_flight += 1,
            CoinStatus::Spent => entry.spent += 1,
        }
    }
    (buckets.into_values().collect(), total, active)
}

#[allow(clippy::unnecessary_wraps)]
fn list_keysets(
    master_seed: &Zeroizing<[u8; 32]>,
    keysets_file: &std::path::Path,
) -> anyhow::Result<Vec<KeysetSummary>> {
    use tardus_wallet::KeysetDb;
    if !keysets_file.exists() {
        return Ok(Vec::new());
    }
    let db = KeysetDb::open(keysets_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("keyset open: {e:?}"))?;
    Ok(db
        .store()
        .entries
        .iter()
        .map(|(name, info)| KeysetSummary {
            name: name.clone(),
            denom: info.denom,
            joint_pk_hex: info.joint_pk_hex.clone(),
            validators: info.validators.clone(),
        })
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn add_keyset(
    master_seed: &Zeroizing<[u8; 32]>,
    keysets_file: &std::path::Path,
    name: String,
    joint_pk_hex: String,
    denom: u64,
    validators: Vec<String>,
    ca_cert_path: Option<String>,
    client_cert_path: Option<String>,
) -> anyhow::Result<()> {
    use tardus_wallet::{KeysetDb, KeysetInfo};

    if name.trim().is_empty() {
        anyhow::bail!("keyset name must not be empty");
    }
    if joint_pk_hex.len() != 64 || hex::decode(&joint_pk_hex).is_err() {
        anyhow::bail!("joint_pk_hex must be 64 hex chars");
    }
    if validators.is_empty() {
        anyhow::bail!("at least one validator URL is required");
    }

    let mut db = KeysetDb::open(keysets_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("keyset open: {e:?}"))?;
    let info = KeysetInfo {
        joint_pk_hex,
        denom,
        validators,
        ca_cert_path,
        client_cert_path,
    };
    db.store_mut().upsert(name, info);
    db.save(master_seed)
        .map_err(|e| anyhow::anyhow!("keyset save: {e:?}"))?;
    Ok(())
}

/// **Faz 9.6** — Build + submit a devnet Withdraw TX directly,
/// no shell-out to CLI. The user's Solana keypair (default
/// `~/.config/solana/id.json`) signs the TX and pays its fee.
/// The TARDUS coin's `denom` lamports are released from the
/// vault PDA to `recipient_b58`.
#[allow(clippy::too_many_lines, clippy::too_many_arguments, deprecated)]
async fn withdraw_on_devnet(
    master_seed: &Zeroizing<[u8; 32]>,
    wallet_file: &std::path::Path,
    coin_label: &str,
    recipient_b58: &str,
    rpc_url: &str,
    program_id_b58: &str,
    solana_keypair_path: &str,
    use_ephemeral_payer: bool,
    use_onchain_pool: bool,
) -> anyhow::Result<UiEvent> {
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_sdk::{
        commitment_config::CommitmentConfig,
        ed25519_program,
        instruction::{AccountMeta, Instruction as SolInstruction},
        pubkey::Pubkey,
        signature::{read_keypair_file, Keypair, Signer},
        system_instruction, system_program, sysvar,
        transaction::Transaction,
    };
    use std::str::FromStr;
    use tardus_client::coin_store::{CoinStatus, StoredCoin};
    use tardus_program::{
        instruction::Instruction as TInstruction,
        processor::compute_nullifier,
    };
    use tardus_wallet::WalletDb;

    const EPHEMERAL_PAYER_LAMPORTS: u64 = 1_000_000;

    let started = std::time::Instant::now();
    let wallet = WalletDb::open(wallet_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("wallet open: {e:?}"))?;
    let found: StoredCoin = wallet
        .store()
        .coins
        .iter()
        .find(|c| c.label.as_deref() == Some(coin_label) && c.status == CoinStatus::Active)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no Active coin with label {coin_label:?}"))?;

    let rpc = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
    let program_id = Pubkey::from_str(program_id_b58)
        .map_err(|e| anyhow::anyhow!("program-id: {e}"))?;
    let recipient = Pubkey::from_str(recipient_b58)
        .map_err(|e| anyhow::anyhow!("recipient: {e}"))?;
    let sponsor = read_keypair_file(solana_keypair_path)
        .map_err(|e| anyhow::anyhow!("read keypair {solana_keypair_path}: {e}"))?;

    // **v2.13.2** — payer strategy: sponsor / ephemeral / ephemeral-from-pool.
    let (payer, payer_strategy, ephemeral_payer_b58) = if use_ephemeral_payer {
        let ephemeral = Keypair::new();
        let eph_pubkey = ephemeral.pubkey();
        let eph_b58 = eph_pubkey.to_string();
        if use_onchain_pool {
            // SponsorPayout(1M lamports → ephemeral) from on-chain pool;
            // sponsor wallet pays only the tiny SponsorPayout TX fee.
            let (pool_pda, _) = Pubkey::find_program_address(
                &[b"tardus", b"sponsor-pool"],
                &Pubkey::from_str(program_id_b58)
                    .map_err(|e| anyhow::anyhow!("program-id: {e}"))?,
            );
            let pay_ix = SolInstruction {
                program_id: Pubkey::from_str(program_id_b58)
                    .map_err(|e| anyhow::anyhow!("program-id: {e}"))?,
                accounts: vec![
                    AccountMeta::new(sponsor.pubkey(), true),
                    AccountMeta::new(pool_pda, false),
                    AccountMeta::new(eph_pubkey, false),
                    AccountMeta::new_readonly(system_program::id(), false),
                ],
                data: borsh::to_vec(&TInstruction::SponsorPayout {
                    lamports: EPHEMERAL_PAYER_LAMPORTS,
                    recipient: eph_pubkey.to_bytes(),
                })
                .map_err(|e| anyhow::anyhow!("borsh: {e}"))?,
            };
            let rpc_fund = RpcClient::new_with_commitment(
                rpc_url.to_string(),
                CommitmentConfig::confirmed(),
            );
            let bh = rpc_fund.get_latest_blockhash().await
                .map_err(|e| anyhow::anyhow!("blockhash (pool payout): {e}"))?;
            let tx = Transaction::new_signed_with_payer(
                &[pay_ix],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                bh,
            );
            rpc_fund.send_and_confirm_transaction(&tx).await
                .map_err(|e| anyhow::anyhow!("sponsor-pool payout: {e}"))?;
            (ephemeral, "ephemeral-from-pool".to_string(), Some(eph_b58))
        } else {
            // Direct sponsor → ephemeral funding transfer.
            let fund_ix = system_instruction::transfer(
                &sponsor.pubkey(),
                &eph_pubkey,
                EPHEMERAL_PAYER_LAMPORTS,
            );
            let rpc_fund = RpcClient::new_with_commitment(
                rpc_url.to_string(),
                CommitmentConfig::confirmed(),
            );
            let bh = rpc_fund.get_latest_blockhash().await
                .map_err(|e| anyhow::anyhow!("blockhash (sponsor fund): {e}"))?;
            let tx = Transaction::new_signed_with_payer(
                &[fund_ix],
                Some(&sponsor.pubkey()),
                &[&sponsor],
                bh,
            );
            rpc_fund.send_and_confirm_transaction(&tx).await
                .map_err(|e| anyhow::anyhow!("sponsor fund: {e}"))?;
            (ephemeral, "ephemeral-from-sponsor".to_string(), Some(eph_b58))
        }
    } else {
        (sponsor, "sponsor-direct".to_string(), None)
    };

    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"keyset-registry"], &program_id);
    let (nullifier_pda, _) =
        Pubkey::find_program_address(&[b"tardus", b"nullifier-tree"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(
        &[b"tardus", b"vault", &found.denom.to_le_bytes()],
        &program_id,
    );

    let reg_acc = rpc
        .get_account(&registry_pda)
        .await
        .map_err(|e| anyhow::anyhow!("registry account: {e}"))?;
    let registry: tardus_program::state::KeysetRegistry =
        <tardus_program::state::KeysetRegistry as borsh::BorshDeserialize>::deserialize_reader(
            &mut &reg_acc.data[..],
        )
        .map_err(|e| anyhow::anyhow!("registry deserialise: {e}"))?;
    let entry = registry
        .find_active_for_denom(found.denom)
        .ok_or_else(|| anyhow::anyhow!("no active keyset for denom {}", found.denom))?;

    let nullifier = compute_nullifier(&found.pubkey_bytes);
    let null_acc = rpc
        .get_account(&nullifier_pda)
        .await
        .map_err(|e| anyhow::anyhow!("nullifier account: {e}"))?;
    let nullifiers: tardus_program::state::NullifierSet =
        if null_acc.data.iter().all(|&b| b == 0) {
            tardus_program::state::NullifierSet::new()
        } else {
            <tardus_program::state::NullifierSet as borsh::BorshDeserialize>::deserialize_reader(
                &mut &null_acc.data[..],
            )
            .map_err(|e| anyhow::anyhow!("nullifier deserialise: {e}"))?
        };
    if nullifiers.contains(&nullifier) {
        anyhow::bail!(
            "double-spend: coin already spent (nullifier {})",
            hex::encode(nullifier)
        );
    }
    let vault_acc = rpc
        .get_account(&vault_pda)
        .await
        .map_err(|e| anyhow::anyhow!("vault account: {e}"))?;
    if vault_acc.lamports < found.denom {
        anyhow::bail!(
            "vault underfunded: have {} lamports, need {}",
            vault_acc.lamports,
            found.denom
        );
    }

    // ed25519 precompile data (1-signature variant; header 16 + sig 64 + pk 32 + msg 32)
    let mut precompile_data = Vec::with_capacity(144);
    precompile_data.push(1u8);
    precompile_data.push(0u8);
    precompile_data.extend_from_slice(&16u16.to_le_bytes());
    precompile_data.extend_from_slice(&u16::MAX.to_le_bytes());
    precompile_data.extend_from_slice(&(16u16 + 64).to_le_bytes());
    precompile_data.extend_from_slice(&u16::MAX.to_le_bytes());
    precompile_data.extend_from_slice(&(16u16 + 64 + 32).to_le_bytes());
    precompile_data.extend_from_slice(&32u16.to_le_bytes());
    precompile_data.extend_from_slice(&u16::MAX.to_le_bytes());
    precompile_data.extend_from_slice(&found.signature_bytes);
    precompile_data.extend_from_slice(&entry.joint_pk);
    precompile_data.extend_from_slice(&found.pubkey_bytes);

    let precompile_ix = SolInstruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data: precompile_data,
    };
    let withdraw_ix = SolInstruction {
        program_id,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new_readonly(registry_pda, false),
            AccountMeta::new(vault_pda, false),
            AccountMeta::new(nullifier_pda, false),
            AccountMeta::new(recipient, false),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ],
        data: borsh::to_vec(&TInstruction::Withdraw {
            coin_pubkey: found.pubkey_bytes,
            coin_signature: tardus_core::Signature::from_bytes(&found.signature_bytes),
            denom: found.denom,
            recipient: recipient.to_bytes(),
        })
        .map_err(|e| anyhow::anyhow!("borsh: {e}"))?,
    };

    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| anyhow::anyhow!("blockhash: {e}"))?;
    let tx = Transaction::new_signed_with_payer(
        &[precompile_ix, withdraw_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| anyhow::anyhow!("send: {e}"))?;

    let sig_str = sig.to_string();
    let explorer = format!("https://explorer.solana.com/tx/{sig_str}?cluster=devnet");

    Ok(UiEvent::WithdrawOnDevnetResult {
        coin_label: coin_label.to_string(),
        denom: found.denom,
        recipient_b58: recipient_b58.to_string(),
        tx_signature: sig_str,
        explorer_url: explorer,
        elapsed_ms: started.elapsed().as_millis(),
        payer_strategy,
        ephemeral_payer_b58,
    })
}

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
async fn refresh(
    master_seed: &Zeroizing<[u8; 32]>,
    wallet_file: &std::path::Path,
    keysets_file: &std::path::Path,
    keyset_name: &str,
    coin_label: &str,
) -> anyhow::Result<UiEvent> {
    use rand::RngCore;
    use tardus_client::coin_store::{CoinStatus, StoredCoin};
    use tardus_core::{PublicKey, SecretKey, Signature};
    use tardus_mint::transcript::SessionId;
    use tardus_refresh::coin::Coin;
    use tardus_wallet::{
        refresh_coin, KeysetDb, ValidatorEndpoint, WalletClientPool, WalletDb,
    };

    let started = std::time::Instant::now();

    // 1. open wallet + look up the Active coin by label
    let mut wallet = WalletDb::open(wallet_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("wallet open: {e:?}"))?;
    let found = wallet
        .store()
        .coins
        .iter()
        .find(|c| c.label.as_deref() == Some(coin_label) && c.status == CoinStatus::Active)
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!("no Active coin with label {coin_label:?}")
        })?;

    let old_pubkey_prefix_hex: String = hex::encode(found.pubkey_bytes)
        .chars()
        .take(16)
        .collect();

    // 2. open keysets, look up name, validate denom
    if !keysets_file.exists() {
        anyhow::bail!("keysets file not found: {}", keysets_file.display());
    }
    let kdb = KeysetDb::open(keysets_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("keyset open: {e:?}"))?;
    let info = kdb
        .store()
        .get(keyset_name)
        .ok_or_else(|| anyhow::anyhow!("unknown keyset {keyset_name:?}"))?;
    if info.denom != found.denom {
        anyhow::bail!(
            "denom mismatch: keyset = {}, coin = {}",
            info.denom,
            found.denom
        );
    }

    // 3. build pool + joint_pk
    let mut endpoints = Vec::with_capacity(info.validators.len());
    for (i, url) in info.validators.iter().enumerate() {
        let idx = (i + 1) as u16;
        let ep = ValidatorEndpoint::plain(idx, url.clone())
            .map_err(|e| anyhow::anyhow!("validator endpoint: {e}"))?;
        endpoints.push(ep);
    }
    let pool = WalletClientPool::new(endpoints)
        .map_err(|e| anyhow::anyhow!("pool: {e}"))?;
    let joint_pk_bytes = parse_hex32(&info.joint_pk_hex)
        .map_err(|e| anyhow::anyhow!("joint_pk: {e}"))?;
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
        .map_err(|e| anyhow::anyhow!("joint_pk decode: {e}"))?;

    // 4. reconstruct the old Coin from stored bytes
    let old_coin = Coin::new(
        SecretKey::from_bytes(&found.secret_bytes)
            .map_err(|e| anyhow::anyhow!("coin sk: {e}"))?,
        found.pubkey_bytes,
        Signature::from_bytes(&found.signature_bytes),
    )
    .map_err(|e| anyhow::anyhow!("coin reconstruct: {e}"))?;

    // 5. drive κ-fold cut-and-choose refresh
    let mut session_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut session_bytes);
    let session_id = SessionId::from_bytes(session_bytes);
    let new_coin = refresh_coin(&pool, &old_coin, &joint_pk, session_id)
        .await
        .map_err(|e| anyhow::anyhow!("refresh_coin: {e}"))?;

    // 6. atomic wallet update: mark old Spent + add new Active
    let old_nullifier = StoredCoin {
        secret_bytes: found.secret_bytes,
        pubkey_bytes: found.pubkey_bytes,
        signature_bytes: found.signature_bytes,
        denom: found.denom,
        status: CoinStatus::Spent,
        label: found.label.clone(),
    }
    .nullifier();
    wallet
        .store_mut()
        .mark_spent(&old_nullifier)
        .map_err(|e| anyhow::anyhow!("mark_spent: {e:?}"))?;

    let new_label = format!("refreshed-{coin_label}");
    let new_pubkey_prefix_hex: String = hex::encode(new_coin.pubkey_bytes())
        .chars()
        .take(16)
        .collect();
    let new_stored = StoredCoin {
        secret_bytes: new_coin.secret().to_bytes(),
        pubkey_bytes: new_coin.pubkey_bytes(),
        signature_bytes: new_coin.signature().to_bytes(),
        denom: found.denom,
        status: CoinStatus::Active,
        label: Some(new_label.clone()),
    };
    wallet
        .store_mut()
        .add(new_stored)
        .map_err(|e| anyhow::anyhow!("wallet add: {e:?}"))?;
    wallet
        .save(master_seed)
        .map_err(|e| anyhow::anyhow!("wallet save: {e:?}"))?;

    let (coin_summary, coin_total, active_coins) = summarize_store(wallet.store());

    Ok(UiEvent::CoinRefreshed {
        old_label: found.label,
        new_label,
        denom: found.denom,
        old_pubkey_prefix_hex,
        new_pubkey_prefix_hex,
        elapsed_ms: started.elapsed().as_millis(),
        coin_summary,
        coin_total,
        active_coins,
    })
}

#[allow(clippy::too_many_lines)]
async fn receive(
    master_seed: &Zeroizing<[u8; 32]>,
    wallet_file: &std::path::Path,
    recipient_pk_hex: &str,
    relay_url: &str,
    keep_on_relay: bool,
    label_prefix: &str,
) -> anyhow::Result<UiEvent> {
    use tardus_client::coin_store::{CoinStatus, StoredCoin};
    use tardus_wallet::{derive_receiving_keypair, sealed_box, WalletDb};

    let started = std::time::Instant::now();

    // 1. open the wallet file (creates empty if missing).
    let mut wallet = WalletDb::open(wallet_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("wallet open: {e:?}"))?;

    // 2. derive recv-sk for sealed-box decryption.
    let (recv_sk, _recv_pk) = derive_receiving_keypair(master_seed);

    // 3. poll the relay.
    let relay_base = relay_url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("reqwest client: {e}"))?;
    let listed: serde_json::Value = client
        .get(format!("{relay_base}/inbox/{}", recipient_pk_hex.trim()))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("relay GET: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("relay JSON: {e}"))?;
    let messages = listed["messages"].as_array().cloned().unwrap_or_default();
    if messages.is_empty() {
        return Ok(UiEvent::ReceiveResult {
            received: 0,
            deleted_from_relay: 0,
            skipped: 0,
            elapsed_ms: started.elapsed().as_millis(),
        });
    }

    // 4. for each message: decrypt → decode JSON → add to wallet → DELETE.
    let mut received = 0usize;
    let mut deleted_from_relay = 0usize;
    let mut skipped = 0usize;
    for msg in &messages {
        let id = msg["id"].as_str().unwrap_or("");
        let payload_hex = msg["payload_hex"].as_str().unwrap_or("");
        let Ok(payload_bytes) = hex::decode(payload_hex) else {
            skipped += 1;
            continue;
        };
        // sealed_box::open first; on failure, fall back to plain JSON.
        let decoded_bytes = sealed_box::open(&payload_bytes, &recv_sk)
            .ok()
            .unwrap_or_else(|| payload_bytes.clone());
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(&decoded_bytes) else {
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
        let Ok(secret_bytes) = parse_hex32(cs) else {
            skipped += 1;
            continue;
        };
        let Ok(pubkey_bytes) = parse_hex32(cp) else {
            skipped += 1;
            continue;
        };
        let Ok(sig_bytes) = parse_hex64(sig) else {
            skipped += 1;
            continue;
        };
        let stored = StoredCoin {
            secret_bytes,
            pubkey_bytes,
            signature_bytes: sig_bytes,
            denom,
            status: CoinStatus::Active,
            label: Some(format!("{label_prefix}-{id}")),
        };
        if wallet.store_mut().add(stored).is_ok() {
            received += 1;
            if !keep_on_relay {
                let del_url = format!(
                    "{relay_base}/inbox/{}/{id}",
                    recipient_pk_hex.trim()
                );
                if client.delete(&del_url).send().await.is_ok() {
                    deleted_from_relay += 1;
                }
            }
        } else {
            skipped += 1;
        }
    }

    // 5. persist wallet if anything changed.
    if received > 0 {
        wallet
            .save(master_seed)
            .map_err(|e| anyhow::anyhow!("wallet save: {e:?}"))?;
    }

    Ok(UiEvent::ReceiveResult {
        received,
        deleted_from_relay,
        skipped,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn parse_hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    let b = hex::decode(s).map_err(|e| anyhow::anyhow!("hex: {e}"))?;
    if b.len() != 32 {
        anyhow::bail!("expected 32 bytes, got {}", b.len());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}

fn parse_hex64(s: &str) -> anyhow::Result<[u8; 64]> {
    let b = hex::decode(s).map_err(|e| anyhow::anyhow!("hex: {e}"))?;
    if b.len() != 64 {
        anyhow::bail!("expected 64 bytes, got {}", b.len());
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&b);
    Ok(a)
}

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
async fn pay(
    master_seed: &Zeroizing<[u8; 32]>,
    keysets_file: &std::path::Path,
    invoice_uri: &str,
    keyset_name: &str,
    encrypt: bool,
) -> anyhow::Result<UiEvent> {
    use rand::RngCore;
    use tardus_client::invoice::Invoice;
    use tardus_core::PublicKey;
    use tardus_mint::transcript::SessionId;
    use tardus_wallet::{
        issue_coin, sealed_box, KeysetDb, ValidatorEndpoint, WalletClientPool,
    };

    let started = std::time::Instant::now();

    // 1. parse invoice
    let inv = Invoice::parse(invoice_uri)
        .map_err(|e| anyhow::anyhow!("invoice parse: {e}"))?;

    // 2. open keysets + look up
    if !keysets_file.exists() {
        anyhow::bail!("keysets file not found: {}", keysets_file.display());
    }
    let db = KeysetDb::open(keysets_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("keyset open: {e:?}"))?;
    let info = db
        .store()
        .get(keyset_name)
        .ok_or_else(|| anyhow::anyhow!("unknown keyset \"{keyset_name}\""))?;

    // 3. validate denom
    if info.denom != inv.denom {
        anyhow::bail!(
            "denom mismatch: keyset = {}, invoice = {}",
            info.denom,
            inv.denom
        );
    }

    // 4. build pool
    let mut endpoints = Vec::with_capacity(info.validators.len());
    for (i, url) in info.validators.iter().enumerate() {
        let idx = (i + 1) as u16;
        let ep = ValidatorEndpoint::plain(idx, url.clone())
            .map_err(|e| anyhow::anyhow!("validator endpoint: {e}"))?;
        endpoints.push(ep);
    }
    let pool = WalletClientPool::new(endpoints)
        .map_err(|e| anyhow::anyhow!("pool: {e}"))?;

    // joint_pk
    let joint_pk_bytes = {
        let b = hex::decode(&info.joint_pk_hex)
            .map_err(|e| anyhow::anyhow!("joint_pk hex: {e}"))?;
        if b.len() != 32 {
            anyhow::bail!("joint_pk must be 32 bytes, got {}", b.len());
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        a
    };
    let joint_pk = PublicKey::from_bytes(&joint_pk_bytes)
        .map_err(|e| anyhow::anyhow!("joint_pk decode: {e}"))?;

    // 5. mint
    let mut session_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut session_bytes);
    let session_id = SessionId::from_bytes(session_bytes);
    let coin = issue_coin(&pool, &joint_pk, session_id)
        .await
        .map_err(|e| anyhow::anyhow!("issue_coin: {e}"))?;

    // 6. JSON payload + optional seal
    let payload_json = serde_json::json!({
        "coin_secret":    hex::encode(coin.secret().to_bytes()),
        "coin_pubkey":    hex::encode(coin.pubkey_bytes()),
        "coin_signature": hex::encode(coin.signature().to_bytes()),
        "denom":          inv.denom,
        "memo":           inv.memo.as_ref().and_then(|m| std::str::from_utf8(m).ok()),
    });
    let plaintext = serde_json::to_vec(&payload_json)?;
    let payload_hex = if encrypt {
        let sealed = sealed_box::seal(&plaintext, &inv.recipient_pubkey)
            .map_err(|e| anyhow::anyhow!("sealed_box::seal: {e}"))?;
        hex::encode(sealed)
    } else {
        hex::encode(&plaintext)
    };

    // 7. POST to relay
    let relay_url = inv
        .relays
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("invoice has no relay URL"))?;
    let recipient_hex = hex::encode(inv.recipient_pubkey);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("reqwest client: {e}"))?;
    let deposit: serde_json::Value = client
        .post(format!(
            "{}/inbox/{recipient_hex}",
            relay_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({ "payload_hex": payload_hex, "ttl_secs": 604_800u64 }))
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("relay POST: {e}"))?
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("relay JSON: {e}"))?;

    let msg_id = deposit["id"].as_str().unwrap_or("").to_string();
    Ok(UiEvent::PaymentSent {
        recipient_prefix_hex: recipient_hex.chars().take(16).collect(),
        denom: inv.denom,
        relay_url,
        message_id: msg_id,
        encrypted: encrypt,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

fn remove_keyset(
    master_seed: &Zeroizing<[u8; 32]>,
    keysets_file: &std::path::Path,
    name: &str,
) -> anyhow::Result<bool> {
    use tardus_wallet::KeysetDb;
    let mut db = KeysetDb::open(keysets_file.to_path_buf(), master_seed)
        .map_err(|e| anyhow::anyhow!("keyset open: {e:?}"))?;
    let removed = db.store_mut().remove(name).is_some();
    if removed {
        db.save(master_seed)
            .map_err(|e| anyhow::anyhow!("keyset save: {e:?}"))?;
    }
    Ok(removed)
}

/// Strip hex-shaped secret runs from error messages before they
/// reach the UI. Heuristic: replace any 32-char (or longer) hex
/// substring with "<redacted>". Defends against the failure path
/// where a wrapped error stringifies a key.
fn redact(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let mut j = i;
        while j < chars.len() && chars[j].is_ascii_hexdigit() {
            j += 1;
        }
        if j - i >= 32 {
            out.push_str("<redacted>");
            i = j;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_strips_long_hex() {
        let s = "wallet open failed: bad seed deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let r = redact(s);
        assert!(r.contains("<redacted>"));
        assert!(!r.contains("deadbeef"));
    }

    #[test]
    fn redact_keeps_short_hex() {
        let s = "error code 0xCC at offset 0xDEAD";
        let r = redact(s);
        // "DEAD" and "CC" are < 32 chars; preserved.
        assert!(r.contains("DEAD"));
        assert!(r.contains("CC"));
    }

    /// Drive list / add / remove against the same on-disk
    /// `keysets.bin` format the CLI writes, proving GUI runtime
    /// wire-compatible. Uses tempdir + a deterministic test seed.
    #[test]
    fn keyset_crud_against_real_file() {
        use tardus_wallet::{derive_master_seed, parse_mnemonic};
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("keysets.bin");
        let phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about";
        let m = parse_mnemonic(phrase).unwrap();
        let seed = derive_master_seed(&m, "");
        let master_seed: Zeroizing<[u8; 32]> = Zeroizing::new(*seed);

        // Empty start
        let listed = list_keysets(&master_seed, &path).unwrap();
        assert!(listed.is_empty());

        // Add 2 keysets
        add_keyset(
            &master_seed,
            &path,
            "mainnet-1m".into(),
            "a".repeat(64),
            1_000_000,
            vec!["https://v1.example.com".into(), "https://v2.example.com".into()],
            None,
            None,
        )
        .unwrap();
        add_keyset(
            &master_seed,
            &path,
            "devnet-test".into(),
            "b".repeat(64),
            1_000,
            vec!["http://127.0.0.1:9787".into()],
            None,
            None,
        )
        .unwrap();
        let listed = list_keysets(&master_seed, &path).unwrap();
        assert_eq!(listed.len(), 2);
        let names: std::collections::HashSet<_> =
            listed.iter().map(|k| k.name.clone()).collect();
        assert!(names.contains("mainnet-1m"));
        assert!(names.contains("devnet-test"));

        // Reject invalid input
        let bad_pk =
            add_keyset(&master_seed, &path, "x".into(), "deadbeef".into(), 1, vec!["url".into()], None, None);
        assert!(bad_pk.is_err());
        let empty_validators = add_keyset(
            &master_seed,
            &path,
            "y".into(),
            "c".repeat(64),
            1,
            vec![],
            None,
            None,
        );
        assert!(empty_validators.is_err());

        // Remove
        let removed = remove_keyset(&master_seed, &path, "devnet-test").unwrap();
        assert!(removed);
        let listed = list_keysets(&master_seed, &path).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "mainnet-1m");

        // Remove non-existent
        let removed = remove_keyset(&master_seed, &path, "ghost").unwrap();
        assert!(!removed);
    }

    /// End-to-end exercise of the Pay async path against real
    /// production binaries (3 validators + 1 relay), through the
    /// dispatch() channel like the GUI itself.
    ///
    /// Marked `#[ignore]` because it spawns 4 processes and runs
    /// the full DKG + threshold sign + sealed-box + relay POST.
    /// Run with:
    ///     cargo test -p tardus-wallet-gui --release \
    ///         pay_via_runtime_against_live_stack -- --ignored --nocapture
    /// Drive UiCommand::Refresh end-to-end against a real
    /// 3-validator stack: mint a coin, save it labelled in a
    /// wallet, then drive UiCommand::Refresh — assert old becomes
    /// Spent + new is Active with unlinkable pubkey, both verify
    /// under joint_pk.
    #[test]
    #[ignore = "spawns 3 production binaries; run with --ignored"]
    #[allow(clippy::too_many_lines, clippy::items_after_statements, clippy::doc_markdown)]
    fn refresh_via_runtime_against_live_stack() {
        use rand::RngCore;
        use std::net::TcpListener;
        use std::process::{Child, Command, Stdio};
        use std::time::Duration as D;
        use tardus_client::coin_store::{CoinStatus, StoredCoin};
        use tardus_core::PublicKey;
        use tardus_mint::transcript::SessionId;
        use tardus_wallet::{
            derive_master_seed, issue_coin, parse_mnemonic, ValidatorEndpoint,
            WalletClientPool, WalletDb,
        };

        struct Guard(Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        fn pick_port() -> u16 {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        }
        fn bin(name: &str) -> std::path::PathBuf {
            let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            let mut p = std::path::PathBuf::from(manifest);
            p.pop();
            p.pop();
            p.push("target/release");
            p.push(name);
            assert!(p.exists(), "missing {}", p.display());
            p
        }
        fn wait_for(url: &str) {
            let c = ::reqwest::blocking::Client::builder()
                .timeout(D::from_secs(1))
                .build()
                .unwrap();
            let t0 = std::time::Instant::now();
            while t0.elapsed() < D::from_secs(5) {
                if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
                    return;
                }
                std::thread::sleep(D::from_millis(50));
            }
            panic!("not healthy: {url}");
        }
        fn spawn_validator(idx: u16) -> (Guard, String) {
            let tmp = tempfile::TempDir::new().unwrap();
            let tmp_path = tmp.keep();
            let port = pick_port();
            let bind = format!("127.0.0.1:{port}");
            let mut seed_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
            let child = Command::new(bin("tardus-validator"))
                .arg("--bind").arg(&bind)
                .arg("--data-dir").arg(&tmp_path)
                .arg("--operator").arg(format!("gui-refresh-test-{idx}"))
                .arg("--master-seed-hex").arg(hex::encode(seed_bytes))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("validator");
            (Guard(child), format!("http://{bind}"))
        }

        // === 1. spawn 3 validators + run DKG ===
        let (v1, v1_base) = spawn_validator(1);
        let (v2, v2_base) = spawn_validator(2);
        let (v3, v3_base) = spawn_validator(3);
        for u in [&v1_base, &v2_base, &v3_base] {
            wait_for(&format!("{u}/health"));
        }
        let ceremony_hex = hex::encode([0xF1u8; 16]);
        let client = ::reqwest::blocking::Client::new();
        let validators = [(1u16, &v1_base), (2, &v2_base), (3, &v3_base)];

        #[derive(serde::Serialize)]
        struct DkgStart {
            ceremony_id_hex: String,
            my_index: u16,
            n: u16,
            t: u16,
        }
        #[derive(serde::Serialize)]
        struct DkgContrib {
            ceremony_id_hex: String,
            from_index: u16,
            broadcast_borsh_hex: String,
            share_for_me_borsh_hex: String,
        }
        #[derive(serde::Serialize)]
        struct DkgFinal {
            ceremony_id_hex: String,
        }

        let mut bcs: std::collections::HashMap<u16, String> =
            std::collections::HashMap::new();
        let mut shs: std::collections::HashMap<u16, Vec<String>> =
            std::collections::HashMap::new();
        for (i, base) in &validators {
            let r: serde_json::Value = client
                .post(format!("{base}/dkg/start"))
                .json(&DkgStart {
                    ceremony_id_hex: ceremony_hex.clone(),
                    my_index: *i,
                    n: 3,
                    t: 3,
                })
                .send()
                .unwrap()
                .json()
                .unwrap();
            bcs.insert(*i, r["broadcast_borsh_hex"].as_str().unwrap().to_string());
            shs.insert(
                *i,
                r["shares_borsh_hex"].as_array().unwrap().iter()
                    .map(|x| x.as_str().unwrap().to_string()).collect(),
            );
        }
        for (i, base) in &validators {
            for (other, _) in &validators {
                if other == i {
                    continue;
                }
                client.post(format!("{base}/dkg/contribute"))
                    .json(&DkgContrib {
                        ceremony_id_hex: ceremony_hex.clone(),
                        from_index: *other,
                        broadcast_borsh_hex: bcs[other].clone(),
                        share_for_me_borsh_hex: shs[other][(*i - 1) as usize].clone(),
                    })
                    .send().unwrap();
            }
        }
        let mut joint_pks = Vec::new();
        for (_, base) in &validators {
            let r: serde_json::Value = client.post(format!("{base}/dkg/finalize"))
                .json(&DkgFinal { ceremony_id_hex: ceremony_hex.clone() })
                .send().unwrap().json().unwrap();
            joint_pks.push(r["joint_pk_hex"].as_str().unwrap().to_string());
        }
        assert_eq!(joint_pks[0], joint_pks[1]);
        assert_eq!(joint_pks[1], joint_pks[2]);
        let joint_pk_hex = joint_pks.into_iter().next().unwrap();

        // === 2. set up wallet + keyset + mint a coin via the
        //        library and save it labelled in the wallet ===
        let tmp = tempfile::TempDir::new().unwrap();
        let wallet_file = tmp.path().join("wallet.bin");
        let keysets_file = tmp.path().join("keysets.bin");
        let phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about";
        let m = parse_mnemonic(phrase).unwrap();
        let seed = derive_master_seed(&m, "");
        let master_seed: Zeroizing<[u8; 32]> = Zeroizing::new(*seed);

        add_keyset(
            &master_seed,
            &keysets_file,
            "live".into(),
            joint_pk_hex.clone(),
            1_000_000,
            vec![v1_base.clone(), v2_base.clone(), v3_base.clone()],
            None,
            None,
        )
        .unwrap();

        // Mint via the library, store in wallet labelled "salary-1".
        let pool = WalletClientPool::new(vec![
            ValidatorEndpoint::plain(1, v1_base.clone()).unwrap(),
            ValidatorEndpoint::plain(2, v2_base.clone()).unwrap(),
            ValidatorEndpoint::plain(3, v3_base.clone()).unwrap(),
        ])
        .unwrap();
        let joint_pk = {
            let b = hex::decode(&joint_pk_hex).unwrap();
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            PublicKey::from_bytes(&a).unwrap()
        };
        let mut sid = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut sid);
        let issue_session = SessionId::from_bytes(sid);
        let rt_helper = tokio::runtime::Runtime::new().unwrap();
        let coin = rt_helper
            .block_on(issue_coin(&pool, &joint_pk, issue_session))
            .expect("issue_coin");
        let mut wallet =
            WalletDb::open(wallet_file.clone(), &master_seed).expect("wallet open");
        let old_cp = coin.pubkey_bytes();
        wallet
            .store_mut()
            .add(StoredCoin {
                secret_bytes: coin.secret().to_bytes(),
                pubkey_bytes: old_cp,
                signature_bytes: coin.signature().to_bytes(),
                denom: 1_000_000,
                status: CoinStatus::Active,
                label: Some("salary-1".into()),
            })
            .unwrap();
        wallet.save(&master_seed).unwrap();
        drop(wallet);

        // === 3. drive UiCommand::Refresh ===
        let handle = spawn_runtime();
        handle.send(UiCommand::Refresh {
            master_seed: master_seed.clone(),
            wallet_file: wallet_file.clone(),
            keysets_file: keysets_file.clone(),
            keyset_name: "live".into(),
            coin_label: "salary-1".into(),
        });

        let t0 = std::time::Instant::now();
        let mut events = Vec::new();
        while t0.elapsed() < D::from_secs(60) {
            handle.drain_events(&mut events);
            if events
                .iter()
                .any(|e| matches!(e, UiEvent::CoinRefreshed { .. } | UiEvent::Error { .. }))
            {
                break;
            }
            std::thread::sleep(D::from_millis(100));
        }
        let r = events
            .iter()
            .find(|e| matches!(e, UiEvent::CoinRefreshed { .. }))
            .unwrap_or_else(|| {
                panic!("no CoinRefreshed after 60 s; events = {events:?}")
            });
        match r {
            UiEvent::CoinRefreshed {
                old_label,
                new_label,
                denom,
                old_pubkey_prefix_hex,
                new_pubkey_prefix_hex,
                ..
            } => {
                assert_eq!(*denom, 1_000_000);
                assert_eq!(old_label.as_deref(), Some("salary-1"));
                assert_eq!(new_label, "refreshed-salary-1");
                assert_ne!(
                    old_pubkey_prefix_hex, new_pubkey_prefix_hex,
                    "Cp unlinkability must hold"
                );
                // Sanity-check the old prefix matches the coin we minted.
                let expected_old_prefix: String = hex::encode(old_cp).chars().take(16).collect();
                assert_eq!(old_pubkey_prefix_hex, &expected_old_prefix);
            }
            _ => unreachable!(),
        }

        // === 4. wallet must now have old=Spent + new=Active ===
        let wallet =
            WalletDb::open(wallet_file.clone(), &master_seed).expect("wallet reopen");
        let coins = &wallet.store().coins;
        assert_eq!(coins.len(), 2);
        let active_count = coins
            .iter()
            .filter(|c| c.status == CoinStatus::Active)
            .count();
        let spent_count = coins
            .iter()
            .filter(|c| c.status == CoinStatus::Spent)
            .count();
        assert_eq!(active_count, 1);
        assert_eq!(spent_count, 1);

        handle.send(UiCommand::Shutdown);
        drop((v1, v2, v3));
    }

    /// Post a sealed payload to a real relay daemon, then drive
    /// `UiCommand::Receive` through the GUI runtime — assert the
    /// coin lands in the wallet file + relay inbox emptied.
    #[test]
    #[ignore = "spawns tardus-relayd; run with --ignored"]
    #[allow(clippy::too_many_lines, clippy::items_after_statements, clippy::doc_markdown)]
    fn receive_via_runtime_against_live_relay() {
        use std::net::TcpListener;
        use std::process::{Child, Command, Stdio};
        use std::time::Duration as D;
        use tardus_wallet::{
            derive_master_seed, derive_receiving_keypair, parse_mnemonic, sealed_box,
        };

        struct Guard(Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        fn pick_port() -> u16 {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        }
        fn bin(name: &str) -> std::path::PathBuf {
            let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            let mut p = std::path::PathBuf::from(manifest);
            p.pop();
            p.pop();
            p.push("target/release");
            p.push(name);
            assert!(p.exists(), "missing {}", p.display());
            p
        }
        fn wait_for(url: &str) {
            let c = ::reqwest::blocking::Client::builder()
                .timeout(D::from_secs(1))
                .build()
                .unwrap();
            let t0 = std::time::Instant::now();
            while t0.elapsed() < D::from_secs(5) {
                if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
                    return;
                }
                std::thread::sleep(D::from_millis(50));
            }
            panic!("not healthy: {url}");
        }

        // === 1. spawn relay ===
        let port = pick_port();
        let bind = format!("127.0.0.1:{port}");
        let relay_base = format!("http://{bind}");
        let child = Command::new(bin("tardus-relayd"))
            .arg("--bind").arg(&bind)
            .arg("--operator").arg("gui-recv-test")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("relay");
        let _relay = Guard(child);
        wait_for(&format!("{relay_base}/health"));

        // === 2. Bob's identity ===
        let phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about";
        let m = parse_mnemonic(phrase).unwrap();
        let seed = derive_master_seed(&m, "");
        let master_seed: Zeroizing<[u8; 32]> = Zeroizing::new(*seed);
        let (_bob_sk, bob_pk) = derive_receiving_keypair(&master_seed);
        let bob_pk_hex = hex::encode(bob_pk);

        // === 3. Sender hand-crafts a sealed payload + POST ===
        //     (mimics what tardus-wallet pay --encrypt produces)
        let payload_json = serde_json::json!({
            "coin_secret":
                "0011223344556677889900112233445566778899001122334455667788990011",
            "coin_pubkey":
                "0022334455667788990011223344556677889900112233445566778899001122",
            "coin_signature":
                "00334455667788990011223344556677889900112233445566778899001122330044556677889900112233445566778899001122334455667788990011223344",
            "denom": 1_000_000u64,
            "memo": "gui-recv-test",
        });
        let plaintext = serde_json::to_vec(&payload_json).unwrap();
        let sealed = sealed_box::seal(&plaintext, &bob_pk).unwrap();
        let payload_hex = hex::encode(&sealed);

        let client = ::reqwest::blocking::Client::new();
        let deposit: serde_json::Value = client
            .post(format!("{relay_base}/inbox/{bob_pk_hex}"))
            .json(&serde_json::json!({"payload_hex": payload_hex, "ttl_secs": 3600}))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert!(deposit["id"].as_str().is_some());

        // === 4. drive UI command through the runtime ===
        let tmp = tempfile::TempDir::new().unwrap();
        let wallet_file = tmp.path().join("wallet.bin");

        let handle = spawn_runtime();
        handle.send(UiCommand::Receive {
            master_seed: master_seed.clone(),
            wallet_file: wallet_file.clone(),
            recipient_pk_hex: bob_pk_hex.clone(),
            relay_url: relay_base.clone(),
            keep_on_relay: false,
            label_prefix: "gui-rx".into(),
        });

        let t0 = std::time::Instant::now();
        let mut events = Vec::new();
        while t0.elapsed() < D::from_secs(15) {
            handle.drain_events(&mut events);
            if events
                .iter()
                .any(|e| matches!(e, UiEvent::ReceiveResult { .. } | UiEvent::Error { .. }))
            {
                break;
            }
            std::thread::sleep(D::from_millis(50));
        }
        let result = events
            .iter()
            .find(|e| matches!(e, UiEvent::ReceiveResult { .. }))
            .unwrap_or_else(|| {
                panic!("no ReceiveResult after 15s; events = {events:?}")
            });
        match result {
            UiEvent::ReceiveResult {
                received,
                deleted_from_relay,
                skipped,
                ..
            } => {
                assert_eq!(*received, 1, "expected 1 coin received");
                assert_eq!(*deleted_from_relay, 1, "expected 1 message deleted");
                assert_eq!(*skipped, 0, "expected 0 skipped");
            }
            _ => unreachable!(),
        }

        // === 5. wallet file should now hold the Active coin ===
        let db = tardus_wallet::WalletDb::open(wallet_file.clone(), &master_seed).unwrap();
        let coins = &db.store().coins;
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].denom, 1_000_000);
        assert_eq!(
            coins[0].status,
            tardus_client::coin_store::CoinStatus::Active
        );

        // === 6. relay inbox should now be empty ===
        let listed: serde_json::Value = client
            .get(format!("{relay_base}/inbox/{bob_pk_hex}"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(listed["messages"].as_array().unwrap().len(), 0);

        handle.send(UiCommand::Shutdown);
    }

    #[test]
    #[ignore = "spawns 4 production binaries; run with --ignored"]
    #[allow(clippy::too_many_lines, clippy::items_after_statements, clippy::default_trait_access, clippy::doc_markdown)]
    fn pay_via_runtime_against_live_stack() {
        use rand::RngCore;
        use std::net::TcpListener;
        use std::process::{Child, Command, Stdio};
        use std::time::Duration as D;
        use tardus_wallet::{derive_master_seed, parse_mnemonic};

        struct Guard(Child);
        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        fn pick_port() -> u16 {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let p = l.local_addr().unwrap().port();
            drop(l);
            p
        }
        fn bin(name: &str) -> std::path::PathBuf {
            let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
            let mut p = std::path::PathBuf::from(manifest);
            p.pop();
            p.pop();
            p.push("target/release");
            p.push(name);
            assert!(p.exists(), "missing {}", p.display());
            p
        }
        fn wait_for(url: &str) {
            let c = ::reqwest::blocking::Client::builder()
                .timeout(D::from_secs(1))
                .build()
                .unwrap();
            let t0 = std::time::Instant::now();
            while t0.elapsed() < D::from_secs(5) {
                if c.get(url).send().is_ok_and(|r| r.status().is_success()) {
                    return;
                }
                std::thread::sleep(D::from_millis(50));
            }
            panic!("not healthy: {url}");
        }
        fn spawn_validator(idx: u16) -> (Guard, String) {
            let tmp = tempfile::TempDir::new().unwrap();
            // leak the tempdir so it outlives the validator
            let tmp_path = tmp.keep();
            let port = pick_port();
            let bind = format!("127.0.0.1:{port}");
            let mut seed_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut seed_bytes);
            let child = Command::new(bin("tardus-validator"))
                .arg("--bind").arg(&bind)
                .arg("--data-dir").arg(&tmp_path)
                .arg("--operator").arg(format!("gui-pay-test-{idx}"))
                .arg("--master-seed-hex").arg(hex::encode(seed_bytes))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("validator");
            (Guard(child), format!("http://{bind}"))
        }
        fn spawn_relay() -> (Guard, String) {
            let port = pick_port();
            let bind = format!("127.0.0.1:{port}");
            let child = Command::new(bin("tardus-relayd"))
                .arg("--bind").arg(&bind)
                .arg("--operator").arg("gui-pay-relay")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("relay");
            (Guard(child), format!("http://{bind}"))
        }

        // === 1. spawn the stack ===
        let (v1, v1_base) = spawn_validator(1);
        let (v2, v2_base) = spawn_validator(2);
        let (v3, v3_base) = spawn_validator(3);
        let (relay, relay_base) = spawn_relay();
        for url in [&v1_base, &v2_base, &v3_base, &relay_base] {
            wait_for(&format!("{url}/health"));
        }

        // === 2. DKG ceremony (driven by reqwest::blocking) ===
        let ceremony_hex = hex::encode([0xD1u8; 16]);
        let client = ::reqwest::blocking::Client::new();
        let validators = [(1u16, &v1_base), (2, &v2_base), (3, &v3_base)];

        #[derive(serde::Serialize)]
        struct DkgStart {
            ceremony_id_hex: String,
            my_index: u16,
            n: u16,
            t: u16,
        }
        #[derive(serde::Serialize)]
        struct DkgContrib {
            ceremony_id_hex: String,
            from_index: u16,
            broadcast_borsh_hex: String,
            share_for_me_borsh_hex: String,
        }
        #[derive(serde::Serialize)]
        struct DkgFinal {
            ceremony_id_hex: String,
        }

        let mut bcs: std::collections::HashMap<u16, String> = Default::default();
        let mut shs: std::collections::HashMap<u16, Vec<String>> = Default::default();
        for (i, base) in &validators {
            let r: serde_json::Value = client
                .post(format!("{base}/dkg/start"))
                .json(&DkgStart {
                    ceremony_id_hex: ceremony_hex.clone(),
                    my_index: *i,
                    n: 3,
                    t: 3,
                })
                .send()
                .unwrap()
                .json()
                .unwrap();
            bcs.insert(*i, r["broadcast_borsh_hex"].as_str().unwrap().to_string());
            shs.insert(
                *i,
                r["shares_borsh_hex"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap().to_string())
                    .collect(),
            );
        }
        for (i, base) in &validators {
            for (other, _) in &validators {
                if other == i {
                    continue;
                }
                client
                    .post(format!("{base}/dkg/contribute"))
                    .json(&DkgContrib {
                        ceremony_id_hex: ceremony_hex.clone(),
                        from_index: *other,
                        broadcast_borsh_hex: bcs[other].clone(),
                        share_for_me_borsh_hex: shs[other][(*i - 1) as usize].clone(),
                    })
                    .send()
                    .unwrap();
            }
        }
        let mut joint_pks = Vec::new();
        for (_, base) in &validators {
            let r: serde_json::Value = client
                .post(format!("{base}/dkg/finalize"))
                .json(&DkgFinal {
                    ceremony_id_hex: ceremony_hex.clone(),
                })
                .send()
                .unwrap()
                .json()
                .unwrap();
            joint_pks.push(r["joint_pk_hex"].as_str().unwrap().to_string());
        }
        assert_eq!(joint_pks[0], joint_pks[1]);
        assert_eq!(joint_pks[1], joint_pks[2]);
        let joint_pk_hex = joint_pks.into_iter().next().unwrap();

        // === 3. set up Bob's identity + keyset file ===
        let tmp = tempfile::TempDir::new().unwrap();
        let keysets_file = tmp.path().join("keysets.bin");
        let phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon about";
        let m = parse_mnemonic(phrase).unwrap();
        let seed = derive_master_seed(&m, "");
        let master_seed: Zeroizing<[u8; 32]> = Zeroizing::new(*seed);

        let (_bob_sk, bob_pk) = tardus_wallet::derive_receiving_keypair(&master_seed);
        let bob_pk_hex = hex::encode(bob_pk);

        // Alice's keyset entry (uses joint_pk we just DKG'd, validators we spawned)
        add_keyset(
            &master_seed,
            &keysets_file,
            "live".into(),
            joint_pk_hex,
            1_000_000,
            vec![v1_base.clone(), v2_base.clone(), v3_base.clone()],
            None,
            None,
        )
        .unwrap();

        let invoice = format!(
            "tardus://{bob_pk_hex}?denom=1000000&relay={relay_base}&memo=Z3VpLXBheS1zbW9rZQ"
        );

        // === 4. drive UI command through the runtime ===
        let handle = spawn_runtime();
        handle.send(UiCommand::Pay {
            master_seed: master_seed.clone(),
            keysets_file: keysets_file.clone(),
            invoice_uri: invoice,
            keyset_name: "live".into(),
            encrypt: true,
        });

        // Collect events for up to 30 s (live stack with DKG-issued
        // sign rounds + sealed-box + relay POST).
        let t0 = std::time::Instant::now();
        let mut events = Vec::new();
        while t0.elapsed() < D::from_secs(30) {
            handle.drain_events(&mut events);
            if events
                .iter()
                .any(|e| matches!(e, UiEvent::PaymentSent { .. } | UiEvent::Error { .. }))
            {
                break;
            }
            std::thread::sleep(D::from_millis(100));
        }
        let payment = events
            .iter()
            .find(|e| matches!(e, UiEvent::PaymentSent { .. }))
            .unwrap_or_else(|| {
                panic!(
                    "no PaymentSent event after 30 s; events = {events:?}"
                )
            });
        match payment {
            UiEvent::PaymentSent {
                recipient_prefix_hex,
                denom,
                encrypted,
                ..
            } => {
                assert_eq!(*denom, 1_000_000);
                assert!(*encrypted);
                assert!(bob_pk_hex.starts_with(recipient_prefix_hex));
            }
            _ => unreachable!(),
        }

        // === 5. confirm the message landed in Bob's inbox ===
        let listed: serde_json::Value = client
            .get(format!("{relay_base}/inbox/{bob_pk_hex}"))
            .send()
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(listed["messages"].as_array().unwrap().len(), 1);

        handle.send(UiCommand::Shutdown);
        drop((v1, v2, v3, relay));
    }

    #[test]
    fn ping_pong_roundtrip() {
        let handle = spawn_runtime();
        handle.send(UiCommand::Ping {
            nonce: "smoke-test".into(),
        });
        // Spin briefly for the runtime to roundtrip.
        let mut events = Vec::new();
        let start = Instant::now();
        while events.is_empty() && start.elapsed() < std::time::Duration::from_secs(2) {
            handle.drain_events(&mut events);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(events.len(), 1);
        match &events[0] {
            UiEvent::Pong { nonce, .. } => assert_eq!(nonce, "smoke-test"),
            other => panic!("expected Pong, got {other:?}"),
        }
        handle.send(UiCommand::Shutdown);
    }
}
