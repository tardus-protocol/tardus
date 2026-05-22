//! TARDUS desktop wallet — egui/eframe scaffold (v0).
//!
//! This is the **first GUI surface** for TARDUS. v0 scope is
//! deliberately narrow:
//!
//! - Generate a fresh BIP-39 mnemonic.
//! - Unlock an existing wallet by entering a mnemonic.
//! - Display the wallet's receiving identity (the pubkey users
//!   give senders for `tardus-wallet invoice make --pubkey ...`).
//! - Display held-coin balance per denomination (active /
//!   in-flight / spent).
//! - Display a paste-or-enter invoice URI and parse it to show
//!   recipient, amount, memo.
//!
//! Sign / refresh / pay / receive flows are deliberately CLI-only
//! in v0; wiring them into the GUI requires tokio-runtime
//! integration with eframe's frame loop (egui's eframe is
//! single-threaded; cross-thread tokio is the v1 GUI scope).
//!
//! License: TARDUS-PROPRIETARY-1.0.

#![allow(clippy::needless_pass_by_value)]

mod config;
mod runtime;
mod theme;

use config::Config;

use eframe::egui;
use std::path::PathBuf;
use std::time::Duration;
use tardus_wallet::{generate_mnemonic, WordCount};
use zeroize::Zeroizing;

use runtime::{
    spawn_runtime, ActiveCoinSummary, DenomBucket as RuntimeDenomBucket, KeysetSummary,
    RuntimeHandle, UiCommand, UiEvent,
};

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([720.0, 560.0])
        .with_min_inner_size([520.0, 400.0])
        .with_title("TARDUS — Wallet");

    let config = Config::load();
    eframe::run_native(
        "TARDUS Wallet",
        eframe::NativeOptions {
            viewport,
            ..Default::default()
        },
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            Ok(Box::new(App::new(ctx, config)))
        }),
    )
}

#[allow(clippy::struct_excessive_bools)]
struct App {
    /// Top-level mode: locked (need mnemonic) or unlocked.
    mode: Mode,

    // === Locked-mode form ===
    mnemonic_input: String,
    passphrase: String,
    wallet_file: PathBuf,
    keysets_file_input: PathBuf,
    error: Option<String>,
    /// True while an async unlock command is in flight.
    busy: bool,
    /// Most recent runtime event (for the status bar).
    status_line: Option<String>,
    /// Runtime handle (tokio thread + channel pair).
    runtime: RuntimeHandle,
    /// `egui` context — kept for explicit cross-thread
    /// `request_repaint()` calls in Faz 8.X+ when events arrive
    /// off-frame (e.g. timer-driven `receive` polling).
    #[allow(dead_code)]
    ctx: egui::Context,

    // === Unlocked-mode cached secret state ===
    /// Cached master seed for keyset CRUD / pay / refresh
    /// operations. Wiped on `lock()`.
    master_seed: Option<Zeroizing<[u8; 32]>>,
    /// Resolved keysets file (defaults to `<wallet_dir>/keysets.bin`).
    keysets_file: PathBuf,

    // === Unlocked-mode state ===
    /// Mnemonic-derived 32-byte receiving-identity pubkey, hex.
    recv_pubkey_hex: String,
    /// Coin store summary computed at open time.
    store_summary: Vec<DenomBucket>,
    coin_total: usize,

    // === Mnemonic-generation panel ===
    generated_mnemonic: Option<String>,
    word_count: u8,

    // === Invoice viewer ===
    invoice_uri_input: String,
    invoice_parsed: Option<String>,

    // === Tab switcher (Faz 8.2+) ===
    current_tab: Tab,

    // === Keyset tab state ===
    keyset_summary: Vec<KeysetSummary>,
    keyset_add_name: String,
    keyset_add_joint_pk: String,
    keyset_add_denom: String,
    keyset_add_validator_buf: String,
    keyset_add_validators: Vec<String>,
    /// Set by clicking "Remove" once; second click commits.
    /// `None` while no removal is pending.
    keyset_remove_target: Option<String>,

    // === Pay tab state ===
    pay_invoice_input: String,
    pay_selected_keyset: Option<String>,
    pay_encrypt: bool,
    pay_last_receipt: Option<PaymentReceipt>,

    // === Receive tab state ===
    receive_relay_url: String,
    receive_recipient_input: String,
    receive_keep_on_relay: bool,
    receive_label_prefix: String,
    receive_last_summary: Option<ReceiveSummary>,

    // === Refresh tab state ===
    active_coins: Vec<ActiveCoinSummary>,
    refresh_selected_keyset: Option<String>,
    refresh_selected_coin: Option<String>,
    refresh_last_result: Option<RefreshResult>,

    // === Withdraw tab state ===
    withdraw_selected_coin: Option<String>,
    withdraw_recipient_input: String,
    withdraw_rpc_input: String,
    withdraw_program_id_input: String,
    withdraw_keypair_path_input: String,
    withdraw_last_result: Option<WithdrawResult>,

    // === v2.13.2: GUI privacy stack ===
    /// Faz 9.1 — generate fresh keypair to sign the Withdraw TX.
    withdraw_use_ephemeral_payer: bool,
    /// Faz 9.4 — fund ephemeral via on-chain `SponsorPool` instead
    /// of direct sponsor → ephemeral transfer.
    withdraw_use_onchain_pool: bool,
}

#[derive(Default, PartialEq, Eq)]
enum Mode {
    #[default]
    Locked,
    Unlocked,
}

#[derive(Default, PartialEq, Eq, Clone, Copy)]
enum Tab {
    #[default]
    Balance,
    Keysets,
    Pay,
    Receive,
    Refresh,
    Withdraw,
    Invoice,
}

/// Last-pay receipt rendered under the Pay tab.
#[derive(Clone)]
struct PaymentReceipt {
    recipient_prefix_hex: String,
    denom: u64,
    relay_url: String,
    message_id: String,
    encrypted: bool,
    elapsed_ms: u128,
}

/// Last-receive result rendered under the Receive tab.
#[derive(Clone)]
struct ReceiveSummary {
    received: usize,
    deleted_from_relay: usize,
    skipped: usize,
    elapsed_ms: u128,
}

/// **Faz 9.6 / v2.13.2** — Last-withdraw result rendered under
/// the Withdraw tab. TX signature + Solana Explorer URL +
/// payer strategy (privacy class).
#[derive(Clone)]
struct WithdrawResult {
    coin_label: String,
    denom: u64,
    recipient_b58: String,
    tx_signature: String,
    explorer_url: String,
    elapsed_ms: u128,
    payer_strategy: String,
    ephemeral_payer_b58: Option<String>,
}

/// Last-refresh result rendered under the Refresh tab. The
/// `old_pubkey_prefix` vs `new_pubkey_prefix` divergence is the
/// user-visible unlinkability evidence.
#[derive(Clone)]
struct RefreshResult {
    old_label: Option<String>,
    new_label: String,
    denom: u64,
    old_pubkey_prefix_hex: String,
    new_pubkey_prefix_hex: String,
    elapsed_ms: u128,
}

type DenomBucket = RuntimeDenomBucket;

impl App {
    fn new(ctx: egui::Context, config: Config) -> Self {
        // Word-count default: prefer last-used; fall back to 24 (the
        // BIP-39 high-entropy default).
        let word_count = match config.last_word_count {
            12 | 24 => config.last_word_count,
            _ => 24,
        };
        Self {
            mode: Mode::default(),
            mnemonic_input: String::new(),
            passphrase: String::new(),
            wallet_file: config.last_wallet_file.clone(),
            keysets_file_input: config.last_keysets_file.clone(),
            error: None,
            busy: false,
            status_line: None,
            runtime: spawn_runtime(),
            ctx,
            master_seed: None,
            keysets_file: PathBuf::new(),
            recv_pubkey_hex: String::new(),
            store_summary: Vec::new(),
            coin_total: 0,
            generated_mnemonic: None,
            word_count,
            invoice_uri_input: String::new(),
            invoice_parsed: None,
            current_tab: Tab::default(),
            keyset_summary: Vec::new(),
            keyset_add_name: String::new(),
            keyset_add_joint_pk: String::new(),
            keyset_add_denom: String::new(),
            keyset_add_validator_buf: String::new(),
            keyset_add_validators: Vec::new(),
            keyset_remove_target: None,
            pay_invoice_input: String::new(),
            pay_selected_keyset: None,
            pay_encrypt: true,
            pay_last_receipt: None,
            receive_relay_url: config.last_relay_url.clone(),
            receive_recipient_input: String::new(),
            receive_keep_on_relay: false,
            receive_label_prefix: "from-relay".into(),
            receive_last_summary: None,
            active_coins: Vec::new(),
            refresh_selected_keyset: None,
            refresh_selected_coin: None,
            refresh_last_result: None,
            withdraw_selected_coin: None,
            withdraw_recipient_input: String::new(),
            withdraw_rpc_input: "https://api.devnet.solana.com".into(),
            withdraw_program_id_input:
                "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u".into(),
            withdraw_keypair_path_input: {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
                format!("{home}/.config/solana/id.json")
            },
            withdraw_last_result: None,
            withdraw_use_ephemeral_payer: false,
            withdraw_use_onchain_pool: false,
        }
    }

    /// Persist user prefs (non-secret only). Best-effort.
    fn persist_prefs(&self) {
        let c = Config {
            last_wallet_file: self.wallet_file.clone(),
            last_keysets_file: self.keysets_file_input.clone(),
            last_relay_url: self.receive_relay_url.clone(),
            last_word_count: self.word_count,
        };
        c.save();
    }

    /// Resolve the keysets file path: explicit `keysets_file_input`
    /// if non-empty, else `<wallet_dir>/keysets.bin`, else `./keysets.bin`.
    fn resolved_keysets_file(&self) -> PathBuf {
        if !self.keysets_file_input.as_os_str().is_empty() {
            return self.keysets_file_input.clone();
        }
        if self.wallet_file.as_os_str().is_empty() {
            return PathBuf::from("./keysets.bin");
        }
        self.wallet_file
            .parent()
            .map_or_else(
                || PathBuf::from("./keysets.bin"),
                |d| d.join("keysets.bin"),
            )
    }

    /// Kick off an async unlock via the runtime channel.
    fn unlock_async(&mut self) {
        self.error = None;
        self.status_line = Some("unlocking…".into());
        self.busy = true;
        let wallet_file = if self.wallet_file.as_os_str().is_empty() {
            None
        } else {
            Some(self.wallet_file.clone())
        };
        self.keysets_file = self.resolved_keysets_file();
        let keysets_file = Some(self.keysets_file.clone());
        self.runtime.send(UiCommand::OpenWallet {
            phrase: self.mnemonic_input.clone(),
            passphrase: self.passphrase.clone(),
            wallet_file,
            keysets_file,
        });
        // Persist the chosen file paths so the next launch
        // pre-fills the Locked screen.
        self.persist_prefs();
    }

    /// After `WalletOpened` lands, request a keyset list so the
    /// keyset tab has data even if the wallet file was empty.
    fn refresh_keyset_list(&self) {
        if let Some(seed) = self.master_seed.as_ref() {
            self.runtime.send(UiCommand::KeysetList {
                master_seed: seed.clone(),
                keysets_file: self.keysets_file.clone(),
            });
        }
    }

    /// Drain runtime events into UI state. Called once per frame.
    #[allow(clippy::too_many_lines)]
    fn drain_events(&mut self) {
        let mut events = Vec::new();
        self.runtime.drain_events(&mut events);
        for ev in events {
            match ev {
                UiEvent::Pong { nonce, round_trip } => {
                    self.status_line =
                        Some(format!("pong[{nonce}] in {} µs", round_trip.as_micros()));
                }
                UiEvent::WalletOpened {
                    recv_pubkey_hex,
                    master_seed,
                    coin_summary,
                    coin_total,
                    keyset_summary,
                    active_coins,
                } => {
                    self.recv_pubkey_hex = recv_pubkey_hex;
                    self.store_summary = coin_summary;
                    self.coin_total = coin_total;
                    self.master_seed = Some(master_seed);
                    self.keyset_summary = keyset_summary;
                    self.active_coins = active_coins;
                    self.mode = Mode::Unlocked;
                    self.busy = false;
                    self.status_line = Some("wallet open ✓".into());
                    // Trigger a fresh keyset list pull (the open path
                    // shipped an empty placeholder).
                    self.refresh_keyset_list();
                }
                UiEvent::Error { op, message } => {
                    self.error = Some(format!("{op}: {message}"));
                    self.busy = false;
                    self.status_line = Some(format!("{op} failed"));
                }
                UiEvent::KeysetList(list) => {
                    self.keyset_summary = list;
                }
                UiEvent::KeysetAdded { name } => {
                    self.status_line = Some(format!("keyset \"{name}\" added"));
                    self.keyset_add_name.clear();
                    self.keyset_add_joint_pk.clear();
                    self.keyset_add_denom.clear();
                    self.keyset_add_validators.clear();
                    self.keyset_add_validator_buf.clear();
                    self.busy = false;
                }
                UiEvent::KeysetRemoved { name } => {
                    self.status_line = Some(format!("keyset \"{name}\" removed"));
                    self.keyset_remove_target = None;
                    self.busy = false;
                }
                UiEvent::WithdrawOnDevnetResult {
                    coin_label,
                    denom,
                    recipient_b58,
                    tx_signature,
                    explorer_url,
                    elapsed_ms,
                    payer_strategy,
                    ephemeral_payer_b58,
                } => {
                    self.status_line = Some(format!(
                        "withdraw ✓  {coin_label} → {recipient_b58} ({elapsed_ms} ms, {payer_strategy})"
                    ));
                    self.withdraw_last_result = Some(WithdrawResult {
                        coin_label,
                        denom,
                        recipient_b58,
                        tx_signature,
                        explorer_url,
                        elapsed_ms,
                        payer_strategy,
                        ephemeral_payer_b58,
                    });
                    self.busy = false;
                }
                UiEvent::CoinRefreshed {
                    old_label,
                    new_label,
                    denom,
                    old_pubkey_prefix_hex,
                    new_pubkey_prefix_hex,
                    elapsed_ms,
                    coin_summary,
                    coin_total,
                    active_coins,
                } => {
                    self.store_summary = coin_summary;
                    self.coin_total = coin_total;
                    self.active_coins = active_coins;
                    self.refresh_selected_coin = None;
                    self.busy = false;
                    self.status_line = Some(format!(
                        "refresh ✓  ({old_pubkey_prefix_hex} → {new_pubkey_prefix_hex}) in {elapsed_ms} ms"
                    ));
                    self.refresh_last_result = Some(RefreshResult {
                        old_label,
                        new_label,
                        denom,
                        old_pubkey_prefix_hex,
                        new_pubkey_prefix_hex,
                        elapsed_ms,
                    });
                }
                UiEvent::ReceiveResult {
                    received,
                    deleted_from_relay,
                    skipped,
                    elapsed_ms,
                } => {
                    self.status_line = Some(format!(
                        "receive: {received} new, {deleted_from_relay} deleted, {skipped} skipped ({elapsed_ms} ms)"
                    ));
                    self.receive_last_summary = Some(ReceiveSummary {
                        received,
                        deleted_from_relay,
                        skipped,
                        elapsed_ms,
                    });
                    self.busy = false;
                    // Persist the relay URL so next session pre-fills.
                    self.persist_prefs();
                }
                UiEvent::PaymentSent {
                    recipient_prefix_hex,
                    denom,
                    relay_url,
                    message_id,
                    encrypted,
                    elapsed_ms,
                } => {
                    self.status_line = Some(format!(
                        "payment sent in {elapsed_ms} ms ✓"
                    ));
                    self.pay_last_receipt = Some(PaymentReceipt {
                        recipient_prefix_hex,
                        denom,
                        relay_url,
                        message_id,
                        encrypted,
                        elapsed_ms,
                    });
                    self.pay_invoice_input.clear();
                    self.busy = false;
                }
            }
        }
    }

    fn lock(&mut self) {
        // Wipe in-memory secrets / derived material before
        // transitioning back to the locked screen.
        self.mnemonic_input.clear();
        self.passphrase.clear();
        self.recv_pubkey_hex.clear();
        self.store_summary.clear();
        self.coin_total = 0;
        self.invoice_parsed = None;
        self.generated_mnemonic = None;
        // `Zeroizing<[u8; 32]>` wipes on drop.
        self.master_seed = None;
        self.keysets_file = PathBuf::new();
        self.keyset_summary.clear();
        self.keyset_add_name.clear();
        self.keyset_add_joint_pk.clear();
        self.keyset_add_denom.clear();
        self.keyset_add_validators.clear();
        self.keyset_add_validator_buf.clear();
        self.keyset_remove_target = None;
        self.pay_invoice_input.clear();
        self.pay_selected_keyset = None;
        self.pay_last_receipt = None;
        self.receive_relay_url.clear();
        self.receive_recipient_input.clear();
        self.receive_last_summary = None;
        self.active_coins.clear();
        self.refresh_selected_keyset = None;
        self.refresh_selected_coin = None;
        self.refresh_last_result = None;
        self.current_tab = Tab::default();
        self.error = None;
        self.status_line = Some("locked".into());
        self.mode = Mode::Locked;
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Pull async events first so subsequent UI render reflects them.
        self.drain_events();

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("TARDUS Wallet");
                ui.label(egui::RichText::new("v1").weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.mode == Mode::Unlocked && ui.button("Lock").clicked() {
                        self.lock();
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.busy {
                    ui.spinner();
                }
                if let Some(s) = &self.status_line {
                    ui.label(egui::RichText::new(s).weak());
                } else {
                    ui.label(egui::RichText::new("idle").weak());
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(concat!(
                            "TARDUS Wallet GUI v",
                            env!("CARGO_PKG_VERSION"),
                            " · ",
                            "TARDUS-PROPRIETARY-1.0",
                        ))
                        .weak()
                        .small(),
                    );
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.mode {
            Mode::Locked => self.ui_locked(ui),
            Mode::Unlocked => self.ui_unlocked(ui),
        });

        // Keep the UI ticking so async events arriving between
        // frames are picked up promptly. 100 ms is a comfortable
        // bound for ping roundtrip + HTTP completions.
        ctx.request_repaint_after(Duration::from_millis(100));
    }
}

impl App {
    #[allow(clippy::too_many_lines)]
    fn ui_locked(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.label("Open an existing wallet or generate a fresh mnemonic.");
        ui.separator();

        ui.heading("Unlock");
        ui.horizontal(|ui| {
            ui.label("Mnemonic:");
            ui.add(
                egui::TextEdit::singleline(&mut self.mnemonic_input)
                    .desired_width(540.0)
                    .password(true)
                    .hint_text("twelve or twenty-four BIP-39 words"),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut self.passphrase)
                    .desired_width(300.0)
                    .password(true)
                    .hint_text("optional"),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Wallet file (optional):");
            let mut s = self
                .wallet_file
                .to_string_lossy()
                .to_string();
            if ui
                .add(
                    egui::TextEdit::singleline(&mut s)
                        .desired_width(420.0)
                        .hint_text("./wallet.bin"),
                )
                .changed()
            {
                self.wallet_file = PathBuf::from(s);
            }
        });

        let unlock_clicked = ui
            .add_enabled(!self.busy, egui::Button::new("Unlock"))
            .clicked();
        if unlock_clicked {
            self.unlock_async();
        }

        if let Some(err) = &self.error {
            ui.add_space(6.0);
            ui.colored_label(theme::color::STATUS_ERROR, err);
        }

        ui.add_space(12.0);
        ui.separator();
        ui.heading("Generate a new mnemonic");
        ui.horizontal(|ui| {
            ui.label("Words:");
            ui.radio_value(&mut self.word_count, 12, "12 words");
            ui.radio_value(&mut self.word_count, 24, "24 words");
            if self.word_count == 0 {
                self.word_count = 24;
            }
            if ui.button("Generate").clicked() {
                let wc = if self.word_count == 12 {
                    WordCount::Twelve
                } else {
                    WordCount::TwentyFour
                };
                match generate_mnemonic(wc) {
                    Ok(m) => self.generated_mnemonic = Some(m.to_string()),
                    Err(e) => self.error = Some(format!("generate: {e}")),
                }
            }
        });

        if let Some(phrase) = self.generated_mnemonic.clone() {
            ui.add_space(4.0);
            ui.colored_label(
                theme::color::HIGHLIGHT,
                "⚠ Write this down OFFLINE before clicking elsewhere. \
                 Loss of this phrase = loss of all coins. Theft of this \
                 phrase = theft of all coins.",
            );
            ui.add(
                egui::TextEdit::multiline(&mut phrase.as_str())
                    .desired_rows(2)
                    .desired_width(640.0)
                    .font(egui::TextStyle::Monospace),
            );
            ui.horizontal(|ui| {
                if ui.button("📋 Copy mnemonic").clicked() {
                    ui.ctx().copy_text(phrase.clone());
                    self.status_line =
                        Some("mnemonic copied to clipboard (paste then clear)".into());
                }
                if ui.button("🧹 Clear from screen").clicked() {
                    self.generated_mnemonic = None;
                    self.status_line = Some("mnemonic cleared from screen".into());
                }
                ui.label(
                    egui::RichText::new(
                        "(clipboard is OS-managed; copy with care)",
                    )
                    .weak()
                    .italics(),
                );
            });
        }
    }

    fn ui_unlocked(&mut self, ui: &mut egui::Ui) {
        // Tab switcher
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.current_tab, Tab::Balance, "BALANCE");
            ui.selectable_value(&mut self.current_tab, Tab::Keysets, "KEYSETS");
            ui.selectable_value(&mut self.current_tab, Tab::Pay, "PAY");
            ui.selectable_value(&mut self.current_tab, Tab::Receive, "RECEIVE");
            ui.selectable_value(&mut self.current_tab, Tab::Refresh, "REFRESH");
            ui.selectable_value(&mut self.current_tab, Tab::Withdraw, "WITHDRAW");
            ui.selectable_value(&mut self.current_tab, Tab::Invoice, "INVOICE");
        });
        ui.separator();

        match self.current_tab {
            Tab::Balance => self.tab_balance(ui),
            Tab::Keysets => self.tab_keysets(ui),
            Tab::Pay => self.tab_pay(ui),
            Tab::Receive => self.tab_receive(ui),
            Tab::Refresh => self.tab_refresh(ui),
            Tab::Withdraw => self.tab_withdraw(ui),
            Tab::Invoice => self.tab_invoice(ui),
        }
    }

    fn tab_balance(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Receiving identity");
        ui.label("Share this with senders to receive payments:");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.recv_pubkey_hex.as_str())
                    .desired_width(540.0)
                    .font(egui::TextStyle::Monospace),
            );
            if ui.button("📋 Copy").clicked() {
                ui.ctx().copy_text(self.recv_pubkey_hex.clone());
                self.status_line = Some("recv pubkey copied".into());
            }
        });

        ui.add_space(10.0);
        ui.separator();
        ui.heading("Coin store");
        ui.label(format!("Total stored coins: {}", self.coin_total));

        if self.store_summary.is_empty() {
            ui.label(
                "(no coins yet — use `tardus-wallet issue` from the CLI to mint your first coin)",
            );
        } else {
            ui.add_space(4.0);
            egui::Grid::new("balance")
                .num_columns(4)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Denom (lamports)").strong());
                    ui.label(egui::RichText::new("Active").strong());
                    ui.label(egui::RichText::new("In flight").strong());
                    ui.label(egui::RichText::new("Spent").strong());
                    ui.end_row();
                    for b in &self.store_summary {
                        ui.label(format!("{}", b.denom));
                        ui.label(format!("{}", b.active));
                        ui.label(format!("{}", b.in_flight));
                        ui.label(format!("{}", b.spent));
                        ui.end_row();
                    }
                });
        }
    }

    #[allow(clippy::too_many_lines)]
    fn tab_keysets(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Keysets");
        ui.label(format!(
            "{} registered keyset(s) in {}",
            self.keyset_summary.len(),
            self.keysets_file.display()
        ));
        ui.add_space(4.0);

        // Listing
        if self.keyset_summary.is_empty() {
            ui.label("(no keysets yet — add one below)");
        } else {
            // Snapshot list to avoid double-borrow on self while
            // iterating + potentially mutating keyset_remove_target.
            let snapshot: Vec<KeysetSummary> = self.keyset_summary.clone();
            egui::Grid::new("keyset-list")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Name").strong());
                    ui.label(egui::RichText::new("Denom").strong());
                    ui.label(egui::RichText::new("joint_pk (prefix)").strong());
                    ui.label(egui::RichText::new("Validators").strong());
                    ui.label(egui::RichText::new(" ").strong());
                    ui.end_row();
                    for k in &snapshot {
                        ui.label(&k.name);
                        ui.label(format!("{}", k.denom));
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&k.joint_pk_hex[..12.min(k.joint_pk_hex.len())])
                                    .monospace(),
                            )
                            .truncate(),
                        );
                        ui.label(format!("{}", k.validators.len()));
                        let pending = self.keyset_remove_target.as_deref() == Some(&k.name);
                        let label = if pending { "Confirm remove" } else { "Remove" };
                        let btn = ui.add_enabled(!self.busy, egui::Button::new(label));
                        if btn.clicked() {
                            if pending {
                                if let Some(seed) = self.master_seed.as_ref() {
                                    self.busy = true;
                                    self.status_line =
                                        Some(format!("removing {}…", k.name));
                                    self.runtime.send(UiCommand::KeysetRemove {
                                        master_seed: seed.clone(),
                                        keysets_file: self.keysets_file.clone(),
                                        name: k.name.clone(),
                                    });
                                }
                            } else {
                                self.keyset_remove_target = Some(k.name.clone());
                            }
                        }
                        ui.end_row();
                    }
                });
            if self.keyset_remove_target.is_some() {
                ui.add_space(4.0);
                if ui.button("Cancel pending removal").clicked() {
                    self.keyset_remove_target = None;
                }
            }
        }

        ui.add_space(12.0);
        ui.separator();
        ui.heading("Add a keyset");
        egui::Grid::new("keyset-add")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label("Name:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.keyset_add_name)
                        .desired_width(380.0)
                        .hint_text("e.g. mainnet-1m"),
                );
                ui.end_row();

                ui.label("joint_pk (hex 64):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.keyset_add_joint_pk)
                        .desired_width(540.0)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("64-char hex"),
                );
                ui.end_row();

                ui.label("Denom (lamports):");
                ui.add(
                    egui::TextEdit::singleline(&mut self.keyset_add_denom)
                        .desired_width(180.0)
                        .hint_text("e.g. 1000000"),
                );
                ui.end_row();
            });

        ui.add_space(4.0);
        ui.label("Validator URLs:");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.keyset_add_validator_buf)
                    .desired_width(440.0)
                    .hint_text("https://validator1.tardus.example.com"),
            );
            if ui.button("+ add").clicked() {
                let trimmed = self.keyset_add_validator_buf.trim().to_string();
                if !trimmed.is_empty() {
                    self.keyset_add_validators.push(trimmed);
                    self.keyset_add_validator_buf.clear();
                }
            }
        });
        if !self.keyset_add_validators.is_empty() {
            ui.add_space(2.0);
            let mut remove_idx: Option<usize> = None;
            for (i, v) in self.keyset_add_validators.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("  • {v}"));
                    if ui.small_button("×").clicked() {
                        remove_idx = Some(i);
                    }
                });
            }
            if let Some(i) = remove_idx {
                self.keyset_add_validators.remove(i);
            }
        }

        ui.add_space(8.0);
        let can_submit = !self.busy
            && !self.keyset_add_name.trim().is_empty()
            && self.keyset_add_joint_pk.len() == 64
            && hex::decode(&self.keyset_add_joint_pk).is_ok()
            && self.keyset_add_denom.parse::<u64>().is_ok()
            && !self.keyset_add_validators.is_empty();
        let resp = ui.add_enabled(can_submit, egui::Button::new("Add keyset"));
        if resp.clicked() {
            if let Some(seed) = self.master_seed.as_ref() {
                if let Ok(denom) = self.keyset_add_denom.parse::<u64>() {
                    self.busy = true;
                    self.status_line = Some(format!(
                        "adding keyset \"{}\"…",
                        self.keyset_add_name
                    ));
                    self.runtime.send(UiCommand::KeysetAdd {
                        master_seed: seed.clone(),
                        keysets_file: self.keysets_file.clone(),
                        name: self.keyset_add_name.trim().to_string(),
                        joint_pk_hex: self.keyset_add_joint_pk.clone(),
                        denom,
                        validators: self.keyset_add_validators.clone(),
                        ca_cert_path: None,
                        client_cert_path: None,
                    });
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn tab_pay(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Pay an invoice");

        if self.keyset_summary.is_empty() {
            ui.colored_label(
                theme::color::HIGHLIGHT,
                "⚠ No keysets registered. Add one under the Keysets tab first.",
            );
            return;
        }

        // Auto-select first keyset if user hasn't picked one yet.
        if self.pay_selected_keyset.is_none() {
            self.pay_selected_keyset = self.keyset_summary.first().map(|k| k.name.clone());
        }

        // Keyset dropdown
        ui.horizontal(|ui| {
            ui.label("Keyset:");
            let current = self
                .pay_selected_keyset
                .clone()
                .unwrap_or_else(|| "(none)".into());
            egui::ComboBox::from_id_salt("pay-keyset-picker")
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for k in &self.keyset_summary {
                        ui.selectable_value(
                            &mut self.pay_selected_keyset,
                            Some(k.name.clone()),
                            format!("{}  (denom {})", k.name, k.denom),
                        );
                    }
                });
            if let Some(name) = &self.pay_selected_keyset {
                if let Some(k) = self.keyset_summary.iter().find(|k| k.name == *name) {
                    ui.label(
                        egui::RichText::new(format!(
                            "{} validator(s), denom {}",
                            k.validators.len(),
                            k.denom
                        ))
                        .weak(),
                    );
                }
            }
        });

        ui.add_space(6.0);
        ui.label("Invoice URI:");
        ui.add(
            egui::TextEdit::multiline(&mut self.pay_invoice_input)
                .desired_rows(2)
                .desired_width(640.0)
                .hint_text("tardus://<recipient_pubkey>?denom=<n>&relay=<url>&memo=..."),
        );

        ui.add_space(4.0);
        ui.checkbox(
            &mut self.pay_encrypt,
            "Encrypt payload (sealed-box AEAD)  ← recommended for production",
        );

        // Live invoice preview (so user sees what they're paying for)
        let parsed_preview = tardus_client::invoice::Invoice::parse(self.pay_invoice_input.trim());
        let parsed_ok = parsed_preview.is_ok();
        match &parsed_preview {
            Ok(inv) => {
                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(format!(
                        "→ to {}…  denom {}  via {} relay(s)",
                        &hex::encode(inv.recipient_pubkey)[..16],
                        inv.denom,
                        inv.relays.len()
                    ))
                    .weak(),
                );
                // Denom mismatch warning vs selected keyset
                if let Some(name) = &self.pay_selected_keyset {
                    if let Some(k) = self.keyset_summary.iter().find(|k| k.name == *name) {
                        if k.denom != inv.denom {
                            ui.colored_label(
                                theme::color::HIGHLIGHT,
                                format!(
                                    "denom mismatch: keyset = {}, invoice = {}",
                                    k.denom, inv.denom
                                ),
                            );
                        }
                    }
                }
            }
            Err(e) if self.pay_invoice_input.trim().is_empty() => {
                ui.add_space(2.0);
                ui.label(egui::RichText::new(format!("(empty: {e})")).weak());
            }
            Err(e) => {
                ui.colored_label(theme::color::STATUS_ERROR, format!("invoice parse: {e}"));
            }
        }

        ui.add_space(8.0);
        let denom_ok = parsed_preview
            .as_ref()
            .ok()
            .zip(
                self.pay_selected_keyset
                    .as_ref()
                    .and_then(|n| self.keyset_summary.iter().find(|k| &k.name == n)),
            )
            .is_some_and(|(inv, k)| inv.denom == k.denom);
        let can_pay = !self.busy
            && parsed_ok
            && denom_ok
            && self.pay_selected_keyset.is_some()
            && self.master_seed.is_some();
        let pay_btn = ui.add_enabled(can_pay, egui::Button::new("Pay"));
        if pay_btn.clicked() {
            if let (Some(seed), Some(name)) =
                (self.master_seed.as_ref(), self.pay_selected_keyset.clone())
            {
                self.busy = true;
                self.error = None;
                self.status_line = Some("paying…".into());
                self.runtime.send(UiCommand::Pay {
                    master_seed: seed.clone(),
                    keysets_file: self.keysets_file.clone(),
                    invoice_uri: self.pay_invoice_input.trim().to_string(),
                    keyset_name: name,
                    encrypt: self.pay_encrypt,
                });
            }
        }

        // Receipt panel
        if let Some(r) = self.pay_last_receipt.clone() {
            ui.add_space(12.0);
            ui.separator();
            ui.heading("Last payment receipt");
            egui::Grid::new("pay-receipt")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("recipient prefix:");
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&r.recipient_prefix_hex).monospace(),
                        )
                        .truncate(),
                    );
                    ui.end_row();
                    ui.label("denom:");
                    ui.label(format!("{}", r.denom));
                    ui.end_row();
                    ui.label("relay:");
                    ui.label(&r.relay_url);
                    ui.end_row();
                    ui.label("message id:");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&r.message_id).monospace(),
                            )
                            .truncate(),
                        );
                        if ui.small_button("📋").clicked() {
                            ui.ctx().copy_text(r.message_id.clone());
                            self.status_line = Some("message id copied".into());
                        }
                    });
                    ui.end_row();
                    ui.label("encrypted:");
                    ui.label(if r.encrypted { "yes ✓ (sealed-box)" } else { "no (plain JSON)" });
                    ui.end_row();
                    ui.label("elapsed:");
                    ui.label(format!("{} ms", r.elapsed_ms));
                    ui.end_row();
                });
        }
    }

    fn tab_receive(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Receive from relay");

        // Auto-populate fields the first time the tab is opened.
        if self.receive_recipient_input.is_empty() && !self.recv_pubkey_hex.is_empty() {
            self.receive_recipient_input = self.recv_pubkey_hex.clone();
        }

        if self.wallet_file.as_os_str().is_empty() {
            ui.colored_label(
                theme::color::HIGHLIGHT,
                "⚠ No wallet file configured. Re-open the wallet with a file path so received coins persist.",
            );
        }

        egui::Grid::new("receive-form")
            .num_columns(2)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Relay URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.receive_relay_url)
                        .desired_width(540.0)
                        .hint_text("https://relay.tardus.example.com:9799"),
                );
                ui.end_row();

                ui.label("Recipient pubkey:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.receive_recipient_input)
                        .desired_width(540.0)
                        .font(egui::TextStyle::Monospace)
                        .hint_text("64-char hex (= our receiving identity)"),
                );
                ui.end_row();

                ui.label("Label prefix:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.receive_label_prefix)
                        .desired_width(220.0)
                        .hint_text("from-relay"),
                );
                ui.end_row();
            });

        ui.add_space(2.0);
        ui.checkbox(
            &mut self.receive_keep_on_relay,
            "Keep on relay (don't DELETE after consume; TTL still applies)",
        );

        // Quick sanity: pubkey is 64 hex chars + URL non-empty + wallet file set.
        let pubkey_ok = self.receive_recipient_input.trim().len() == 64
            && hex::decode(self.receive_recipient_input.trim()).is_ok();
        let url_ok = !self.receive_relay_url.trim().is_empty();
        let wallet_ok = !self.wallet_file.as_os_str().is_empty();
        let seed_ok = self.master_seed.is_some();
        let can_receive =
            !self.busy && pubkey_ok && url_ok && wallet_ok && seed_ok;

        ui.add_space(8.0);
        let receive_btn = ui.add_enabled(can_receive, egui::Button::new("Receive"));
        if receive_btn.clicked() {
            if let Some(seed) = self.master_seed.as_ref() {
                self.busy = true;
                self.error = None;
                self.status_line = Some("receiving…".into());
                self.runtime.send(UiCommand::Receive {
                    master_seed: seed.clone(),
                    wallet_file: self.wallet_file.clone(),
                    recipient_pk_hex: self.receive_recipient_input.trim().to_string(),
                    relay_url: self.receive_relay_url.trim().to_string(),
                    keep_on_relay: self.receive_keep_on_relay,
                    label_prefix: self.receive_label_prefix.trim().to_string(),
                });
            }
        }

        if let Some(r) = &self.receive_last_summary {
            ui.add_space(12.0);
            ui.separator();
            ui.heading("Last receive result");
            egui::Grid::new("receive-result")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Received (new):");
                    ui.label(format!("{}", r.received));
                    ui.end_row();
                    ui.label("Deleted from relay:");
                    ui.label(format!("{}", r.deleted_from_relay));
                    ui.end_row();
                    ui.label("Skipped:");
                    ui.label(format!("{}", r.skipped));
                    ui.end_row();
                    ui.label("Elapsed:");
                    ui.label(format!("{} ms", r.elapsed_ms));
                    ui.end_row();
                });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Switch to the Balance tab to see newly received coins. \
                     (Wallet file is reloaded the next time you unlock.)",
                )
                .weak()
                .italics(),
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn tab_refresh(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Refresh a coin (κ-fold cut-and-choose)");

        if self.active_coins.is_empty() {
            ui.colored_label(
                theme::color::HIGHLIGHT,
                "⚠ No Active coins in the wallet. Mint or receive one first.",
            );
            return;
        }
        if self.keyset_summary.is_empty() {
            ui.colored_label(
                theme::color::HIGHLIGHT,
                "⚠ No keysets registered. Add one under the Keysets tab first.",
            );
            return;
        }

        if self.refresh_selected_keyset.is_none() {
            self.refresh_selected_keyset = self.keyset_summary.first().map(|k| k.name.clone());
        }
        if self.refresh_selected_coin.is_none() {
            self.refresh_selected_coin = self.active_coins.first().map(|c| c.label.clone());
        }

        // Keyset picker
        ui.horizontal(|ui| {
            ui.label("Keyset:");
            let current = self
                .refresh_selected_keyset
                .clone()
                .unwrap_or_else(|| "(none)".into());
            egui::ComboBox::from_id_salt("refresh-keyset-picker")
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for k in &self.keyset_summary {
                        ui.selectable_value(
                            &mut self.refresh_selected_keyset,
                            Some(k.name.clone()),
                            format!("{}  (denom {})", k.name, k.denom),
                        );
                    }
                });
        });

        // Coin picker
        ui.horizontal(|ui| {
            ui.label("Coin:");
            let current = self
                .refresh_selected_coin
                .clone()
                .unwrap_or_else(|| "(none)".into());
            egui::ComboBox::from_id_salt("refresh-coin-picker")
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for c in &self.active_coins {
                        ui.selectable_value(
                            &mut self.refresh_selected_coin,
                            Some(c.label.clone()),
                            format!("{}  (denom {}, Cp {}…)", c.label, c.denom, c.pubkey_prefix_hex),
                        );
                    }
                });
        });

        // Denom-match guard between the selected keyset and the
        // selected coin (refresh requires equal denominations).
        let denom_match = (|| -> Option<bool> {
            let kn = self.refresh_selected_keyset.as_deref()?;
            let cl = self.refresh_selected_coin.as_deref()?;
            let k = self.keyset_summary.iter().find(|k| k.name == kn)?;
            let c = self.active_coins.iter().find(|c| c.label == cl)?;
            Some(k.denom == c.denom)
        })()
        .unwrap_or(false);

        if !denom_match {
            ui.add_space(4.0);
            ui.colored_label(
                theme::color::HIGHLIGHT,
                "denom mismatch between selected keyset and coin",
            );
        }

        ui.add_space(8.0);
        let can_refresh = !self.busy
            && denom_match
            && self.master_seed.is_some()
            && !self.wallet_file.as_os_str().is_empty();
        let refresh_btn = ui.add_enabled(can_refresh, egui::Button::new("Refresh"));
        if refresh_btn.clicked() {
            if let (Some(seed), Some(keyset), Some(label)) = (
                self.master_seed.as_ref(),
                self.refresh_selected_keyset.clone(),
                self.refresh_selected_coin.clone(),
            ) {
                self.busy = true;
                self.error = None;
                self.status_line = Some(format!("refreshing {label}…"));
                self.runtime.send(UiCommand::Refresh {
                    master_seed: seed.clone(),
                    wallet_file: self.wallet_file.clone(),
                    keysets_file: self.keysets_file.clone(),
                    keyset_name: keyset,
                    coin_label: label,
                });
            }
        }

        if let Some(r) = &self.refresh_last_result {
            ui.add_space(12.0);
            ui.separator();
            ui.heading("Last refresh result");
            egui::Grid::new("refresh-result")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("Old label:");
                    ui.label(r.old_label.clone().unwrap_or_else(|| "(unlabeled)".into()));
                    ui.end_row();
                    ui.label("New label:");
                    ui.label(&r.new_label);
                    ui.end_row();
                    ui.label("Denom:");
                    ui.label(format!("{}", r.denom));
                    ui.end_row();
                    ui.label("Old Cp prefix:");
                    ui.label(
                        egui::RichText::new(&r.old_pubkey_prefix_hex)
                            .monospace()
                            .color(theme::color::FG_SOFT),
                    );
                    ui.end_row();
                    ui.label("New Cp prefix:");
                    ui.label(
                        egui::RichText::new(&r.new_pubkey_prefix_hex)
                            .monospace()
                            .color(theme::color::STATUS_OK),
                    );
                    ui.end_row();
                    ui.label("Elapsed:");
                    ui.label(format!("{} ms", r.elapsed_ms));
                    ui.end_row();
                });
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Old Cp != New Cp = unlinkability (T4 cut-and-choose soundness).",
                )
                .weak()
                .italics(),
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn tab_withdraw(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Withdraw — convert coin to real SOL on devnet");
        ui.label(
            egui::RichText::new(
                "Faz 9.6: GUI submits the TX directly via solana-client. \
                 Your Solana wallet keypair (default ~/.config/solana/id.json) \
                 signs + pays the TX fee.",
            )
            .weak()
            .italics(),
        );
        ui.separator();

        if self.active_coins.is_empty() {
            ui.colored_label(
                theme::color::HIGHLIGHT,
                "⚠ No Active coins. Mint via Pay / Receive first.",
            );
            return;
        }

        if self.withdraw_selected_coin.is_none() {
            self.withdraw_selected_coin = self.active_coins.first().map(|c| c.label.clone());
        }

        // Coin picker
        ui.horizontal(|ui| {
            ui.label("Coin:");
            let current = self
                .withdraw_selected_coin
                .clone()
                .unwrap_or_else(|| "(none)".into());
            egui::ComboBox::from_id_salt("withdraw-coin-picker")
                .selected_text(current)
                .show_ui(ui, |ui| {
                    for c in &self.active_coins {
                        ui.selectable_value(
                            &mut self.withdraw_selected_coin,
                            Some(c.label.clone()),
                            format!("{}  (denom {}, Cp {}…)", c.label, c.denom, c.pubkey_prefix_hex),
                        );
                    }
                });
        });

        // Recipient input
        ui.horizontal(|ui| {
            ui.label("Recipient (Solana pubkey, base58):");
            ui.add(
                egui::TextEdit::singleline(&mut self.withdraw_recipient_input)
                    .desired_width(420.0)
                    .font(egui::TextStyle::Monospace)
                    .hint_text("e.g. 6d9bccB2hPNq6Loq2ZgEVuHECPufVnsFVfAWRqg7gKKa"),
            );
        });

        // Selected coin info (need full Cp + signature for the CLI command)
        let selected = self
            .withdraw_selected_coin
            .as_ref()
            .and_then(|n| self.active_coins.iter().find(|c| &c.label == n));

        ui.add_space(8.0);
        let can_prepare = selected.is_some()
            && !self.withdraw_recipient_input.trim().is_empty()
            && self.withdraw_recipient_input.trim().len() >= 32
            && self.withdraw_recipient_input.trim().len() <= 44;

        if let Some(coin) = selected {
            ui.add_space(4.0);
            #[allow(clippy::cast_precision_loss)]
            let sol = (coin.denom as f64) / 1e9;
            ui.label(
                egui::RichText::new(format!(
                    "Will withdraw {} lamports ({sol:.9} SOL) to the recipient.",
                    coin.denom
                ))
                .strong(),
            );
        }

        // **Faz 9.6**: ops config (RPC / program / keypair). Defaults
        // pre-fill devnet + standard Solana keypair path.
        ui.add_space(8.0);
        ui.separator();
        ui.heading("Devnet submission");
        egui::Grid::new("withdraw-config")
            .num_columns(2)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.label("RPC URL:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.withdraw_rpc_input)
                        .desired_width(420.0),
                );
                ui.end_row();
                ui.label("Program ID:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.withdraw_program_id_input)
                        .desired_width(420.0)
                        .font(egui::TextStyle::Monospace),
                );
                ui.end_row();
                ui.label("Solana keypair path:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.withdraw_keypair_path_input)
                        .desired_width(420.0),
                );
                ui.end_row();
            });

        // **v2.13.2** privacy stack toggles
        ui.add_space(8.0);
        ui.separator();
        ui.heading("Privacy options (Faz 9 stack)");
        ui.checkbox(
            &mut self.withdraw_use_ephemeral_payer,
            "Use ephemeral payer (Faz 9.1) — fresh signer per TX, sponsor only funds it",
        );
        ui.add_enabled_ui(self.withdraw_use_ephemeral_payer, |ui| {
            ui.checkbox(
                &mut self.withdraw_use_onchain_pool,
                "  └ Fund ephemeral from on-chain SponsorPool (Faz 9.4) — commingled source",
            );
        });
        if !self.withdraw_use_ephemeral_payer {
            self.withdraw_use_onchain_pool = false;
        }

        ui.add_space(8.0);
        let can_submit = !self.busy
            && can_prepare
            && self.master_seed.is_some()
            && !self.wallet_file.as_os_str().is_empty();
        let btn = ui.add_enabled(can_submit, egui::Button::new("Submit Withdraw TX"));
        if btn.clicked() {
            if let (Some(seed), Some(coin)) = (self.master_seed.as_ref(), selected) {
                self.busy = true;
                self.error = None;
                self.status_line = Some(format!("withdrawing {coin_label}…",
                    coin_label = coin.label));
                self.runtime.send(UiCommand::WithdrawOnDevnet {
                    master_seed: seed.clone(),
                    wallet_file: self.wallet_file.clone(),
                    coin_label: coin.label.clone(),
                    recipient_b58: self.withdraw_recipient_input.trim().to_string(),
                    rpc_url: self.withdraw_rpc_input.trim().to_string(),
                    program_id_b58: self.withdraw_program_id_input.trim().to_string(),
                    solana_keypair_path: self.withdraw_keypair_path_input.trim().to_string(),
                    use_ephemeral_payer: self.withdraw_use_ephemeral_payer,
                    use_onchain_pool: self.withdraw_use_onchain_pool,
                });
            }
        }

        if let Some(r) = self.withdraw_last_result.clone() {
            ui.add_space(12.0);
            ui.separator();
            ui.heading("Last withdraw result");
            egui::Grid::new("withdraw-result")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label("coin label:");
                    ui.label(&r.coin_label);
                    ui.end_row();
                    ui.label("denom:");
                    ui.label(format!("{}", r.denom));
                    ui.end_row();
                    ui.label("recipient:");
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(&r.recipient_b58).monospace(),
                        )
                        .truncate(),
                    );
                    ui.end_row();
                    ui.label("tx signature:");
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&r.tx_signature).monospace(),
                            )
                            .truncate(),
                        );
                        if ui.small_button("📋").clicked() {
                            ui.ctx().copy_text(r.tx_signature.clone());
                            self.status_line = Some("tx signature copied".into());
                        }
                    });
                    ui.end_row();
                    ui.label("explorer:");
                    ui.hyperlink(&r.explorer_url);
                    ui.end_row();
                    ui.label("payer strategy:");
                    ui.label(
                        egui::RichText::new(&r.payer_strategy)
                            .color(match r.payer_strategy.as_str() {
                                "sponsor-direct" => theme::color::HIGHLIGHT,
                                "ephemeral-from-sponsor" => theme::color::STATUS_OK,
                                "ephemeral-from-pool" => theme::color::ACCENT,
                                _ => theme::color::FG,
                            }),
                    );
                    ui.end_row();
                    if let Some(eph) = r.ephemeral_payer_b58.clone() {
                        ui.label("ephemeral signer:");
                        ui.add(
                            egui::Label::new(egui::RichText::new(&eph).monospace())
                                .truncate(),
                        );
                        ui.end_row();
                    }
                    ui.label("elapsed:");
                    ui.label(format!("{} ms", r.elapsed_ms));
                    ui.end_row();
                });
        }
    }

    fn tab_invoice(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.heading("Invoice viewer");
        ui.label("Paste a `tardus://` URI to inspect it before paying:");
        ui.add(
            egui::TextEdit::multiline(&mut self.invoice_uri_input)
                .desired_rows(2)
                .desired_width(640.0)
                .hint_text("tardus://<recipient_pubkey>?denom=<n>&relay=<url>&memo=..."),
        );
        if ui.button("Parse").clicked() {
            self.invoice_parsed = Some(match tardus_client::invoice::Invoice::parse(
                self.invoice_uri_input.trim(),
            ) {
                Ok(inv) => format!(
                    "{{\n  \"recipient_pubkey\": \"{}\",\n  \"denom\": {},\n  \"relays\": {},\n  \"memo\": {}\n}}",
                    hex::encode(inv.recipient_pubkey),
                    inv.denom,
                    serde_json::to_string(&inv.relays).unwrap_or_default(),
                    inv.memo
                        .and_then(|m| String::from_utf8(m).ok())
                        .map_or_else(|| "null".to_string(), |m| format!("{m:?}")),
                ),
                Err(e) => format!("parse error: {e}"),
            });
        }
        if let Some(parsed) = &self.invoice_parsed {
            ui.add_space(6.0);
            ui.add(
                egui::TextEdit::multiline(&mut parsed.as_str())
                    .desired_rows(8)
                    .desired_width(640.0)
                    .font(egui::TextStyle::Monospace),
            );
        }

        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "v1 scaffold: pay / receive / refresh flows still CLI-only in Faz 8.2. \
                 Faz 8.3+ wires them into the GUI.",
            )
            .weak()
            .italics(),
        );
    }
}
