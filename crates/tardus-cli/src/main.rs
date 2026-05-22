//! TARDUS CLI binary.
//!
//! Subcommand surface (v1):
//!
//! ```text
//! tardus invoice make --pubkey <hex32> --denom <lamports>
//!                     [--relay <url>]+ [--memo <text>]
//! tardus invoice parse <uri>
//! tardus coin verify  --coin <hex> --joint-pk <hex32>
//! tardus demo dkg-sim --n <N> --t <T>
//! tardus demo lifecycle-sim
//! ```

#![allow(clippy::doc_markdown)]

use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(
    name = "tardus",
    version,
    about = "TARDUS protocol CLI tools",
    long_about = "Command-line tools for working with the TARDUS protocol: invoice URI \
                  manipulation, coin verification, and protocol simulation."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Invoice URI utilities (encode / decode).
    Invoice {
        #[command(subcommand)]
        action: InvoiceAction,
    },
    /// Coin operations (verify, inspect).
    Coin {
        #[command(subcommand)]
        action: CoinAction,
    },
    /// Protocol simulation and demonstration.
    Demo {
        #[command(subcommand)]
        action: DemoAction,
    },
    /// Devnet / mainnet on-chain operations.
    Devnet {
        #[command(subcommand)]
        action: DevnetAction,
    },
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
        /// The URI string to parse.
        uri: String,
    },
}

#[derive(Subcommand)]
enum CoinAction {
    /// Verify a coin's signature against a joint public key.
    /// Coin format: `secret_hex32 || pubkey_hex32 || signature_hex64`.
    Verify {
        /// Coin payload as 128-char hex (secret || pubkey || signature).
        #[arg(long)]
        coin: String,
        /// Joint public key as 64-char hex.
        #[arg(long = "joint-pk")]
        joint_pk: String,
    },
}

#[derive(Subcommand)]
enum DemoAction {
    /// Simulate a complete DKG ceremony and print the joint public key.
    DkgSim {
        /// Number of validators.
        #[arg(long, default_value = "4")]
        n: u16,
        /// Threshold.
        #[arg(long, default_value = "3")]
        t: u16,
    },
    /// Full SDK lifecycle: DKG → issue coin → refresh → verify. Prints JSON summary.
    LifecycleSim,
    /// Generate a fresh single-mint keypair and issue one coin, ready for
    /// devnet test flow. Prints JSON with mint_pk, coin_pk, coin_signature.
    /// Bypasses threshold DKG — use only for testing.
    IssueCoin,
}

#[derive(Subcommand)]
enum DevnetAction {
    /// Show program account info + on-chain registry contents.
    Info {
        /// Program ID (base58).
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        /// RPC endpoint.
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// Bootstrap the singleton PDAs (registry + nullifier tree) for a fresh deployment.
    /// Idempotent — re-runs skip if accounts already exist.
    BootstrapSingletons {
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// Query whether a coin's nullifier has been inserted on-chain.
    QueryNullifier {
        /// Coin's public commitment Cp as 64-char hex.
        #[arg(long)]
        coin_pubkey: String,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// Bootstrap the vault PDA for a specific denomination.
    BootstrapVault {
        /// Denomination in lamports (or token base units).
        #[arg(long)]
        denom: u64,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// Register a new keyset (joint_pk + denom) into the on-chain registry.
    RegisterKeyset {
        /// Joint public key as 64-char hex.
        #[arg(long)]
        joint_pk: String,
        /// Denomination in lamports.
        #[arg(long)]
        denom: u64,
        /// Epoch number (default 1).
        #[arg(long, default_value = "1")]
        epoch: u64,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **Faz G-mini** — Resize the on-chain registry / nullifier-tree
    /// to a larger byte allocation. Required when the 1024-byte
    /// initial allocation fills (caps ~11 keysets). Caller pays
    /// the rent top-up via a paired System::Transfer inside the
    /// same TX.
    ResizeRegistry {
        /// New allocation size in bytes (cap 64 KiB).
        #[arg(long, default_value = "8192")]
        new_size: u32,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **Faz G** — Resize the on-chain nullifier-tree PDA. The
    /// initial 8 KiB allocation caps at ~250 spent coins; bump to
    /// 64 KiB for ~2000, 256 KiB for ~8000. Mainnet long-term
    /// solution is Light Protocol compressed-merkle-tree
    /// (deferred to v1.5 — see deploy/runbooks/light-protocol-integration-design.md).
    ResizeNullifierTree {
        /// New allocation size in bytes (cap 64 KiB on a single tx;
        /// for larger jumps, multiple sequential resizes).
        #[arg(long, default_value = "65536")]
        new_size: u32,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **Faz G** — Print on-chain capacity report: registry used /
    /// total, nullifier-tree used / total, sponsor pool balance,
    /// vault PDAs (lamports per denom).
    Capacity {
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **Faz E** — Submit a Withdraw TX: ed25519 precompile +
    /// tardus::Withdraw releases `denom` lamports from the vault
    /// PDA to `recipient`. This is the "Bob gets real SOL"
    /// economic-loop counterpart of Refresh.
    Withdraw {
        /// Coin's public commitment Cp as 64-char hex.
        #[arg(long)]
        coin_pubkey: String,
        /// Coin's mint signature as 128-char hex (R || s).
        #[arg(long)]
        coin_signature: String,
        /// Denomination of the surrendered coin.
        #[arg(long)]
        denom: u64,
        /// Recipient pubkey (base58) — wallet that receives the SOL.
        #[arg(long)]
        recipient: String,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **Faz E** — End-to-end "Alice pays Bob and Bob withdraws to
    /// real SOL". Full economic loop: deposit → mint → P2P deliver
    /// → withdraw to fresh recipient wallet.
    AlicePaysBobAndBobWithdraws {
        /// Denomination for the demo keyset (must be fresh on devnet).
        #[arg(long, default_value = "1000000")]
        denom: u64,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
        /// **v2.13.2 GUI parity** — sign the Withdraw TX with a
        /// fresh ephemeral keypair (Faz 9.1) instead of the deployer
        /// wallet. The deployer becomes just the funder.
        #[arg(long)]
        use_ephemeral_payer: bool,
        /// **Faz 9.4 GUI parity** — when `--use-ephemeral-payer` is
        /// set, fund the ephemeral from the on-chain `SponsorPool`
        /// (commingled source) instead of a direct deployer→ephemeral
        /// transfer. Requires a non-empty SponsorPool PDA balance.
        #[arg(long)]
        use_onchain_pool: bool,
    },
    /// **v1.4.13 / Faz 9.3** — Bootstrap the on-chain SponsorPool PDA
    /// (one-shot, idempotent). Required before SponsorDeposit /
    /// SponsorPayout work.
    SponsorBootstrap {
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **v1.4.13 / Faz 9.3** — Deposit SOL into the on-chain
    /// SponsorPool. Anyone can deposit; the pool is community-funded.
    SponsorDeposit {
        /// Deposit amount in lamports.
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **v1.4.13 / Faz 9.3** — Drain `lamports` from the on-chain
    /// SponsorPool to `recipient`. Rate-limited to 1 payout per 5
    /// slots across all callers.
    SponsorPayout {
        /// Payout in lamports (capped by pool balance).
        #[arg(long)]
        lamports: u64,
        /// Recipient pubkey (base58).
        #[arg(long)]
        recipient: String,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// **TRUE Alice→Bob private payment**, end-to-end with on-chain
    /// settlement. Spawns Alice's mint (3 local validators + DKG),
    /// spawns a local relay, generates two independent BIP-39
    /// identities, registers the keyset on devnet, Alice mints +
    /// seals to Bob's pubkey, posts to relay; Bob fetches from
    /// relay + decrypts + refreshes via the validators; Bob's
    /// refresh nullifier is committed to devnet.
    ///
    /// Two devnet TXs are produced; the second (Bob's Refresh) is
    /// the **private TX** — observers see the nullifier of Alice's
    /// coin land on chain, but cannot link it to Alice or Bob.
    AlicePaysBobOnDevnet {
        /// Denomination for the demo keyset (must be fresh on devnet).
        #[arg(long, default_value = "8888")]
        denom: u64,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
        /// Faz 9.2: comma- or colon-separated list of sponsor
        /// keypair file paths. Per-TX random selection breaks
        /// the same-source-many-TXs correlation. Empty = default
        /// keypair (single sponsor, v9.1 behavior).
        #[arg(long, default_value = "")]
        sponsor_pool: String,
        /// **Faz 9.4** — Fund the ephemeral payer from the on-chain
        /// SponsorPool (commingled, multi-depositor) instead of
        /// from a single sponsor wallet. Requires the pool to be
        /// bootstrapped + funded (`tardus devnet sponsor-bootstrap`
        /// + `tardus devnet sponsor-deposit`).
        #[arg(long, default_value = "false")]
        use_onchain_pool: bool,
    },
    /// End-to-end private-TX demo: spawn 3 local validators, run
    /// DKG, register the keyset on devnet, mint a coin off-chain,
    /// then submit a private Refresh TX. Prints the Solana Explorer
    /// URL of the resulting nullifier insertion.
    PrivateTxDemo {
        /// Denomination for the demo keyset (must be fresh / unused on devnet).
        #[arg(long, default_value = "7777")]
        denom: u64,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
    /// Submit a Refresh TX: ed25519 precompile + tardus::Refresh,
    /// nullifying an existing coin on-chain.
    Refresh {
        /// Coin's public commitment Cp as 64-char hex.
        #[arg(long)]
        coin_pubkey: String,
        /// Coin's mint signature as 128-char hex (R || s).
        #[arg(long)]
        coin_signature: String,
        /// Denomination of the surrendered coin.
        #[arg(long)]
        denom: u64,
        #[arg(long, default_value = "AmY1ysgQyCC6CmorXkrNkogBSHmomy4kbsPziAYUx47u")]
        program_id: String,
        #[arg(long, default_value = "https://api.devnet.solana.com")]
        rpc: String,
    },
}

#[allow(clippy::too_many_lines)]
fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Invoice { action } => match action {
            InvoiceAction::Make {
                pubkey,
                denom,
                relay,
                memo,
            } => commands::invoice::make(&pubkey, denom, relay, memo),
            InvoiceAction::Parse { uri } => commands::invoice::parse(&uri),
        },
        Command::Coin { action } => match action {
            CoinAction::Verify { coin, joint_pk } => commands::coin::verify(&coin, &joint_pk),
        },
        Command::Demo { action } => match action {
            DemoAction::DkgSim { n, t } => commands::demo::dkg_sim(n, t),
            DemoAction::LifecycleSim => commands::demo::lifecycle_sim(),
            DemoAction::IssueCoin => commands::demo::issue_coin_demo(),
        },
        Command::Devnet { action } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime");
            rt.block_on(async {
                match action {
                    DevnetAction::Info { program_id, rpc } => {
                        commands::devnet::info(&program_id, &rpc).await
                    }
                    DevnetAction::BootstrapSingletons { program_id, rpc } => {
                        commands::devnet::bootstrap_singletons(&program_id, &rpc).await
                    }
                    DevnetAction::QueryNullifier {
                        coin_pubkey,
                        program_id,
                        rpc,
                    } => commands::devnet::query_nullifier(&coin_pubkey, &program_id, &rpc).await,
                    DevnetAction::BootstrapVault {
                        denom,
                        program_id,
                        rpc,
                    } => commands::devnet::bootstrap_vault(denom, &program_id, &rpc).await,
                    DevnetAction::RegisterKeyset {
                        joint_pk,
                        denom,
                        epoch,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::register_keyset(
                            &joint_pk,
                            denom,
                            epoch,
                            &program_id,
                            &rpc,
                        )
                        .await
                    }
                    DevnetAction::Refresh {
                        coin_pubkey,
                        coin_signature,
                        denom,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::refresh(
                            &coin_pubkey,
                            &coin_signature,
                            denom,
                            &program_id,
                            &rpc,
                        )
                        .await
                    }
                    DevnetAction::PrivateTxDemo {
                        denom,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::private_tx_demo(denom, &program_id, &rpc).await
                    }
                    DevnetAction::ResizeRegistry {
                        new_size,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::resize_registry(new_size, &program_id, &rpc)
                            .await
                    }
                    DevnetAction::ResizeNullifierTree {
                        new_size,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::resize_nullifier_tree(
                            new_size,
                            &program_id,
                            &rpc,
                        )
                        .await
                    }
                    DevnetAction::Capacity { program_id, rpc } => {
                        commands::devnet::capacity(&program_id, &rpc).await
                    }
                    DevnetAction::Withdraw {
                        coin_pubkey,
                        coin_signature,
                        denom,
                        recipient,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::withdraw(
                            &coin_pubkey,
                            &coin_signature,
                            denom,
                            &recipient,
                            &program_id,
                            &rpc,
                            false, // use_ephemeral_payer
                            false, // use_onchain_pool
                        )
                        .await
                    }
                    DevnetAction::AlicePaysBobAndBobWithdraws {
                        denom,
                        program_id,
                        rpc,
                        use_ephemeral_payer,
                        use_onchain_pool,
                    } => {
                        commands::devnet::alice_pays_bob_and_bob_withdraws(
                            denom,
                            &program_id,
                            &rpc,
                            use_ephemeral_payer,
                            use_onchain_pool,
                        )
                        .await
                    }
                    DevnetAction::SponsorBootstrap { program_id, rpc } => {
                        commands::devnet::sponsor_bootstrap(&program_id, &rpc).await
                    }
                    DevnetAction::SponsorDeposit {
                        amount,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::sponsor_deposit(amount, &program_id, &rpc).await
                    }
                    DevnetAction::SponsorPayout {
                        lamports,
                        recipient,
                        program_id,
                        rpc,
                    } => {
                        commands::devnet::sponsor_payout(
                            lamports,
                            &recipient,
                            &program_id,
                            &rpc,
                        )
                        .await
                    }
                    DevnetAction::AlicePaysBobOnDevnet {
                        denom,
                        program_id,
                        rpc,
                        sponsor_pool,
                        use_onchain_pool,
                    } => {
                        commands::devnet::alice_pays_bob_on_devnet(
                            denom,
                            &program_id,
                            &rpc,
                            &sponsor_pool,
                            use_onchain_pool,
                        )
                        .await
                    }
                }
            })
        }
    };
    if let Err(e) = result {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}
