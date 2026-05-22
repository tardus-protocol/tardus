//! Deterministic cross-language test vector generator.
//!
//! Produces hex vectors that the TypeScript SDK (`ts-sdk/test/
//! rust-cross-language.test.ts`) reproduces bit-equal:
//!
//!   1. master_seed   (32 B) derived from canonical BIP-39
//!      mnemonic "abandon abandon ... about".
//!   2. recv_sk       (32 B canonical Ed25519 scalar).
//!   3. recv_pk       (32 B Edwards-compressed pubkey).
//!   4. sealed_box    (Vec<u8>, the wire bytes Rust produced
//!      when sealing a known plaintext to recv_pk; ephemeral
//!      key is random per run, so this vector is one specific
//!      sample — the TS test decrypts it to assert
//!      wire-format compatibility).
//!   5. plaintext     (the known plaintext that sealed_box should
//!      decrypt to).
//!
//! Run with:
//! ```sh
//! cargo run -p tardus-wallet --example cross_language_vectors --release
//! ```
//!
//! Copy the printed JSON into
//! `ts-sdk/test/rust-cross-language.test.ts::RUST_VECTORS`.

#![allow(
    clippy::doc_markdown,
    clippy::similar_names,
    clippy::format_collect
)]

use tardus_wallet::{derive_master_seed, derive_receiving_keypair, parse_mnemonic, sealed_box};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let phrase = parse_mnemonic(
        "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about",
    )
    .expect("canonical BIP-39 mnemonic");
    let master_seed = derive_master_seed(&phrase, "");
    let (recv_sk, recv_pk) = derive_receiving_keypair(&master_seed);

    let plaintext = b"tardus cross-language test vector v1";
    let sealed = sealed_box::seal(plaintext, &recv_pk).expect("seal");

    println!("{{");
    println!(
        "  \"mnemonic\": \"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\","
    );
    println!("  \"master_seed_hex\":  \"{}\",", hex(master_seed.as_ref()));
    println!("  \"recv_sk_hex\":      \"{}\",", hex(recv_sk.as_ref()));
    println!("  \"recv_pk_hex\":      \"{}\",", hex(&recv_pk));
    println!("  \"plaintext_hex\":    \"{}\",", hex(plaintext));
    println!("  \"sealed_box_hex\":   \"{}\"", hex(&sealed));
    println!("}}");
}
