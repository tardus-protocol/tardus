//! `tardus invoice` subcommand: encode / decode `tardus://` URIs.

use anyhow::{anyhow, Context, Result};
use tardus_client::invoice::{Invoice, MEMO_MAX_BYTES};

pub fn make(pubkey_hex: &str, denom: u64, relays: Vec<String>, memo: Option<String>) -> Result<()> {
    let pubkey = decode_hex_32(pubkey_hex).context("invalid --pubkey")?;
    if let Some(m) = &memo {
        if m.len() > MEMO_MAX_BYTES {
            return Err(anyhow!(
                "--memo exceeds {} bytes ({})",
                MEMO_MAX_BYTES,
                m.len()
            ));
        }
    }
    let inv = Invoice {
        recipient_pubkey: pubkey,
        denom,
        relays,
        memo: memo.map(String::into_bytes),
    };
    println!("{}", inv.to_uri());
    Ok(())
}

pub fn parse(uri: &str) -> Result<()> {
    let inv = Invoice::parse(uri).map_err(|e| anyhow!("parse failure: {e}"))?;
    // Hand-rolled JSON to avoid pulling serde_json into the binary.
    println!("{{");
    println!(
        "  \"recipient_pubkey\": \"{}\",",
        hex::encode(inv.recipient_pubkey)
    );
    println!("  \"denom\": {},", inv.denom);
    print!("  \"relays\": [");
    for (i, r) in inv.relays.iter().enumerate() {
        if i > 0 {
            print!(",");
        }
        print!("{r:?}");
    }
    println!("],");
    match &inv.memo {
        None => println!("  \"memo\": null"),
        Some(m) => match core::str::from_utf8(m) {
            Ok(s) => println!("  \"memo\": {s:?}"),
            Err(_) => println!("  \"memo_hex\": \"{}\"", hex::encode(m)),
        },
    }
    println!("}}");
    Ok(())
}

fn decode_hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).context("not valid hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
