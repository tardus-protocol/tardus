//! Per-host config persistence (Faz 8.6).
//!
//! Stores only non-secret user preferences — wallet file paths,
//! keysets file path, last-used relay URL, mnemonic word-count
//! preference. **Never** writes secret material to disk.
//!
//! Lives at `~/.config/tardus-wallet-gui/config.toml` (Linux),
//! `~/Library/Application Support/.../config.toml` (macOS),
//! `%APPDATA%\tardus-wallet-gui\config.toml` (Windows) via the
//! `directories` crate's `ProjectDirs`.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Things we remember between runs. Pure preferences — no secrets.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[allow(clippy::struct_field_names)] // `last_*` prefix is intentional taxonomy
pub struct Config {
    /// Last wallet file used (auto-fills the Locked-screen field).
    pub last_wallet_file: PathBuf,
    /// Last keysets file used (defaults to `<wallet_dir>/keysets.bin`
    /// when empty, see [`crate::App::resolved_keysets_file`]).
    pub last_keysets_file: PathBuf,
    /// Last relay URL used in the Receive tab.
    pub last_relay_url: String,
    /// Mnemonic word-count preference (12 or 24).
    pub last_word_count: u8,
}

impl Config {
    /// Resolve the config-file path under the user's standard config
    /// dir. Returns `None` only on platforms where `ProjectDirs`
    /// cannot determine a home directory (rare; e.g. minimal CI
    /// containers).
    #[must_use]
    pub fn path() -> Option<PathBuf> {
        let pd = directories::ProjectDirs::from("dev", "tardus", "tardus-wallet-gui")?;
        Some(pd.config_dir().join("config.toml"))
    }

    /// Load from disk. On any failure (missing file, bad TOML,
    /// permission error) returns `Config::default()` and logs a
    /// warning — the user shouldn't be blocked from launching the
    /// wallet by config-file corruption.
    #[must_use]
    pub fn load() -> Self {
        let Some(path) = Self::path() else {
            return Self::default();
        };
        let Ok(s) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match toml::from_str::<Self>(&s) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "config load: TOML decode failed, falling back to defaults"
                );
                Self::default()
            }
        }
    }

    /// Save to disk. Best-effort: failures are logged but not
    /// propagated (the user's session works fine without persistent
    /// config; we just won't remember next time).
    pub fn save(&self) {
        let Some(path) = Self::path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!(
                    path = %parent.display(),
                    error = %e,
                    "config save: create_dir_all failed"
                );
                return;
            }
        }
        match toml::to_string_pretty(self) {
            Ok(s) => {
                if let Err(e) = std::fs::write(&path, s) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "config save: write failed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "config save: TOML encode failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let c = Config::default();
        assert!(c.last_wallet_file.as_os_str().is_empty());
        assert!(c.last_keysets_file.as_os_str().is_empty());
        assert!(c.last_relay_url.is_empty());
        assert_eq!(c.last_word_count, 0);
    }

    #[test]
    fn toml_roundtrip() {
        let c = Config {
            last_wallet_file: PathBuf::from("/tmp/wallet.bin"),
            last_keysets_file: PathBuf::from("/tmp/keysets.bin"),
            last_relay_url: "https://relay.example.com:9799".into(),
            last_word_count: 24,
        };
        let s = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.last_wallet_file, c.last_wallet_file);
        assert_eq!(back.last_relay_url, c.last_relay_url);
        assert_eq!(back.last_word_count, c.last_word_count);
    }

    #[test]
    fn missing_fields_use_default() {
        // Older config without `last_word_count` should not break.
        let partial = r#"
            last_wallet_file = "/tmp/wallet.bin"
            last_relay_url = "https://relay.example.com"
        "#;
        let c: Config = toml::from_str(partial).unwrap();
        assert_eq!(c.last_wallet_file, PathBuf::from("/tmp/wallet.bin"));
        assert_eq!(c.last_word_count, 0);
        assert!(c.last_keysets_file.as_os_str().is_empty());
    }
}
