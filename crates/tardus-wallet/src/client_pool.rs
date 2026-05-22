//! Pool of HTTPS clients, one per validator endpoint.
//!
//! Each `ValidatorEndpoint` holds the validator's index, base URL,
//! and a pre-built `reqwest::Client` configured with the appropriate
//! TLS roots. For mTLS deployments the same builder accepts a client
//! `Identity`.

use crate::error::{Error, Result};
use std::time::Duration;

/// One validator's connection parameters.
#[derive(Clone)]
pub struct ValidatorEndpoint {
    pub my_index: u16,
    pub base_url: String,
    client: reqwest::Client,
}

impl ValidatorEndpoint {
    /// Build a plain-HTTP endpoint. Use only for testing.
    ///
    /// # Errors
    /// Returns `Error::Http` if the underlying reqwest client fails to build.
    pub fn plain(my_index: u16, base_url: impl Into<String>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            my_index,
            base_url: base_url.into(),
            client,
        })
    }

    /// Build a TLS endpoint pinned to a specific CA PEM. Use this in
    /// production with the org-wide root CA.
    ///
    /// # Errors
    /// - `Error::Http` if the cert fails to parse or the client build fails.
    pub fn tls(
        my_index: u16,
        base_url: impl Into<String>,
        ca_pem: &[u8],
    ) -> Result<Self> {
        let cert = reqwest::Certificate::from_pem(ca_pem)?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            my_index,
            base_url: base_url.into(),
            client,
        })
    }

    /// Build an mTLS endpoint with both server CA and client identity.
    ///
    /// `client_pem_bundle` must contain both the client cert and its
    /// private key, concatenated as PEM (the format reqwest's
    /// `Identity::from_pem` expects).
    ///
    /// # Errors
    /// - `Error::Http` on cert/identity/build failure.
    pub fn mtls(
        my_index: u16,
        base_url: impl Into<String>,
        ca_pem: &[u8],
        client_pem_bundle: &[u8],
    ) -> Result<Self> {
        let cert = reqwest::Certificate::from_pem(ca_pem)?;
        let identity = reqwest::Identity::from_pem(client_pem_bundle)?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(cert)
            .identity(identity)
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Self {
            my_index,
            base_url: base_url.into(),
            client,
        })
    }

    /// POST a JSON body to `path`, return the JSON response decoded as `R`.
    pub(crate) async fn post<B, R>(&self, path: &str, body: &B) -> Result<R>
    where
        B: serde::Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let url = format!("{}{path}", self.base_url);
        let resp = self.client.post(&url).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::ValidatorRejected {
                status: status.as_u16(),
                body: text,
            });
        }
        Ok(resp.json::<R>().await?)
    }
}

/// A pool over `n` validator endpoints. Read-only after construction.
#[derive(Clone)]
pub struct WalletClientPool {
    endpoints: Vec<ValidatorEndpoint>,
}

impl WalletClientPool {
    /// # Errors
    /// `Error::BadLength` if the slice is empty.
    pub fn new(endpoints: Vec<ValidatorEndpoint>) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(Error::BadLength {
                label: "endpoints",
                expected: 1,
                got: 0,
            });
        }
        Ok(Self { endpoints })
    }

    #[must_use]
    pub fn endpoints(&self) -> &[ValidatorEndpoint] {
        &self.endpoints
    }

    #[must_use]
    pub fn signing_set(&self) -> Vec<u16> {
        self.endpoints.iter().map(|e| e.my_index).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }
}
