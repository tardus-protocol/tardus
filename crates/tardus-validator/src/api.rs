//! HTTP API surface for the validator daemon.
//!
//! v2.1: read-only operator endpoints (health, info, version). v2.2
//! will add user-facing ceremony endpoints (issue, refresh) and the
//! inter-validator coordination endpoints.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use borsh::BorshDeserialize;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tardus_core::{BlindChallenge, SecretKey, Signature};
use tardus_mint::dkg::{dkg_finalize, dkg_start, DkgRound1Broadcast, PeerContribution};
use tardus_mint::rotation::{
    reshare_finalize, reshare_start, ReshareRound1Broadcast, ResharePeerContribution,
};
use tardus_mint::sign::{partial_sign, validator_round1};
use tardus_mint::transcript::{CeremonyId, SessionId};
use tardus_mint::vss::{h_generator, VssParameters, VssShare};
use tardus_refresh::refresh::{
    validator_refresh_round1, validator_refresh_round5, MintRefreshR3Challenge,
    UserRefreshR2Output,
};

use crate::dkg_sessions::{DkgSession, SharedDkgSessions};
use crate::refresh_sessions::{RefreshSessionEntry, SharedRefreshSessions};
use crate::reshare_sessions::{ReshareSession, SharedReshareSessions};
use crate::sign_sessions::{SharedSignSessions, SignSessionEntry};
use crate::state::{SharedState, ValidatorConfig};
use crate::storage::{share_path, write_share_record, ValidatorShareRecord};
use crate::transparency_log::{
    self, SharedTransparency, TransparencyEvent,
};

#[derive(Clone)]
pub struct AppState {
    pub config: ValidatorConfig,
    pub state: SharedState,
    pub sign_sessions: SharedSignSessions,
    pub refresh_sessions: SharedRefreshSessions,
    pub dkg_sessions: SharedDkgSessions,
    pub reshare_sessions: SharedReshareSessions,
    pub transparency: Option<SharedTransparency>,
}

/// Append a transparency-log event if the logger is configured.
/// Silent on I/O failure (we never want logging to break a ceremony).
async fn tlog(app: &AppState, event: TransparencyEvent) {
    if let Some(logger) = app.transparency.as_ref() {
        let mut guard = logger.lock().await;
        if let Err(e) = guard.append(event).await {
            tracing::warn!(error = %e, "transparency log append failed");
        }
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub probes_served: u64,
}

#[derive(Serialize)]
pub struct InfoResponse {
    pub operator: String,
    pub bind_addr: String,
    pub share_loaded: bool,
    pub keyset_id_hex: Option<String>,
    pub my_index: Option<u16>,
    pub n: Option<u16>,
    pub t: Option<u16>,
    pub epoch: Option<u64>,
    pub sign_sessions: u64,
    pub refresh_sessions: u64,
}

#[derive(Serialize)]
pub struct VersionResponse {
    pub crate_version: &'static str,
    pub api_version: &'static str,
}

/// `GET /health`
pub async fn health(State(app): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let probes = {
        let mut s = app.state.write().await;
        s.health_probes_served = s.health_probes_served.saturating_add(1);
        s.health_probes_served
    };
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            probes_served: probes,
        }),
    )
}

/// `GET /info`
pub async fn info(State(app): State<AppState>) -> Json<InfoResponse> {
    let s = app.state.read().await;
    let share_loaded = s.share.is_some();
    let (keyset_id_hex, my_index, n, t, epoch) = if let Some(share) = &s.share {
        (
            Some(hex::encode(share.keyset_id)),
            Some(share.my_index),
            Some(share.n),
            Some(share.t),
            Some(share.epoch),
        )
    } else {
        (None, None, None, None, None)
    };
    Json(InfoResponse {
        operator: app.config.operator_name.clone(),
        bind_addr: app.config.bind_addr.to_string(),
        share_loaded,
        keyset_id_hex,
        my_index,
        n,
        t,
        epoch,
        sign_sessions: s.sign_session_counter,
        refresh_sessions: s.refresh_session_counter,
    })
}

/// `GET /version`
pub async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        crate_version: env!("CARGO_PKG_VERSION"),
        api_version: "tardus-validator-v0.1",
    })
}

// =====================================================================
// Sign session endpoints (v2.2)
// =====================================================================

/// JSON-encoded API error.
#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

fn decode_hex32(s: &str, label: &str) -> Result<[u8; 32], (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(s).map_err(|e| err(StatusCode::BAD_REQUEST, format!("{label}: {e}")))?;
    if bytes.len() != 32 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("{label}: expected 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_session_id(s: &str) -> Result<SessionId, (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(s).map_err(|e| err(StatusCode::BAD_REQUEST, format!("session_id: {e}")))?;
    if bytes.len() != 16 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("session_id: expected 16 bytes, got {}", bytes.len()),
        ));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(SessionId::from_bytes(arr))
}

fn decode_ceremony_id(s: &str) -> Result<CeremonyId, (StatusCode, Json<ApiError>)> {
    let bytes =
        hex::decode(s).map_err(|e| err(StatusCode::BAD_REQUEST, format!("ceremony_id: {e}")))?;
    if bytes.len() != 16 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("ceremony_id: expected 16 bytes, got {}", bytes.len()),
        ));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(CeremonyId::from_bytes(arr))
}

#[derive(Deserialize)]
pub struct SignRound1Req {
    pub session_id_hex: String,
}

#[derive(Serialize)]
pub struct SignRound1Resp {
    pub from_index: u16,
    pub session_id_hex: String,
    pub r_i_hex: String,
}

/// `POST /sign/round1` — produce this validator's commitment for a
/// fresh sign session. Persists the per-session nonce state until
/// `/sign/round3` consumes it.
///
/// # Errors
/// - 400 if `session_id_hex` is malformed.
/// - 503 if the validator share is not yet loaded.
/// - 409 if a session with the same id is already in flight
///   (nonce-reuse protection).
pub async fn sign_round1(
    State(app): State<AppState>,
    Json(req): Json<SignRound1Req>,
) -> Result<Json<SignRound1Resp>, (StatusCode, Json<ApiError>)> {
    let session_id = decode_session_id(&req.session_id_hex)?;

    let my_index = {
        let s = app.state.read().await;
        let share = s.share.as_ref().ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "validator share not loaded",
            )
        })?;
        share.my_index
    };

    let (out, state) = validator_round1(session_id, my_index, &mut OsRng);

    app.sign_sessions
        .insert(SignSessionEntry {
            state,
            created_at: std::time::Instant::now(),
        })
        .await
        .map_err(|()| {
            err(
                StatusCode::CONFLICT,
                "session_id already in flight (nonce-reuse rejected)",
            )
        })?;

    {
        let mut s = app.state.write().await;
        s.sign_session_counter = s.sign_session_counter.saturating_add(1);
    }

    tlog(
        &app,
        TransparencyEvent::SignSessionStart {
            session_id_hex: hex::encode(session_id.to_bytes()),
            my_index,
        },
    )
    .await;

    Ok(Json(SignRound1Resp {
        from_index: out.from_index,
        session_id_hex: hex::encode(out.session_id.to_bytes()),
        r_i_hex: hex::encode(out.r_i),
    }))
}

#[derive(Deserialize)]
pub struct SignRound3Req {
    pub session_id_hex: String,
    pub signing_set: Vec<u16>,
    pub challenge_hex: String,
}

#[derive(Serialize)]
pub struct SignRound3Resp {
    pub from_index: u16,
    pub session_id_hex: String,
    pub s_i_hex: String,
}

/// `POST /sign/round3` — consume the previously-stored Round-1 state
/// and produce this validator's partial signature.
///
/// # Errors
/// - 400 if any hex field is malformed or `partial_sign` rejects.
/// - 503 if the validator share is not yet loaded.
/// - 404 if no in-flight session exists for the given `session_id_hex`
///   (already consumed or expired).
/// - 500 on impossible share-decode failure.
pub async fn sign_round3(
    State(app): State<AppState>,
    Json(req): Json<SignRound3Req>,
) -> Result<Json<SignRound3Resp>, (StatusCode, Json<ApiError>)> {
    let session_id = decode_session_id(&req.session_id_hex)?;
    let c_bytes = decode_hex32(&req.challenge_hex, "challenge_hex")?;
    let challenge = BlindChallenge { c: c_bytes };

    let share_bytes = {
        let s = app.state.read().await;
        let share = s.share.as_ref().ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "validator share not loaded",
            )
        })?;
        share.my_share_bytes
    };
    let my_share = SecretKey::from_bytes(&share_bytes)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("share decode: {e}")))?;

    let entry = app
        .sign_sessions
        .take(&session_id)
        .await
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "no in-flight session with that id (already consumed or expired)",
            )
        })?;

    let out = partial_sign(&entry.state, &challenge, &my_share, &req.signing_set)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("partial_sign: {e:?}")))?;

    Ok(Json(SignRound3Resp {
        from_index: out.from_index,
        session_id_hex: hex::encode(out.session_id.to_bytes()),
        s_i_hex: hex::encode(out.s_i),
    }))
}

// =====================================================================
// Refresh session endpoints (v2.3)
// =====================================================================

fn decode_hex64(s: &str, label: &str) -> Result<[u8; 64], (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(s).map_err(|e| err(StatusCode::BAD_REQUEST, format!("{label}: {e}")))?;
    if bytes.len() != 64 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("{label}: expected 64 bytes, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Deserialize)]
pub struct RefreshRound1Req {
    pub session_id_hex: String,
    pub kappa: u8,
}

#[derive(Serialize)]
pub struct RefreshRound1Resp {
    pub from_index: u16,
    pub session_id_hex: String,
    pub kappa: u8,
    pub r_per_candidate_hex: Vec<String>,
}

/// `POST /refresh/round1` — validator's κ commitments for a fresh
/// refresh session. Persists the per-session κ nonces until
/// `/refresh/round5` consumes them.
///
/// # Errors
/// - 400 if `session_id_hex` is malformed or `kappa == 0`.
/// - 503 if validator share not loaded.
/// - 409 if a session with the same id is already in flight.
pub async fn refresh_round1(
    State(app): State<AppState>,
    Json(req): Json<RefreshRound1Req>,
) -> Result<Json<RefreshRound1Resp>, (StatusCode, Json<ApiError>)> {
    let session_id = decode_session_id(&req.session_id_hex)?;
    if req.kappa == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "kappa must be > 0"));
    }

    let my_index = {
        let s = app.state.read().await;
        let share = s.share.as_ref().ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "validator share not loaded",
            )
        })?;
        share.my_index
    };

    let (out, state) =
        validator_refresh_round1(session_id, my_index, req.kappa, &mut OsRng)
            .map_err(|e| err(StatusCode::BAD_REQUEST, format!("refresh_round1: {e:?}")))?;

    app.refresh_sessions
        .insert(RefreshSessionEntry {
            state,
            created_at: std::time::Instant::now(),
        })
        .await
        .map_err(|()| {
            err(
                StatusCode::CONFLICT,
                "session_id already in flight (nonce-reuse rejected)",
            )
        })?;

    {
        let mut s = app.state.write().await;
        s.refresh_session_counter = s.refresh_session_counter.saturating_add(1);
    }

    tlog(
        &app,
        TransparencyEvent::RefreshSessionStart {
            session_id_hex: hex::encode(session_id.to_bytes()),
            my_index,
            kappa: req.kappa,
        },
    )
    .await;

    Ok(Json(RefreshRound1Resp {
        from_index: out.from_index,
        session_id_hex: hex::encode(out.session_id.to_bytes()),
        kappa: req.kappa,
        r_per_candidate_hex: out.r_per_candidate.iter().map(hex::encode).collect(),
    }))
}

#[derive(Deserialize)]
pub struct RefreshRound5Req {
    pub session_id_hex: String,
    pub signing_set: Vec<u16>,
    pub gamma_star: u8,
    /// κ challenge scalars from `user_refresh_round2`, hex-encoded.
    pub user_challenges_hex: Vec<String>,
    pub melted_coin_pubkey_hex: String,
    pub melted_coin_signature_hex: String,
}

#[derive(Serialize)]
pub struct RefreshRound5Resp {
    pub from_index: u16,
    pub session_id_hex: String,
    pub s_partial_hex: String,
}

/// `POST /refresh/round5` — consume the previously-stored Round-1
/// state and produce this validator's partial signature for γ*.
///
/// # Errors
/// - 400 if any hex field is malformed, `kappa`/`gamma_star` bounds wrong,
///   or `validator_refresh_round5` rejects.
/// - 503 if validator share not loaded.
/// - 404 if no in-flight session.
/// - 500 on impossible share-decode failure.
pub async fn refresh_round5(
    State(app): State<AppState>,
    Json(req): Json<RefreshRound5Req>,
) -> Result<Json<RefreshRound5Resp>, (StatusCode, Json<ApiError>)> {
    let session_id = decode_session_id(&req.session_id_hex)?;
    let kappa = u8::try_from(req.user_challenges_hex.len())
        .map_err(|_| err(StatusCode::BAD_REQUEST, "too many user_challenges_hex"))?;
    if kappa == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "user_challenges_hex empty"));
    }
    if req.gamma_star == 0 || req.gamma_star > kappa {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("gamma_star {} out of range [1..{}]", req.gamma_star, kappa),
        ));
    }

    let mut challenges = Vec::with_capacity(kappa as usize);
    for (i, hx) in req.user_challenges_hex.iter().enumerate() {
        let c = decode_hex32(hx, &format!("user_challenges_hex[{i}]"))?;
        challenges.push(c);
    }
    let melted_coin_pubkey = decode_hex32(&req.melted_coin_pubkey_hex, "melted_coin_pubkey_hex")?;
    let melted_coin_signature =
        Signature::from_bytes(&decode_hex64(&req.melted_coin_signature_hex, "melted_coin_signature_hex")?);

    let share_bytes = {
        let s = app.state.read().await;
        let share = s.share.as_ref().ok_or_else(|| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                "validator share not loaded",
            )
        })?;
        share.my_share_bytes
    };
    let my_share = SecretKey::from_bytes(&share_bytes)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("share decode: {e}")))?;

    let entry = app
        .refresh_sessions
        .take(&session_id)
        .await
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "no in-flight refresh session (already consumed or expired)",
            )
        })?;

    let user_round2 = UserRefreshR2Output {
        session_id,
        kappa,
        challenges,
        melted_coin_pubkey,
        melted_coin_signature,
    };
    let challenge = MintRefreshR3Challenge {
        session_id,
        gamma_star: req.gamma_star,
    };

    let out = validator_refresh_round5(
        &entry.state,
        &user_round2,
        &challenge,
        &my_share,
        &req.signing_set,
    )
    .map_err(|e| err(StatusCode::BAD_REQUEST, format!("validator_refresh_round5: {e:?}")))?;

    Ok(Json(RefreshRound5Resp {
        from_index: out.from_index,
        session_id_hex: hex::encode(out.session_id.to_bytes()),
        s_partial_hex: hex::encode(out.s_partial),
    }))
}

// =====================================================================
// DKG ceremony endpoints (v2.5)
// =====================================================================

#[derive(Deserialize)]
pub struct DkgStartReq {
    pub ceremony_id_hex: String,
    pub my_index: u16,
    pub n: u16,
    pub t: u16,
}

#[derive(Serialize)]
pub struct DkgStartResp {
    pub ceremony_id_hex: String,
    pub my_index: u16,
    pub n: u16,
    pub t: u16,
    pub broadcast_borsh_hex: String,
    /// `n` shares, in index order `1..=n`. The dealer's self-share
    /// is at position `my_index - 1`. Hex-encoded Borsh.
    pub shares_borsh_hex: Vec<String>,
}

/// `POST /dkg/start` — run this validator's Round-1 contribution to
/// a fresh DKG ceremony.
///
/// # Errors
/// - 400 if `ceremony_id_hex` malformed, `my_index` out of range, or
///   `VssParameters::new` rejects.
/// - 409 if the ceremony is already in flight.
pub async fn dkg_start_handler(
    State(app): State<AppState>,
    Json(req): Json<DkgStartReq>,
) -> Result<Json<DkgStartResp>, (StatusCode, Json<ApiError>)> {
    let ceremony_id = decode_ceremony_id(&req.ceremony_id_hex)?;
    let params = VssParameters::new(req.n, req.t)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("vss params: {e:?}")))?;
    let h = h_generator();

    let round1 = dkg_start(ceremony_id, req.my_index, params, &h, &mut OsRng)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("dkg_start: {e:?}")))?;

    let broadcast_bytes = borsh::to_vec(&round1.broadcast)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("borsh: {e}")))?;
    let shares_hex: Vec<String> = round1
        .shares
        .iter()
        .map(|s| {
            borsh::to_vec(s)
                .map(hex::encode)
                .unwrap_or_default()
        })
        .collect();

    let resp = DkgStartResp {
        ceremony_id_hex: req.ceremony_id_hex.clone(),
        my_index: req.my_index,
        n: req.n,
        t: req.t,
        broadcast_borsh_hex: hex::encode(&broadcast_bytes),
        shares_borsh_hex: shares_hex,
    };

    let session = DkgSession {
        my_round1: round1,
        n: req.n,
        peer_contributions: std::collections::HashMap::new(),
        created_at: std::time::Instant::now(),
    };
    app.dkg_sessions
        .start(ceremony_id, session)
        .await
        .map_err(|()| err(StatusCode::CONFLICT, "ceremony already in flight"))?;

    tlog(
        &app,
        TransparencyEvent::DkgStart {
            ceremony_id_hex: req.ceremony_id_hex.clone(),
            my_index: req.my_index,
            n: req.n,
            t: req.t,
        },
    )
    .await;

    Ok(Json(resp))
}

#[derive(Deserialize)]
pub struct DkgContributeReq {
    pub ceremony_id_hex: String,
    pub from_index: u16,
    pub broadcast_borsh_hex: String,
    /// The single share this peer dealt for us.
    pub share_for_me_borsh_hex: String,
}

#[derive(Serialize)]
pub struct DkgContributeResp {
    pub ceremony_id_hex: String,
    pub contributions_received: usize,
}

/// `POST /dkg/contribute` — store a peer's contribution.
///
/// # Errors
/// - 400 if any field malformed or Borsh decode fails.
/// - 404 if no ceremony with that id is in flight.
pub async fn dkg_contribute_handler(
    State(app): State<AppState>,
    Json(req): Json<DkgContributeReq>,
) -> Result<Json<DkgContributeResp>, (StatusCode, Json<ApiError>)> {
    let ceremony_id = decode_ceremony_id(&req.ceremony_id_hex)?;
    let broadcast_bytes = hex::decode(&req.broadcast_borsh_hex)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("broadcast hex: {e}")))?;
    let broadcast = DkgRound1Broadcast::try_from_slice(&broadcast_bytes)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("broadcast borsh: {e}")))?;
    let share_bytes = hex::decode(&req.share_for_me_borsh_hex)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("share hex: {e}")))?;
    let share_for_me = VssShare::try_from_slice(&share_bytes)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("share borsh: {e}")))?;
    let contribution = PeerContribution {
        broadcast,
        share_for_me,
    };

    let count = app
        .dkg_sessions
        .contribute(ceremony_id, req.from_index, contribution)
        .await
        .map_err(|()| err(StatusCode::NOT_FOUND, "no ceremony in flight"))?;

    Ok(Json(DkgContributeResp {
        ceremony_id_hex: req.ceremony_id_hex,
        contributions_received: count,
    }))
}

#[derive(Deserialize)]
pub struct DkgFinalizeReq {
    pub ceremony_id_hex: String,
}

#[derive(Serialize)]
pub struct DkgFinalizeResp {
    pub ceremony_id_hex: String,
    pub my_index: u16,
    pub joint_pk_hex: String,
    pub qual: Vec<u16>,
    pub share_persisted: bool,
}

/// `POST /dkg/finalize` — once n-1 peer contributions are collected,
/// run `dkg_finalize`, persist the new share record (if a master seed
/// was configured at boot), and report the joint public key.
///
/// # Errors
/// - 400 if ceremony id malformed.
/// - 404 if no in-flight ceremony or insufficient peer contributions.
/// - 422 on `dkg_finalize` cryptographic rejection (e.g.\ cheating dealer).
/// - 500 on storage / Borsh failure during persistence.
pub async fn dkg_finalize_handler(
    State(app): State<AppState>,
    Json(req): Json<DkgFinalizeReq>,
) -> Result<Json<DkgFinalizeResp>, (StatusCode, Json<ApiError>)> {
    let ceremony_id = decode_ceremony_id(&req.ceremony_id_hex)?;
    let (round1, contributions, n) = app
        .dkg_sessions
        .take_finalisable(ceremony_id)
        .await
        .map_err(|()| {
            err(
                StatusCode::NOT_FOUND,
                "no ceremony in flight or insufficient peer contributions",
            )
        })?;

    let my_index = round1.private.my_index;
    let t = round1.private.params.t;
    let h = h_generator();
    let finalised = dkg_finalize(&round1, &contributions, &h)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, format!("dkg_finalize: {e:?}")))?;

    // Persist the new share, if a master seed is configured.
    let joint_pk_bytes = finalised.joint_pk.to_bytes();
    let mut keyset_id = [0u8; 33];
    keyset_id[0] = 0x02;
    keyset_id[1..].copy_from_slice(&joint_pk_bytes);
    let record = ValidatorShareRecord {
        keyset_id,
        my_index: finalised.my_index,
        n,
        t,
        epoch: 1,
        joint_pk_bytes,
        my_share_bytes: finalised.my_share.to_bytes(),
        qual: finalised.qual.clone(),
    };

    let share_persisted = if let Some(seed) = app.config.master_seed.as_ref() {
        let path = share_path(&app.config.data_dir, &keyset_id);
        write_share_record(&path, seed, &record)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("storage: {e:?}")))?;
        true
    } else {
        false
    };

    // Swap into memory.
    {
        let mut s = app.state.write().await;
        s.share = Some(record);
    }

    let qual = finalised.qual.clone();
    tlog(
        &app,
        TransparencyEvent::DkgFinalize {
            ceremony_id_hex: req.ceremony_id_hex.clone(),
            my_index,
            joint_pk_hex: hex::encode(joint_pk_bytes),
            qual: qual.clone(),
        },
    )
    .await;

    Ok(Json(DkgFinalizeResp {
        ceremony_id_hex: req.ceremony_id_hex,
        my_index,
        joint_pk_hex: hex::encode(joint_pk_bytes),
        qual,
        share_persisted,
    }))
}

// =====================================================================
// Reshare ceremony endpoints (v2.6)
// =====================================================================

#[derive(Deserialize)]
pub struct ReshareStartReq {
    pub ceremony_id_hex: String,
}

#[derive(Serialize)]
pub struct ReshareStartResp {
    pub ceremony_id_hex: String,
    pub my_index: u16,
    pub n: u16,
    pub t: u16,
    pub broadcast_borsh_hex: String,
    /// `n` shares, in index order `1..=n`. The dealer's self-share
    /// is at position `my_index - 1`. Hex-encoded Borsh.
    pub shares_borsh_hex: Vec<String>,
}

/// `POST /reshare/start` — run this validator's Round-1 contribution to
/// a fresh reshare ceremony. Validator must already have a share loaded.
///
/// # Errors
/// - 400 if `ceremony_id_hex` malformed.
/// - 503 if no share loaded.
/// - 409 if the ceremony is already in flight.
pub async fn reshare_start_handler(
    State(app): State<AppState>,
    Json(req): Json<ReshareStartReq>,
) -> Result<Json<ReshareStartResp>, (StatusCode, Json<ApiError>)> {
    let ceremony_id = decode_ceremony_id(&req.ceremony_id_hex)?;
    let (my_index, n, t) = {
        let s = app.state.read().await;
        let share = s.share.as_ref().ok_or_else(|| {
            err(StatusCode::SERVICE_UNAVAILABLE, "no share loaded")
        })?;
        (share.my_index, share.n, share.t)
    };
    let params = VssParameters::new(n, t)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("vss params: {e:?}")))?;
    let h = h_generator();
    let round1 = reshare_start(ceremony_id, my_index, params, &h, &mut OsRng)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("reshare_start: {e:?}")))?;

    let broadcast_bytes = borsh::to_vec(&round1.broadcast)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("borsh: {e}")))?;
    let shares_hex: Vec<String> = round1
        .shares
        .iter()
        .map(|s| borsh::to_vec(s).map(hex::encode).unwrap_or_default())
        .collect();
    let resp = ReshareStartResp {
        ceremony_id_hex: req.ceremony_id_hex.clone(),
        my_index,
        n,
        t,
        broadcast_borsh_hex: hex::encode(&broadcast_bytes),
        shares_borsh_hex: shares_hex,
    };

    let session = ReshareSession {
        my_round1: round1,
        n,
        peer_contributions: std::collections::HashMap::new(),
        created_at: std::time::Instant::now(),
    };
    app.reshare_sessions
        .start(ceremony_id, session)
        .await
        .map_err(|()| err(StatusCode::CONFLICT, "ceremony already in flight"))?;

    tlog(
        &app,
        TransparencyEvent::ReshareStart {
            ceremony_id_hex: req.ceremony_id_hex.clone(),
            my_index,
            n,
            t,
        },
    )
    .await;

    Ok(Json(resp))
}

#[derive(Deserialize)]
pub struct ReshareContributeReq {
    pub ceremony_id_hex: String,
    pub from_index: u16,
    pub broadcast_borsh_hex: String,
    pub share_for_me_borsh_hex: String,
}

#[derive(Serialize)]
pub struct ReshareContributeResp {
    pub ceremony_id_hex: String,
    pub contributions_received: usize,
}

/// `POST /reshare/contribute` — store a peer's reshare contribution.
///
/// # Errors
/// - 400 if any field malformed or Borsh decode fails.
/// - 404 if no in-flight reshare ceremony.
pub async fn reshare_contribute_handler(
    State(app): State<AppState>,
    Json(req): Json<ReshareContributeReq>,
) -> Result<Json<ReshareContributeResp>, (StatusCode, Json<ApiError>)> {
    let ceremony_id = decode_ceremony_id(&req.ceremony_id_hex)?;
    let broadcast_bytes = hex::decode(&req.broadcast_borsh_hex)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("broadcast hex: {e}")))?;
    let broadcast = ReshareRound1Broadcast::try_from_slice(&broadcast_bytes)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("broadcast borsh: {e}")))?;
    let share_bytes = hex::decode(&req.share_for_me_borsh_hex)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("share hex: {e}")))?;
    let share_for_me = VssShare::try_from_slice(&share_bytes)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("share borsh: {e}")))?;
    let contribution = ResharePeerContribution {
        broadcast,
        share_for_me,
    };
    let count = app
        .reshare_sessions
        .contribute(ceremony_id, req.from_index, contribution)
        .await
        .map_err(|()| err(StatusCode::NOT_FOUND, "no reshare ceremony in flight"))?;
    Ok(Json(ReshareContributeResp {
        ceremony_id_hex: req.ceremony_id_hex,
        contributions_received: count,
    }))
}

#[derive(Deserialize)]
pub struct ReshareFinalizeReq {
    pub ceremony_id_hex: String,
}

#[derive(Serialize)]
pub struct ReshareFinalizeResp {
    pub ceremony_id_hex: String,
    pub my_index: u16,
    pub new_epoch: u64,
    pub share_persisted: bool,
}

/// `POST /reshare/finalize` — combine old share + n-1 peer
/// contributions into a fresh share with epoch+1. Joint public key
/// is unchanged by reshare (T5).
///
/// # Errors
/// - 400 if ceremony id malformed.
/// - 404 if no in-flight reshare or insufficient contributions.
/// - 422 on `reshare_finalize` rejection (cheating dealer:
///   `ResharePolyNonZero`).
/// - 500 on storage / Borsh failure.
///
/// # Panics
/// Cannot panic: the `expect` inside `s.share.as_ref()` is reached
/// only after we've already verified that the share is loaded
/// upstream in this function.
pub async fn reshare_finalize_handler(
    State(app): State<AppState>,
    Json(req): Json<ReshareFinalizeReq>,
) -> Result<Json<ReshareFinalizeResp>, (StatusCode, Json<ApiError>)> {
    let ceremony_id = decode_ceremony_id(&req.ceremony_id_hex)?;
    let (round1, contributions, n) = app
        .reshare_sessions
        .take_finalisable(ceremony_id)
        .await
        .map_err(|()| {
            err(
                StatusCode::NOT_FOUND,
                "no reshare ceremony in flight or insufficient contributions",
            )
        })?;
    let old_share_bytes = {
        let s = app.state.read().await;
        let share = s
            .share
            .as_ref()
            .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "no share loaded"))?;
        share.my_share_bytes
    };
    let old_share = SecretKey::from_bytes(&old_share_bytes)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("old share: {e}")))?;
    let h = h_generator();
    let finalised = reshare_finalize(&round1, &old_share, &contributions, &h)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, format!("reshare_finalize: {e:?}")))?;

    // Build new record at epoch+1, keeping keyset_id + joint_pk.
    let (keyset_id, joint_pk_bytes, t, new_epoch) = {
        let s = app.state.read().await;
        let cur = s
            .share
            .as_ref()
            .expect("share present (verified above)");
        (
            cur.keyset_id,
            cur.joint_pk_bytes,
            cur.t,
            cur.epoch.saturating_add(1),
        )
    };
    let record = ValidatorShareRecord {
        keyset_id,
        my_index: finalised.my_index,
        n,
        t,
        epoch: new_epoch,
        joint_pk_bytes,
        my_share_bytes: finalised.new_share.to_bytes(),
        qual: finalised.qual,
    };

    let share_persisted = if let Some(seed) = app.config.master_seed.as_ref() {
        let path = share_path(&app.config.data_dir, &keyset_id);
        write_share_record(&path, seed, &record)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("storage: {e:?}")))?;
        true
    } else {
        false
    };

    {
        let mut s = app.state.write().await;
        s.share = Some(record);
    }

    tlog(
        &app,
        TransparencyEvent::ReshareFinalize {
            ceremony_id_hex: req.ceremony_id_hex.clone(),
            my_index: finalised.my_index,
            new_epoch,
        },
    )
    .await;

    Ok(Json(ReshareFinalizeResp {
        ceremony_id_hex: req.ceremony_id_hex,
        my_index: finalised.my_index,
        new_epoch,
        share_persisted,
    }))
}

// =====================================================================
// Transparency log query endpoints (v2.7)
// =====================================================================

#[derive(Serialize)]
pub struct TransparencyTailResp {
    pub entries: Vec<transparency_log::LogEntry>,
    pub last_event_id: String,
}

/// `GET /transparency/log` — return all log entries plus the last
/// event id. Read-only; no admin token required (the log is
/// intentionally public).
///
/// # Errors
/// - 404 if the transparency log is disabled (no `--transparency-log`).
/// - 500 on file-read I/O failure.
pub async fn transparency_log_handler(
    State(app): State<AppState>,
) -> Result<Json<TransparencyTailResp>, (StatusCode, Json<ApiError>)> {
    let logger = app
        .transparency
        .as_ref()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "transparency log disabled"))?;
    let (path, last_event_id) = {
        let g = logger.lock().await;
        (g.path().clone(), g.last_event_id().to_string())
    };
    let entries = transparency_log::read_all(&path)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("read log: {e}")))?;
    Ok(Json(TransparencyTailResp {
        entries,
        last_event_id,
    }))
}

#[derive(Serialize)]
pub struct ChainVerifyResp {
    pub valid: bool,
    pub entries_checked: usize,
    pub failure_index: Option<usize>,
    pub failure_reason: Option<String>,
}

/// `GET /transparency/verify-chain` — re-walk the on-disk log and
/// confirm the hash chain is intact.
///
/// # Errors
/// - 404 if the transparency log is disabled (no `--transparency-log`).
pub async fn transparency_verify_chain_handler(
    State(app): State<AppState>,
) -> Result<Json<ChainVerifyResp>, (StatusCode, Json<ApiError>)> {
    let logger = app
        .transparency
        .as_ref()
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "transparency log disabled"))?;
    let path = {
        let g = logger.lock().await;
        g.path().clone()
    };
    let resp = match transparency_log::verify_chain(&path).await {
        Ok(count) => ChainVerifyResp {
            valid: true,
            entries_checked: count,
            failure_index: None,
            failure_reason: None,
        },
        Err((idx, reason)) => ChainVerifyResp {
            valid: false,
            entries_checked: idx,
            failure_index: Some(idx),
            failure_reason: Some(reason),
        },
    };
    Ok(Json(resp))
}

// =====================================================================
// Observability + admin endpoints (v2.4)
// =====================================================================

/// `GET /metrics` — Prometheus text-format scrape endpoint.
///
/// Surface the counters and gauges that §8 of the spec calls out as
/// the validator daemon's instrumentation surface for the 14
/// auto-detection failure modes.
pub async fn metrics(State(app): State<AppState>) -> impl IntoResponse {
    let s = app.state.read().await;
    let uptime = s.started_at.elapsed().as_secs_f64();
    let share_loaded = u8::from(s.share.is_some());
    let sign_inflight = app.sign_sessions.len().await;
    let refresh_inflight = app.refresh_sessions.len().await;

    let body = format!(
        "# HELP validator_uptime_seconds Seconds since validator process start.\n\
         # TYPE validator_uptime_seconds gauge\n\
         validator_uptime_seconds {uptime:.3}\n\
         # HELP validator_share_loaded 1 if the validator share is loaded into memory, else 0.\n\
         # TYPE validator_share_loaded gauge\n\
         validator_share_loaded {share_loaded}\n\
         # HELP validator_health_probes_total Total /health requests served.\n\
         # TYPE validator_health_probes_total counter\n\
         validator_health_probes_total {hp}\n\
         # HELP validator_sign_sessions_total Total /sign/round1 sessions accepted.\n\
         # TYPE validator_sign_sessions_total counter\n\
         validator_sign_sessions_total {ss}\n\
         # HELP validator_sign_sessions_inflight Sign sessions currently between Round 1 and Round 3.\n\
         # TYPE validator_sign_sessions_inflight gauge\n\
         validator_sign_sessions_inflight {si}\n\
         # HELP validator_refresh_sessions_total Total /refresh/round1 sessions accepted.\n\
         # TYPE validator_refresh_sessions_total counter\n\
         validator_refresh_sessions_total {rs}\n\
         # HELP validator_refresh_sessions_inflight Refresh sessions currently between Round 1 and Round 5.\n\
         # TYPE validator_refresh_sessions_inflight gauge\n\
         validator_refresh_sessions_inflight {ri}\n\
         # HELP validator_share_reloads_total Total /admin/reload-share calls.\n\
         # TYPE validator_share_reloads_total counter\n\
         validator_share_reloads_total {sr}\n",
        hp = s.health_probes_served,
        ss = s.sign_session_counter,
        si = sign_inflight,
        rs = s.refresh_session_counter,
        ri = refresh_inflight,
        sr = s.share_reloads,
    );
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        body,
    )
}

#[derive(Serialize)]
pub struct SessionsResponse {
    pub sign_inflight: usize,
    pub refresh_inflight: usize,
}

/// `GET /admin/sessions` — show in-flight session counts. Admin token
/// required.
///
/// # Errors
/// - 401 if `X-Admin-Token` missing or wrong.
/// - 403 if admin endpoints are disabled (no token configured at boot).
pub async fn admin_sessions(
    State(app): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SessionsResponse>, (StatusCode, Json<ApiError>)> {
    check_admin(&app, &headers)?;
    let sign_inflight = app.sign_sessions.len().await;
    let refresh_inflight = app.refresh_sessions.len().await;
    Ok(Json(SessionsResponse {
        sign_inflight,
        refresh_inflight,
    }))
}

#[derive(Serialize)]
pub struct ReloadResponse {
    pub reloaded: bool,
    pub keyset_id_hex: Option<String>,
    pub epoch: Option<u64>,
}

/// `POST /admin/reload-share` — re-scan the data dir for any share
/// files and reload them under the master seed. Used after an
/// off-process reshare ceremony updates the share file on disk.
///
/// # Errors
/// - 401 if `X-Admin-Token` missing or wrong.
/// - 503 if no master seed was configured at boot
///   (`TARDUS_VALIDATOR_MASTER_SEED`).
/// - 500 if the share file is corrupt.
pub async fn admin_reload_share(
    State(app): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ReloadResponse>, (StatusCode, Json<ApiError>)> {
    check_admin(&app, &headers)?;

    let seed = app.config.master_seed.as_ref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "no master seed configured at boot",
        )
    })?;

    let mut loaded = None;
    let entries = std::fs::read_dir(&app.config.data_dir).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read_dir: {e}"),
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("dir entry: {e}"),
            )
        })?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("bin")
            && path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with("share_"))
        {
            let record = crate::storage::read_share_record(&path, seed).map_err(|e| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("share decode: {e:?}"),
                )
            })?;
            loaded = Some(record);
            break; // single-share mode v2.4
        }
    }

    let resp = match loaded {
        Some(record) => {
            let keyset_id_hex = hex::encode(record.keyset_id);
            let epoch = record.epoch;
            let mut s = app.state.write().await;
            s.share = Some(record);
            s.share_reloads = s.share_reloads.saturating_add(1);
            ReloadResponse {
                reloaded: true,
                keyset_id_hex: Some(keyset_id_hex),
                epoch: Some(epoch),
            }
        }
        None => ReloadResponse {
            reloaded: false,
            keyset_id_hex: None,
            epoch: None,
        },
    };
    Ok(Json(resp))
}

fn check_admin(
    app: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ApiError>)> {
    let expected = app
        .config
        .admin_token
        .as_ref()
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "admin endpoints disabled"))?;
    let supplied = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing X-Admin-Token"))?;
    if supplied != expected {
        return Err(err(StatusCode::UNAUTHORIZED, "invalid X-Admin-Token"));
    }
    Ok(())
}

/// Build the v2.5 router (read-only + sign + refresh + DKG + observability + admin).
pub fn router(app: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/version", get(version))
        .route("/metrics", get(metrics))
        .route("/sign/round1", post(sign_round1))
        .route("/sign/round3", post(sign_round3))
        .route("/refresh/round1", post(refresh_round1))
        .route("/refresh/round5", post(refresh_round5))
        .route("/dkg/start", post(dkg_start_handler))
        .route("/dkg/contribute", post(dkg_contribute_handler))
        .route("/dkg/finalize", post(dkg_finalize_handler))
        .route("/reshare/start", post(reshare_start_handler))
        .route("/reshare/contribute", post(reshare_contribute_handler))
        .route("/reshare/finalize", post(reshare_finalize_handler))
        .route("/transparency/log", get(transparency_log_handler))
        .route("/transparency/verify-chain", get(transparency_verify_chain_handler))
        .route("/admin/sessions", get(admin_sessions))
        .route("/admin/reload-share", post(admin_reload_share))
        .with_state(app)
}
