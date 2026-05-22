use crate::{
    inbox::{Message, SharedInbox},
    state::{RelayConfig, SharedState},
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_TTL_SECS: u64 = 7 * 24 * 3600; // one week

#[derive(Clone)]
pub struct AppState {
    pub config: RelayConfig,
    pub state: SharedState,
    pub inbox: SharedInbox,
}

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

fn parse_recipient(hex_str: &str) -> Result<[u8; 32], (StatusCode, Json<ApiError>)> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("recipient: {e}")))?;
    if bytes.len() != 32 {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("recipient: expected 32 bytes, got {}", bytes.len()),
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub uptime_seconds: u64,
    pub deposits_total: u64,
    pub fetches_total: u64,
    pub messages_inflight: usize,
}

pub async fn health(State(app): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    let s = app.state.read().await;
    let uptime = s.started_at.elapsed().as_secs();
    let inflight = app.inbox.total_messages().await;
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok",
            uptime_seconds: uptime,
            deposits_total: s.deposits_total,
            fetches_total: s.fetches_total,
            messages_inflight: inflight,
        }),
    )
}

#[derive(Serialize)]
pub struct InfoResponse {
    pub operator: String,
    pub bind_addr: String,
    pub max_per_recipient: usize,
    pub max_payload_bytes: usize,
    pub default_ttl_secs: u64,
}

pub async fn info(State(app): State<AppState>) -> Json<InfoResponse> {
    Json(InfoResponse {
        operator: app.config.operator_name.clone(),
        bind_addr: app.config.bind_addr.to_string(),
        max_per_recipient: app.config.max_per_recipient,
        max_payload_bytes: app.config.max_payload_bytes,
        default_ttl_secs: DEFAULT_TTL_SECS,
    })
}

#[derive(Deserialize)]
pub struct DepositReq {
    pub payload_hex: String,
    pub ttl_secs: Option<u64>,
}

/// `POST /inbox/{recipient_pk_hex}` — anonymous deposit.
///
/// # Errors
/// - 400 if `recipient_pk_hex` malformed, payload too large.
/// - 503 if inbox full for recipient.
pub async fn deposit(
    State(app): State<AppState>,
    Path(recipient_hex): Path<String>,
    Json(req): Json<DepositReq>,
) -> Result<Json<Message>, (StatusCode, Json<ApiError>)> {
    let recipient = parse_recipient(&recipient_hex)?;
    let ttl = Duration::from_secs(req.ttl_secs.unwrap_or(DEFAULT_TTL_SECS));
    let msg = app
        .inbox
        .deposit(recipient, req.payload_hex, ttl)
        .await
        .map_err(|e| match e {
            crate::Error::PayloadTooLarge { .. } => err(StatusCode::BAD_REQUEST, e.to_string()),
            crate::Error::InboxFull { .. } => err(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
            other => err(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    let mut s = app.state.write().await;
    s.deposits_total = s.deposits_total.saturating_add(1);
    Ok(Json(msg))
}

#[derive(Serialize)]
pub struct ListResponse {
    pub messages: Vec<Message>,
}

/// `GET /inbox/{recipient_pk_hex}` — recipient polls for messages.
///
/// # Errors
/// - 400 if `recipient_pk_hex` malformed.
pub async fn list(
    State(app): State<AppState>,
    Path(recipient_hex): Path<String>,
) -> Result<Json<ListResponse>, (StatusCode, Json<ApiError>)> {
    let recipient = parse_recipient(&recipient_hex)?;
    let messages = app.inbox.list(recipient).await;
    let mut s = app.state.write().await;
    s.fetches_total = s.fetches_total.saturating_add(1);
    Ok(Json(ListResponse { messages }))
}

#[derive(Serialize)]
pub struct RemoveResponse {
    pub removed: bool,
}

/// `DELETE /inbox/{recipient_pk_hex}/{message_id}` — recipient marks
/// a message as consumed.
///
/// # Errors
/// - 400 if `recipient_pk_hex` malformed.
pub async fn remove(
    State(app): State<AppState>,
    Path((recipient_hex, message_id)): Path<(String, String)>,
) -> Result<Json<RemoveResponse>, (StatusCode, Json<ApiError>)> {
    let recipient = parse_recipient(&recipient_hex)?;
    let removed = app.inbox.remove(recipient, &message_id).await;
    Ok(Json(RemoveResponse { removed }))
}

pub fn router(app: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/info", get(info))
        .route("/inbox/:recipient", post(deposit).get(list))
        .route("/inbox/:recipient/:id", delete(remove))
        .with_state(app)
}
