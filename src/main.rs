mod security;
mod triage;

use std::{env, net::SocketAddr, sync::Arc};

use anyhow::{bail, Context};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tower_http::limit::RequestBodyLimitLayer;

const DEFAULT_BIND: &str = "127.0.0.1:8080";
const MAX_REQUEST_BYTES: usize = 1_048_576;
const MIN_BEARER_TOKEN_BYTES: usize = 32;

#[derive(Clone)]
struct SecurityMcp {
    tool_router: ToolRouter<Self>,
}

impl SecurityMcp {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct IndicatorArgs {
    /// Indicator type: ip, domain, url, or sha256.
    kind: String,
    /// The indicator to validate. Never submit credentials or unrelated personal data.
    indicator: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct HashTextArgs {
    /// Text evidence to hash. Maximum 8 KiB. The server does not store or log this value.
    text: String,
}

#[tool_router]
impl SecurityMcp {
    #[tool(
        description = "Return the server's defensive-security operating boundaries and a high-level baseline checklist. Read-only; this tool does not inspect the host or change systems."
    )]
    fn get_security_baseline(&self) -> String {
        json!({
            "service": "cybersecurity-mcp-server",
            "mode": "defensive_read_only_starter",
            "controls": [
                "Use least-privilege identities and short-lived credentials where supported.",
                "Require MFA for privileged and remote access.",
                "Patch internet-facing and actively exploited systems by risk priority.",
                "Centralize security telemetry and retain evidence according to policy.",
                "Back up critical data and regularly test restoration.",
                "Use approved incident-response runbooks and human approval for containment.",
                "Review service accounts, secrets, access grants, and audit records regularly."
            ],
            "limitations": [
                "No live SIEM, EDR, threat-intelligence, or asset-inventory integration is configured.",
                "Outputs are decision support and must be validated by a qualified analyst.",
                "No action is taken against endpoints, accounts, networks, or production systems."
            ]
        }).to_string()
    }

    #[tool(
        description = "Perform syntax-only validation and safe normalization of an IP address, domain, HTTP(S) URL, or SHA-256 digest. Does not resolve DNS, visit URLs, query reputation services, or attribute activity."
    )]
    fn assess_indicator(
        &self,
        Parameters(args): Parameters<IndicatorArgs>,
    ) -> Result<String, McpError> {
        let assessment = security::assess_indicator(&args.kind, &args.indicator)
            .map_err(|message| McpError::invalid_params(message, None))?;
        Ok(serde_json::to_string_pretty(&assessment)
            .unwrap_or_else(|_| "{\"error\":\"response serialization failed\"}".to_string()))
    }

    #[tool(
        description = "Provide defensive triage guidance for a security alert using its stated severity and metadata. No live detections, automatic containment, account changes, or other actions are performed. Treat the output as analyst decision support."
    )]
    fn triage_security_alert(
        &self,
        Parameters(args): Parameters<triage::AlertArgs>,
    ) -> Result<String, McpError> {
        let result = triage::triage_alert(args)
            .map_err(|message| McpError::invalid_params(message, None))?;
        Ok(serde_json::to_string_pretty(&result)
            .unwrap_or_else(|_| "{\"error\":\"response serialization failed\"}".to_string()))
    }

    #[tool(
        description = "Compute a SHA-256 digest of supplied text for evidence-integrity workflows. Input is limited to 8 KiB and is not stored or logged. This does not hash files on the host."
    )]
    fn sha256_text(&self, Parameters(args): Parameters<HashTextArgs>) -> Result<String, McpError> {
        if args.text.len() > 8192 {
            return Err(McpError::invalid_params(
                "text must not exceed 8192 bytes",
                None,
            ));
        }
        let digest = Sha256::digest(args.text.as_bytes());
        Ok(json!({
            "algorithm": "SHA-256",
            "digest_hex": hex::encode(digest),
            "input_bytes": args.text.len(),
            "stored": false
        })
        .to_string())
    }
}

#[tool_handler(
    name = "cybersecurity-mcp-server",
    version = "0.1.1",
    instructions = "Read-only defensive cybersecurity tools for syntax-only indicator validation, analyst-led alert triage, baseline guidance, and SHA-256 hashing of supplied text. Treat outputs as decision support. Never infer that an indicator is malicious from syntax alone. No destructive or live-response actions are exposed."
)]
impl ServerHandler for SecurityMcp {}

#[derive(Clone)]
struct AuthState {
    expected_token: Arc<str>,
}

async fn require_bearer_token(
    State(state): State<AuthState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    let valid = provided
        .map(|candidate| {
            let candidate = candidate.as_bytes();
            let expected = state.expected_token.as_bytes();
            candidate.len() == expected.len() && bool::from(candidate.ct_eq(expected))
        })
        .unwrap_or(false);

    if valid {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "Unauthorized",
        )
            .into_response()
    }
}

async fn healthz() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "cybersecurity-mcp-server" }))
}

async fn run_stdio() -> anyhow::Result<()> {
    // MCP stdio reserves stdout for protocol messages. Diagnostics are sent to stderr.
    let service = SecurityMcp::new().serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

async fn run_http() -> anyhow::Result<()> {
    let token = env::var("MCP_BEARER_TOKEN")
        .context("MCP_BEARER_TOKEN is required when MCP_TRANSPORT=http")?;
    if token.len() < MIN_BEARER_TOKEN_BYTES || token.trim() != token {
        bail!("MCP_BEARER_TOKEN must be at least 32 bytes with no leading/trailing whitespace");
    }

    let bind: SocketAddr = env::var("MCP_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.to_string())
        .parse()
        .context("MCP_BIND must be a valid socket address, e.g. 127.0.0.1:8080")?;

    let service = StreamableHttpService::new(
        || Ok(SecurityMcp::new()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default().with_json_response(true),
    );

    let protected_routes =
        Router::new()
            .nest_service("/mcp", service)
            .route_layer(middleware::from_fn_with_state(
                AuthState {
                    expected_token: Arc::<str>::from(token),
                },
                require_bearer_token,
            ));

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(protected_routes)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BYTES));

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .with_context(|| format!("failed to bind MCP listener to {bind}"))?;
    tracing::info!(address = %bind, "authenticated Streamable HTTP MCP server is ready");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "failed to listen for shutdown signal");
            }
        })
        .await?;
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    match env::var("MCP_TRANSPORT")
        .unwrap_or_else(|_| "stdio".to_string())
        .as_str()
    {
        "stdio" => run_stdio().await,
        "http" => run_http().await,
        other => bail!("unsupported MCP_TRANSPORT '{other}'; use 'stdio' or 'http'"),
    }
}
