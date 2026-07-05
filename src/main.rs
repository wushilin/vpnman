use axum::{
    Json, Router,
    body::Body,
    extract::{Form, Path, Query, State},
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose};
use chrono::{DateTime, SecondsFormat, Utc};
use clap::Parser;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs, io,
    net::{IpAddr, SocketAddr},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;

const RESERVED_VARS: [&str; 3] = ["ca_cert", "client_cert", "client_key"];

#[derive(Clone)]
struct AppState {
    root: Arc<PathBuf>,
    http: Client,
    update_lock: Arc<Mutex<()>>,
    basic_auth: Option<Arc<BasicAuthRuntime>>,
}

#[derive(Debug, Parser)]
#[command(name = "vpnman", about = "OpenVPN profile manager")]
struct Cli {
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
struct AppConfig {
    data_dir: PathBuf,
    bind: BindConfig,
    #[serde(default)]
    basic_auth: Option<BasicAuthConfig>,
}

#[derive(Debug, Deserialize)]
struct BindConfig {
    host: String,
    port: u16,
}

#[derive(Debug, Deserialize)]
struct BasicAuthConfig {
    #[serde(default)]
    enabled: bool,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Clone)]
struct BasicAuthRuntime {
    expected_header: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MinicaConfig {
    base_url: String,
    username: String,
    password: String,
    default_ca_id: String,
    cert_defaults: CertDefaults,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertDefaults {
    valid_days: u32,
    country_code: String,
    organization: String,
    state: String,
    city: String,
    organization_unit: String,
    digest_algorithm: String,
    #[serde(default = "default_key_profile")]
    key_profile: String,
    dns_list: Vec<String>,
    ip_list: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TemplateMetadata {
    name: String,
    description: String,
    #[serde(default = "default_token_start")]
    token_start: String,
    #[serde(default = "default_token_stop")]
    token_stop: String,
    variables: BTreeMap<String, VariableMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VariableMetadata {
    #[serde(rename = "type")]
    kind: VariableKind,
    description: String,
    #[serde(default)]
    default: String,
    #[serde(default)]
    options: String,
    #[serde(default)]
    min: Option<i64>,
    #[serde(default)]
    max: Option<i64>,
    #[serde(default = "default_true")]
    required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VariableKind {
    Text,
    Number,
    Textarea,
    DropdownCsv,
}

#[derive(Debug, Clone)]
struct Template {
    id: String,
    body: String,
    metadata: TemplateMetadata,
    variables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProfileMetadata {
    client_name: String,
    template_id: String,
    template_name: String,
    ca_id: String,
    ca_common_name: String,
    cert_id: String,
    tags: Vec<String>,
    created_at: DateTime<Utc>,
    variables: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MinicaCa {
    id: String,
    #[serde(alias = "commonName", default)]
    common_name: String,
    #[serde(default)]
    cert_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MinicaCert {
    id: String,
    #[serde(alias = "commonName", default)]
    common_name: String,
    #[serde(default)]
    cert_pem: String,
    #[serde(default)]
    key_pem: String,
}

#[derive(Debug, Deserialize)]
struct ApiEnvelope<T> {
    data: Option<T>,
    error: Option<ApiError>,
    success: bool,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
    status: Option<u16>,
}

#[derive(Debug, Serialize)]
struct TestResponse {
    ok: bool,
    message: String,
    #[serde(default)]
    cas: Vec<MinicaCa>,
}

#[derive(Debug, Serialize)]
struct VpnmanEnvelope<T: Serialize> {
    success: bool,
    error_code: String,
    error_message: String,
    data: Option<T>,
}

#[derive(Debug, Serialize)]
struct ApiTemplate {
    id: String,
    name: String,
    description: String,
    token_start: String,
    token_stop: String,
    variables: BTreeMap<String, VariableMetadata>,
}

#[derive(Debug, Serialize)]
struct ApiProfileSummary {
    id: String,
    metadata: ProfileMetadata,
}

#[derive(Debug, Serialize)]
struct ApiProfile {
    id: String,
    metadata: ProfileMetadata,
    profile: String,
}

#[derive(Debug, Deserialize)]
struct IssueConfigRequest {
    template_id: String,
    #[serde(default)]
    ca_id: Option<String>,
    client_name: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    parameters: BTreeMap<String, String>,
}

#[derive(Debug)]
struct IssueConfigInput {
    template_id: String,
    ca_id: String,
    client_name: String,
    tags: Vec<String>,
    parameters: BTreeMap<String, String>,
}

#[derive(Debug)]
struct ApiFailure {
    status: StatusCode,
    code: &'static str,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CertIdResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct MinicaSettingsForm {
    base_url: String,
    username: String,
    password: String,
    default_ca_id: String,
}

#[derive(Debug, Deserialize)]
struct CertDefaultsForm {
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    default_ca_id: Option<String>,
    valid_days: u32,
    country_code: String,
    organization: String,
    state: String,
    city: String,
    organization_unit: String,
    digest_algorithm: String,
    key_profile: String,
    dns_list: String,
    ip_list: String,
}

#[derive(Debug, Deserialize)]
struct TemplateSaveForm {
    id: String,
    name: String,
    description: String,
    token_start: String,
    token_stop: String,
    body: String,
    variables_yaml: String,
}

#[derive(Debug, Deserialize)]
struct GenerateForm {
    template_id: String,
    ca_id: String,
    client_name: String,
    tags: String,
    #[serde(flatten)]
    values: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct GenerateQuery {
    template_id: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_key_profile() -> String {
    "rsa:4096".to_string()
}

fn default_token_start() -> String {
    "%".to_string()
}

fn default_token_stop() -> String {
    "%".to_string()
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = match load_app_config(&cli.config) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let root = config.data_dir;
    ensure_dirs(&root).expect("failed to initialize data directories");
    ensure_default_config(&root).expect("failed to initialize minica config");
    let bind_addr = match bind_addr(&config.bind) {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let basic_auth = match basic_auth_runtime(config.basic_auth.as_ref()) {
        Ok(auth) => auth.map(Arc::new),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };

    let state = AppState {
        root: Arc::new(root),
        http: Client::builder()
            .cookie_store(true)
            .build()
            .expect("failed to build HTTP client"),
        update_lock: Arc::new(Mutex::new(())),
        basic_auth,
    };

    let app = Router::new()
        .route("/", get(root_redirect))
        .route("/vpnman", get(root_redirect))
        .route("/vpnman/", get(index))
        .route(
            "/vpnman/settings/minica",
            get(minica_settings).post(save_minica_settings),
        )
        .route("/vpnman/settings/minica/test", post(test_minica_settings))
        .route(
            "/vpnman/settings/minica/cert-defaults",
            post(save_cert_defaults),
        )
        .route(
            "/vpnman/settings/minica/cert-defaults/test",
            post(test_cert_defaults),
        )
        .route("/vpnman/templates", get(templates_index))
        .route("/vpnman/templates/new", post(create_template))
        .route(
            "/vpnman/templates/{id}/edit",
            get(edit_template).post(save_template),
        )
        .route("/vpnman/templates/{id}/delete", post(delete_template))
        .route(
            "/vpnman/generate",
            get(generate_form).post(generate_profile),
        )
        .route("/vpnman/profiles", get(profiles_index))
        .route("/vpnman/profiles/{id}", get(profile_detail))
        .route("/vpnman/profiles/{id}/download", get(download_profile))
        .route("/vpnman/profiles/{id}/delete", post(delete_profile))
        .route("/vpnman/api/templates", get(api_list_templates))
        .route("/vpnman/api/cas", get(api_list_cas))
        .route("/vpnman/api/configs", post(api_issue_config))
        .route("/vpnman/api/profiles", get(api_list_profiles))
        .route("/vpnman/api/profiles/{id}", get(api_get_profile))
        .route("/vpnman/api/openapi.json", get(openapi_json))
        .route("/vpnman/api/swagger", get(swagger_explorer))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ))
        .with_state(state);

    println!("vpnman listening on http://{bind_addr}");
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("bind failed");
    axum::serve(listener, app).await.expect("server failed");
}

async fn root_redirect() -> Redirect {
    Redirect::to("/vpnman/")
}

fn load_app_config(path: &FsPath) -> Result<AppConfig, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read config '{}': {err}", path.display()))?;
    let config = serde_yaml::from_str::<AppConfig>(&text)
        .map_err(|err| format!("invalid config '{}': {err}", path.display()))?;
    validate_app_config(&config)
        .map_err(|err| format!("invalid config '{}': {err}", path.display()))?;
    Ok(config)
}

fn validate_app_config(config: &AppConfig) -> Result<(), String> {
    if config.data_dir.as_os_str().is_empty() {
        return Err("data_dir is required".to_string());
    }
    if config.bind.host.trim().is_empty() {
        return Err("bind.host is required".to_string());
    }
    if contains_crlf(&config.bind.host) {
        return Err("bind.host must not contain CR or LF".to_string());
    }
    if let Some(auth) = &config.basic_auth {
        if auth.enabled {
            let username = auth
                .username
                .as_deref()
                .ok_or_else(|| "basic_auth.username is required when enabled".to_string())?;
            let password = auth
                .password
                .as_deref()
                .ok_or_else(|| "basic_auth.password is required when enabled".to_string())?;
            if username.is_empty() {
                return Err("basic_auth.username must not be empty when enabled".to_string());
            }
            if password.is_empty() {
                return Err("basic_auth.password must not be empty when enabled".to_string());
            }
            if contains_crlf(username) {
                return Err("basic_auth.username must not contain CR or LF".to_string());
            }
            if contains_crlf(password) {
                return Err("basic_auth.password must not contain CR or LF".to_string());
            }
        }
    }
    Ok(())
}

fn bind_addr(bind: &BindConfig) -> Result<SocketAddr, String> {
    let host = bind
        .host
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid bind.host '{}': {err}", bind.host))?;
    Ok(SocketAddr::new(host, bind.port))
}

fn basic_auth_runtime(
    config: Option<&BasicAuthConfig>,
) -> Result<Option<BasicAuthRuntime>, String> {
    let Some(config) = config else {
        return Ok(None);
    };
    if !config.enabled {
        return Ok(None);
    }
    let username = config
        .username
        .as_deref()
        .ok_or_else(|| "basic_auth.username is required when enabled".to_string())?;
    let password = config
        .password
        .as_deref()
        .ok_or_else(|| "basic_auth.password is required when enabled".to_string())?;
    let encoded = general_purpose::STANDARD.encode(format!("{username}:{password}"));
    Ok(Some(BasicAuthRuntime {
        expected_header: format!("Basic {encoded}"),
    }))
}

async fn security_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let is_api = req.uri().path().starts_with("/vpnman/api/");
    if request_has_crlf(&req) {
        if is_api {
            return api_error(
                StatusCode::BAD_REQUEST,
                "invalid_crlf",
                "request contains invalid CR/LF characters",
            );
        }
        return (
            StatusCode::BAD_REQUEST,
            "request contains invalid CR/LF characters",
        )
            .into_response();
    }
    if let Some(auth) = &state.basic_auth {
        let authorized = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(|value| constant_time_eq(value.as_bytes(), auth.expected_header.as_bytes()))
            .unwrap_or(false);
        if !authorized {
            if is_api {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(header::WWW_AUTHENTICATE, "Basic realm=\"vpnman\"")],
                    Json(VpnmanEnvelope::<Value> {
                        success: false,
                        error_code: "authentication_required".to_string(),
                        error_message: "authentication required".to_string(),
                        data: None,
                    }),
                )
                    .into_response();
            }
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Basic realm=\"vpnman\"")],
                "authentication required",
            )
                .into_response();
        }
    }
    next.run(req).await
}

fn request_has_crlf(req: &Request<Body>) -> bool {
    contains_crlf(req.uri().path())
        || req.uri().query().is_some_and(contains_crlf)
        || req.headers().iter().any(|(name, value)| {
            contains_crlf(name.as_str()) || value.to_str().map(contains_crlf).unwrap_or(true)
        })
}

fn contains_crlf(value: &str) -> bool {
    value.contains('\r') || value.contains('\n')
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let templates = load_templates(&state.root).unwrap_or_default();
    let profiles = load_profiles(&state.root).unwrap_or_default();
    let cfg = read_minica_config(&state.root).unwrap_or_else(|_| default_minica_config());
    let ca_status = if cfg.base_url.trim().is_empty()
        || cfg.username.trim().is_empty()
        || cfg.default_ca_id.trim().is_empty()
    {
        "Certificate Authority not configured"
    } else {
        "Certificate Authority configured"
    };
    page_without_heading(
        "VPN Manager",
        &format!(
            r#"
            <section class="grid three">
              <div class="panel summary-card"><span class="metric">{}</span><span class="label">OpenVPN Templates</span></div>
              <div class="panel summary-card"><span class="metric">{}</span><span class="label">OpenVPN Configs</span></div>
              <div class="panel summary-card"><span class="metric status">{}</span><span class="label">Certificate Authority</span></div>
            </section>
            "#,
            templates.len(),
            profiles.len(),
            esc(ca_status)
        ),
    )
}

async fn minica_settings(State(state): State<AppState>) -> Html<String> {
    let cfg = read_minica_config(&state.root).unwrap_or_else(|_| default_minica_config());
    let ca_result = minica_list_cas(&state, &cfg).await;
    let ca_options = ca_result
        .as_ref()
        .map(|cas| ca_select_options(cas, &cfg.default_ca_id))
        .unwrap_or_else(|_| ca_select_options(&[], &cfg.default_ca_id));
    let ca_html = match ca_result {
        Ok(cas) if cas.is_empty() => {
            "<p class=\"muted\">Connected, but no CAs were returned.</p>".to_string()
        }
        Ok(cas) => {
            let rows = cas
                .iter()
                .map(|ca| {
                    format!(
                        "<tr><td>{}</td><td><code>{}</code></td></tr>",
                        esc(&ca.common_name),
                        esc(&ca.id)
                    )
                })
                .collect::<String>();
            format!(
                "<table><thead><tr><th>Common name</th><th>ID</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        }
        Err(err) => format!(
            "<p class=\"error\">Connection test failed: {}</p>",
            esc(&err)
        ),
    };

    page(
        "Certificate Authority Config",
        &format!(
            r#"
            <form method="post" class="panel form js-test-form" data-test-url="/vpnman/settings/minica/test" data-save-confirm="Save certificate authority settings?">
              <h2>Minica Settings</h2>
              <div class="field"><label>Base URL</label><input name="base_url" value="{}" placeholder="http://localhost:9988"></div>
              <div class="row">
                <div class="field"><label>Username</label><input name="username" value="{}"></div>
                <div class="field"><label>Password</label><input name="password" type="password" value="{}"></div>
              </div>
              <div class="field"><label>Default CA ID</label><select name="default_ca_id" class="js-ca-select" data-current="{}">{}</select></div>
              <p class="test-result" aria-live="polite"></p>
              <div class="toolbar compact">
                <button class="button primary js-confirm-save" type="submit">Save</button>
                <button class="button js-inline-test" type="button">Test</button>
                <button class="button" type="reset">Reset</button>
              </div>
              <h2>Available CAs</h2>
              {}
            </form>
            <form method="post" action="/vpnman/settings/minica/cert-defaults" class="panel form js-test-form" data-test-url="/vpnman/settings/minica/cert-defaults/test" data-save-confirm="Save certificate defaults?">
              <h2>Certificate Defaults</h2>
              <input type="hidden" name="base_url" class="js-ca-shadow" data-source="base_url">
              <input type="hidden" name="username" class="js-ca-shadow" data-source="username">
              <input type="hidden" name="password" class="js-ca-shadow" data-source="password">
              <input type="hidden" name="default_ca_id" class="js-ca-shadow" data-source="default_ca_id">
              <div class="row">
                <div class="field"><label>Valid days</label><input name="valid_days" type="number" value="{}"></div>
                <div class="field"><label>Key profile</label><select name="key_profile">
                  {}
                </select></div>
              </div>
              <div class="row">
                <div class="field"><label>Country code</label><input name="country_code" value="{}"></div>
                <div class="field"><label>Digest algorithm</label><input name="digest_algorithm" value="{}"></div>
              </div>
              <div class="row">
                <div class="field"><label>Organization</label><input name="organization" value="{}"></div>
                <div class="field"><label>Organization unit</label><input name="organization_unit" value="{}"></div>
              </div>
              <div class="row">
                <div class="field"><label>State</label><input name="state" value="{}"></div>
                <div class="field"><label>City</label><input name="city" value="{}"></div>
              </div>
              <div class="row">
                <div class="field"><label>DNS list</label><input name="dns_list" value="{}" placeholder="vpn.example.com,*.example.com"></div>
                <div class="field"><label>IP list</label><input name="ip_list" value="{}" placeholder="10.0.0.1,10.0.0.2"></div>
              </div>
              <p class="test-result" aria-live="polite"></p>
              <div class="toolbar compact">
                <button class="button primary js-confirm-save" type="submit">Save</button>
                <button class="button js-inline-test" type="button">Test</button>
                <button class="button" type="reset">Reset</button>
              </div>
            </form>
            "#,
            esc(&cfg.base_url),
            esc(&cfg.username),
            esc(&cfg.password),
            esc(&cfg.default_ca_id),
            ca_options,
            ca_html,
            cfg.cert_defaults.valid_days,
            key_profile_options(&cfg.cert_defaults.key_profile),
            esc(&cfg.cert_defaults.country_code),
            esc(&cfg.cert_defaults.digest_algorithm),
            esc(&cfg.cert_defaults.organization),
            esc(&cfg.cert_defaults.organization_unit),
            esc(&cfg.cert_defaults.state),
            esc(&cfg.cert_defaults.city),
            esc(&cfg.cert_defaults.dns_list.join(",")),
            esc(&cfg.cert_defaults.ip_list.join(","))
        ),
    )
}

async fn save_minica_settings(
    State(state): State<AppState>,
    Form(form): Form<MinicaSettingsForm>,
) -> impl IntoResponse {
    let _guard = state.update_lock.lock().await;
    let mut cfg = read_minica_config(&state.root).unwrap_or_else(|_| default_minica_config());
    cfg.base_url = form.base_url.trim().trim_end_matches('/').to_string();
    cfg.username = form.username;
    cfg.password = form.password;
    cfg.default_ca_id = form.default_ca_id;

    match write_yaml(&minica_config_path(&state.root), &cfg) {
        Ok(_) => Redirect::to("/vpnman/settings/minica").into_response(),
        Err(err) => error_page("Failed To Save Settings", err).into_response(),
    }
}

async fn test_minica_settings(
    State(state): State<AppState>,
    Form(form): Form<MinicaSettingsForm>,
) -> Json<TestResponse> {
    let mut cfg = read_minica_config(&state.root).unwrap_or_else(|_| default_minica_config());
    cfg.base_url = form.base_url.trim().trim_end_matches('/').to_string();
    cfg.username = form.username;
    cfg.password = form.password;
    cfg.default_ca_id = form.default_ca_id;

    match minica_list_cas(&state, &cfg).await {
        Ok(cas) => Json(TestResponse {
            ok: true,
            message: format!("OK: listed {} CA(s)", cas.len()),
            cas,
        }),
        Err(err) => Json(TestResponse {
            ok: false,
            message: format!("Not OK: {err}"),
            cas: Vec::new(),
        }),
    }
}

async fn save_cert_defaults(
    State(state): State<AppState>,
    Form(form): Form<CertDefaultsForm>,
) -> impl IntoResponse {
    let _guard = state.update_lock.lock().await;
    let mut cfg = read_minica_config(&state.root).unwrap_or_else(|_| default_minica_config());
    if let Some(base_url) = form.base_url.as_ref() {
        cfg.base_url = base_url.trim().trim_end_matches('/').to_string();
    }
    if let Some(username) = form.username.as_ref() {
        cfg.username = username.clone();
    }
    if let Some(password) = form.password.as_ref() {
        cfg.password = password.clone();
    }
    if let Some(default_ca_id) = form.default_ca_id.as_ref() {
        cfg.default_ca_id = default_ca_id.clone();
    }
    cfg.cert_defaults = CertDefaults {
        valid_days: form.valid_days,
        country_code: form.country_code,
        organization: form.organization,
        state: form.state,
        city: form.city,
        organization_unit: form.organization_unit,
        digest_algorithm: form.digest_algorithm,
        key_profile: form.key_profile,
        dns_list: parse_csv(&form.dns_list),
        ip_list: parse_csv(&form.ip_list),
    };

    match write_yaml(&minica_config_path(&state.root), &cfg) {
        Ok(_) => Redirect::to("/vpnman/settings/minica").into_response(),
        Err(err) => error_page("Failed To Save Certificate Defaults", err).into_response(),
    }
}

async fn test_cert_defaults(
    State(state): State<AppState>,
    Form(form): Form<CertDefaultsForm>,
) -> Json<TestResponse> {
    let _guard = state.update_lock.lock().await;
    let mut cfg = read_minica_config(&state.root).unwrap_or_else(|_| default_minica_config());
    cfg.cert_defaults = CertDefaults {
        valid_days: form.valid_days,
        country_code: form.country_code,
        organization: form.organization,
        state: form.state,
        city: form.city,
        organization_unit: form.organization_unit,
        digest_algorithm: form.digest_algorithm,
        key_profile: form.key_profile,
        dns_list: parse_csv(&form.dns_list),
        ip_list: parse_csv(&form.ip_list),
    };
    let ca_id = cfg.default_ca_id.clone();
    if ca_id.trim().is_empty() {
        return Json(TestResponse {
            ok: false,
            message: "Not OK: Default CA ID is required for certificate test".to_string(),
            cas: Vec::new(),
        });
    }
    let test_cn = format!("test-{}", &Uuid::new_v4().simple().to_string()[..5]);
    match minica_create_cert(&state, &cfg, &ca_id, &test_cn).await {
        Ok(cert) => match minica_delete_cert(&state, &cfg, &ca_id, &cert.id).await {
            Ok(_) => Json(TestResponse {
                ok: true,
                message: format!("OK: issued and deleted {test_cn}"),
                cas: Vec::new(),
            }),
            Err(err) => Json(TestResponse {
                ok: false,
                message: format!("Not OK: issued {test_cn}, but could not delete it: {err}"),
                cas: Vec::new(),
            }),
        },
        Err(err) => Json(TestResponse {
            ok: false,
            message: format!("Not OK: can't test: {err}"),
            cas: Vec::new(),
        }),
    }
}

async fn templates_index(State(state): State<AppState>) -> Html<String> {
    let templates = load_templates(&state.root).unwrap_or_default();
    let rows = templates
        .iter()
        .map(|t| {
            format!(
                r#"<tr><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td><a class="button small" href="/vpnman/templates/{}/edit">Edit</a> <form class="inline js-confirm-delete" method="post" action="/vpnman/templates/{}/delete" data-confirm="Delete this OpenVPN template?"><button class="button danger small" type="submit">Delete</button></form></td></tr>"#,
                esc(&t.metadata.name),
                esc(&t.metadata.description),
                esc(&t.id),
                t.variables.len(),
                esc(&t.id),
                esc(&t.id),
            )
        })
        .collect::<String>();
    page(
        "OpenVPN Templates",
        &format!(
            r#"
            <form method="post" action="/vpnman/templates/new" class="toolbar"><button class="button primary" type="submit">New</button></form>
            <table><thead><tr><th>Name</th><th>Description</th><th>ID</th><th>Variables</th><th></th></tr></thead><tbody>{}</tbody></table>
            "#,
            rows
        ),
    )
}

async fn create_template(State(state): State<AppState>) -> impl IntoResponse {
    let _guard = state.update_lock.lock().await;
    let id = unique_id("template");
    let dir = templates_dir(&state.root).join(&id);
    let body = sample_template();
    let mut metadata = TemplateMetadata {
        name: "Standard OpenVPN Client".to_string(),
        description: "Self-contained client profile".to_string(),
        token_start: default_token_start(),
        token_stop: default_token_stop(),
        variables: BTreeMap::new(),
    };
    sync_metadata_with_body(&body, &mut metadata);
    metadata.name = unique_template_name(&state.root, &metadata.name, None);

    let result = fs::create_dir_all(&dir)
        .and_then(|_| fs::write(dir.join("template.ovpn"), body))
        .and_then(|_| write_yaml(&dir.join("metadata.yaml"), &metadata));

    match result {
        Ok(_) => Redirect::to(&format!("/vpnman/templates/{id}/edit")).into_response(),
        Err(err) => error_page("Failed To Create Template", err).into_response(),
    }
}

async fn delete_template(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !valid_storage_id(&id) {
        return error_page("Invalid Template ID", "template ID is not valid").into_response();
    }
    let dir = templates_dir(&state.root).join(&id);
    let _guard = state.update_lock.lock().await;
    match fs::remove_dir_all(dir) {
        Ok(_) => Redirect::to("/vpnman/templates").into_response(),
        Err(err) => error_page("Failed To Delete Template", err).into_response(),
    }
}

async fn edit_template(State(state): State<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    if !valid_storage_id(&id) {
        return error_page("Invalid Template ID", "template ID is not valid").into_response();
    }
    match load_template(&state.root, &id) {
        Ok(template) => {
            let vars_yaml = serde_yaml::to_string(&template.metadata.variables).unwrap_or_default();
            let reserved = template
                .variables
                .iter()
                .filter(|v| is_reserved(v))
                .map(|v| format!("<code>{}</code>", esc(v)))
                .collect::<Vec<_>>()
                .join(" ");
            Html(template_page(
                "Edit Template",
                &format!(
                    r#"
                    <form method="post" class="panel form">
                      <input type="hidden" name="id" value="{}">
                      <div class="row">
                        <div class="field"><label>Name</label><input name="name" value="{}"></div>
                        <div class="field"><label>Template ID</label><input value="{}" disabled></div>
                      </div>
                      <div class="field"><label>Description</label><input name="description" value="{}"></div>
                      <div class="row">
                        <div class="field"><label>Token start</label><input name="token_start" value="{}" required></div>
                        <div class="field"><label>Token stop</label><input name="token_stop" value="{}" required></div>
                      </div>
                      <div class="field"><label>OpenVPN Template</label><textarea name="body" class="code" rows="18">{}</textarea></div>
                      <div class="field"><label>Variable Metadata YAML</label><textarea name="variables_yaml" class="code" rows="14">{}</textarea></div>
                      <p class="muted">Detected variables are synchronized on save. Reserved auto-filled variables: {}</p>
                      <button class="button primary" type="submit">Save Template</button>
                    </form>
                    "#,
                    esc(&template.id),
                    esc(&template.metadata.name),
                    esc(&template.id),
                    esc(&template.metadata.description),
                    esc(&template.metadata.token_start),
                    esc(&template.metadata.token_stop),
                    esc(&template.body),
                    esc(&vars_yaml),
                    reserved
                ),
            ))
            .into_response()
        }
        Err(err) => error_page("Template Not Found", err).into_response(),
    }
}

async fn save_template(
    State(state): State<AppState>,
    Form(form): Form<TemplateSaveForm>,
) -> impl IntoResponse {
    if !valid_storage_id(&form.id) {
        return error_page("Invalid Template ID", "template ID is not valid").into_response();
    }
    let mut metadata = TemplateMetadata {
        name: form.name,
        description: form.description,
        token_start: form.token_start,
        token_stop: form.token_stop,
        variables: match serde_yaml::from_str::<BTreeMap<String, VariableMetadata>>(
            &form.variables_yaml,
        ) {
            Ok(vars) => vars,
            Err(err) => return error_page("Invalid Variable YAML", err).into_response(),
        },
    };
    if let Err(err) = validate_token_delimiters(&metadata) {
        return error_page("Invalid Token Delimiters", err).into_response();
    }
    sync_metadata_with_body(&form.body, &mut metadata);
    if let Err(err) = validate_variable_definitions(&metadata) {
        return error_page("Invalid Variable Metadata", err).into_response();
    }
    let _guard = state.update_lock.lock().await;
    if let Err(err) = validate_unique_template_name(&state.root, &metadata.name, Some(&form.id)) {
        return error_page("Template Name Must Be Unique", err).into_response();
    }

    let dir = templates_dir(&state.root).join(&form.id);
    let result = fs::create_dir_all(&dir)
        .and_then(|_| fs::write(dir.join("template.ovpn"), form.body))
        .and_then(|_| write_yaml(&dir.join("metadata.yaml"), &metadata));

    match result {
        Ok(_) => Redirect::to(&format!("/vpnman/templates/{}/edit", form.id)).into_response(),
        Err(err) => error_page("Failed To Save Template", err).into_response(),
    }
}

async fn generate_form(
    State(state): State<AppState>,
    Query(query): Query<GenerateQuery>,
) -> Html<String> {
    let templates = load_templates(&state.root).unwrap_or_default();
    let cfg = read_minica_config(&state.root).unwrap_or_else(|_| default_minica_config());
    let cas = minica_list_cas(&state, &cfg).await.unwrap_or_default();
    let selected_template_id = query
        .template_id
        .or_else(|| templates.first().map(|t| t.id.clone()))
        .unwrap_or_default();

    let template_options = templates
        .iter()
        .map(|t| {
            let selected = if t.id == selected_template_id {
                " selected"
            } else {
                ""
            };
            format!(
                "<option value=\"{}\"{}>{}</option>",
                esc(&t.id),
                selected,
                esc(&t.metadata.name)
            )
        })
        .collect::<String>();
    let ca_options = cas
        .iter()
        .map(|ca| {
            let selected = if ca.id == cfg.default_ca_id {
                " selected"
            } else {
                ""
            };
            format!(
                "<option value=\"{}\"{}>{} ({})</option>",
                esc(&ca.id),
                selected,
                esc(&ca.common_name),
                esc(&ca.id)
            )
        })
        .collect::<String>();

    let template_fields = templates
        .iter()
        .find(|t| t.id == selected_template_id)
        .map(render_template_variable_inputs)
        .unwrap_or_else(|| {
            "<p class=\"muted\">Create a template before generating a profile.</p>".to_string()
        });

    page(
        "Generate Profile",
        &format!(
            r#"
            <form method="post" class="panel form">
              <div class="row">
                <div class="field"><label>Template</label><select name="template_id" onchange="window.location='/vpnman/generate?template_id='+encodeURIComponent(this.value)">{}</select></div>
                <div class="field"><label>Certificate Authority</label><select name="ca_id">{}</select></div>
              </div>
              <div class="row">
                <div class="field"><label>Client name</label><input name="client_name" required></div>
                <div class="field"><label>Tags</label><input name="tags" placeholder="laptop,team=engineering,region=sg"></div>
              </div>
              <h2>Template Values</h2>
              {}
              <button class="button primary" type="submit">Generate Profile</button>
            </form>
            "#,
            template_options, ca_options, template_fields
        ),
    )
}

async fn generate_profile(
    State(state): State<AppState>,
    Form(form): Form<GenerateForm>,
) -> impl IntoResponse {
    let _guard = state.update_lock.lock().await;
    let parameters = form
        .values
        .into_iter()
        .filter_map(|(key, value)| key.strip_prefix("var_").map(|var| (var.to_string(), value)))
        .collect::<BTreeMap<_, _>>();
    let input = IssueConfigInput {
        template_id: form.template_id,
        ca_id: form.ca_id,
        client_name: form.client_name,
        tags: parse_csv(&form.tags),
        parameters,
    };
    match issue_openvpn_config(&state, input).await {
        Ok(_) => Redirect::to("/vpnman/profiles").into_response(),
        Err(err) => error_page(err.code, err.message).into_response(),
    }
}

async fn issue_openvpn_config(
    state: &AppState,
    input: IssueConfigInput,
) -> Result<ApiProfile, ApiFailure> {
    let cfg = read_minica_config(&state.root).map_err(|err| ApiFailure {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "minica_config_missing",
        message: err.to_string(),
    })?;
    let template = load_template(&state.root, &input.template_id).map_err(|err| ApiFailure {
        status: StatusCode::NOT_FOUND,
        code: "template_not_found",
        message: err.to_string(),
    })?;

    let mut vars = BTreeMap::new();
    for var in &template.variables {
        if is_reserved(var) {
            continue;
        }
        let value = input.parameters.get(var).cloned().unwrap_or_default();
        let meta = template
            .metadata
            .variables
            .get(var)
            .cloned()
            .unwrap_or_else(|| default_variable(var));
        if meta.required && value.trim().is_empty() {
            return Err(ApiFailure {
                status: StatusCode::BAD_REQUEST,
                code: "missing_required_parameter",
                message: format!("{var} is required"),
            });
        }
        validate_variable_value(var, &meta, &value).map_err(|err| ApiFailure {
            status: StatusCode::BAD_REQUEST,
            code: "invalid_parameter",
            message: err,
        })?;
        vars.insert(var.clone(), value);
    }

    let ca = minica_get_ca(state, &cfg, &input.ca_id)
        .await
        .map_err(|err| ApiFailure {
            status: StatusCode::BAD_GATEWAY,
            code: "failed_to_load_ca",
            message: err,
        })?;

    let cert = minica_find_or_create_cert(state, &cfg, &input.ca_id, &input.client_name)
        .await
        .map_err(|err| ApiFailure {
            status: StatusCode::BAD_GATEWAY,
            code: "failed_to_get_client_certificate",
            message: err,
        })?;

    if ca.cert_pem.trim().is_empty() {
        return Err(ApiFailure {
            status: StatusCode::BAD_GATEWAY,
            code: "missing_ca_cert",
            message: "Minica CA response did not include cert_pem".to_string(),
        });
    }
    if cert.cert_pem.trim().is_empty() || cert.key_pem.trim().is_empty() {
        return Err(ApiFailure {
            status: StatusCode::BAD_GATEWAY,
            code: "missing_client_material",
            message: "Minica certificate response did not include cert_pem and key_pem".to_string(),
        });
    }

    let mut replacements = vars.clone();
    replacements.insert("ca_cert".to_string(), ca.cert_pem.trim().to_string());
    replacements.insert("client_cert".to_string(), cert.cert_pem.trim().to_string());
    replacements.insert("client_key".to_string(), cert.key_pem.trim().to_string());
    let rendered = render_template(&template.body, &template.metadata, &replacements);

    let profile_id = unique_id(&slugify(&input.client_name));
    let profile_dir = profiles_dir(&state.root).join(&profile_id);
    let metadata = ProfileMetadata {
        client_name: input.client_name,
        template_id: template.id,
        template_name: template.metadata.name,
        ca_id: input.ca_id,
        ca_common_name: ca.common_name,
        cert_id: cert.id,
        tags: input.tags,
        created_at: Utc::now(),
        variables: vars,
    };

    fs::create_dir_all(&profile_dir)
        .and_then(|_| fs::write(profile_dir.join("profile.ovpn"), &rendered))
        .and_then(|_| write_yaml(&profile_dir.join("metadata.yaml"), &metadata))
        .map_err(|err| ApiFailure {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "failed_to_save_profile",
            message: err.to_string(),
        })?;

    Ok(ApiProfile {
        id: profile_id,
        metadata,
        profile: rendered,
    })
}

async fn profiles_index(State(state): State<AppState>) -> Html<String> {
    let profiles = load_profiles(&state.root).unwrap_or_default();
    let rows = profiles
        .iter()
        .map(|(id, meta)| {
            format!(
                r#"<tr><td><a href="/vpnman/profiles/{}">{}</a></td><td>{}</td><td>{}</td><td title="{}">{}</td><td><a class="button small" href="/vpnman/profiles/{}/download">Download</a> <form class="inline js-confirm-delete" method="post" action="/vpnman/profiles/{}/delete" data-confirm="Delete this OpenVPN config?"><button class="button danger small" type="submit">Delete</button></form></td></tr>"#,
                esc(id),
                esc(&meta.client_name),
                esc(&meta.ca_common_name),
                render_parameter_chips(&meta.variables),
                esc(&days_ago_title(meta.created_at)),
                esc(&meta.created_at.date_naive().to_string()),
                esc(id),
                esc(id),
            )
        })
        .collect::<String>();
    page(
        "OpenVPN Configs",
        &format!(
            r#"<section class="toolbar"><a class="button primary" href="/vpnman/generate">New</a></section><table class="configs-table"><thead><tr><th>Client</th><th>CA</th><th>Parameters</th><th>Created</th><th></th></tr></thead><tbody>{}</tbody></table>"#,
            rows
        ),
    )
}

async fn profile_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !valid_storage_id(&id) {
        return error_page("Invalid Profile ID", "profile ID is not valid").into_response();
    }
    let dir = profiles_dir(&state.root).join(&id);
    let meta = match read_yaml::<ProfileMetadata>(&dir.join("metadata.yaml")) {
        Ok(meta) => meta,
        Err(err) => return error_page("Profile Not Found", err).into_response(),
    };
    let raw = match fs::read_to_string(dir.join("profile.ovpn")) {
        Ok(raw) => raw,
        Err(err) => return error_page("Profile Not Found", err).into_response(),
    };
    let variables = meta
        .variables
        .iter()
        .map(|(key, value)| {
            format!(
                "<tr><td class=\"param-key-cell\">{}</td><td class=\"param-value-cell\">{}</td></tr>",
                esc(key),
                esc(value)
            )
        })
        .collect::<String>();
    Html(config_page(
        &meta.client_name,
        &format!(
            r#"
            <section class="toolbar">
              <a class="button" href="/vpnman/profiles">Back</a>
              <a class="button primary" href="/vpnman/profiles/{}/download">Download</a>
              <form class="inline js-confirm-delete" method="post" action="/vpnman/profiles/{}/delete" data-confirm="Delete this OpenVPN config?"><button class="button danger" type="submit">Delete</button></form>
            </section>
            <section class="panel">
              <h2>Details</h2>
              <dl class="details">
                <dt>Client</dt><dd>{}</dd>
                <dt>Template</dt><dd>{}</dd>
                <dt>Certificate Authority</dt><dd>{}</dd>
                <dt>Certificate ID</dt><dd><code>{}</code></dd>
                <dt>Tags</dt><dd>{}</dd>
                <dt>Created</dt><dd title="{}">{}</dd>
              </dl>
            </section>
            <section class="panel">
              <h2>Template Values</h2>
              <table class="parameters-table"><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>{}</tbody></table>
            </section>
            <section class="panel">
              <h2>Raw Profile</h2>
              <textarea class="code raw" readonly>{}</textarea>
            </section>
            "#,
            esc(&id),
            esc(&id),
            esc(&meta.client_name),
            esc(&meta.template_name),
            esc(&meta.ca_common_name),
            esc(&meta.cert_id),
            esc(&meta.tags.join(", ")),
            esc(&days_ago_title(meta.created_at)),
            esc(&iso8601_seconds(meta.created_at)),
            variables,
            esc(&raw)
        ),
    ))
    .into_response()
}

async fn download_profile(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !valid_storage_id(&id) {
        return error_page("Invalid Profile ID", "profile ID is not valid").into_response();
    }
    let path = profiles_dir(&state.root).join(&id).join("profile.ovpn");
    match fs::read(path) {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/x-openvpn-profile"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=\"profile.ovpn\"",
                ),
            ],
            bytes,
        )
            .into_response(),
        Err(err) => error_page("Profile Not Found", err).into_response(),
    }
}

async fn delete_profile(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if !valid_storage_id(&id) {
        return error_page("Invalid Profile ID", "profile ID is not valid").into_response();
    }
    let dir = profiles_dir(&state.root).join(&id);
    let _guard = state.update_lock.lock().await;
    match fs::remove_dir_all(dir) {
        Ok(_) => Redirect::to("/vpnman/profiles").into_response(),
        Err(err) => error_page("Failed To Delete Profile", err).into_response(),
    }
}

async fn api_list_templates(State(state): State<AppState>) -> Response {
    match load_templates(&state.root) {
        Ok(templates) => api_ok(
            templates
                .into_iter()
                .map(|template| ApiTemplate {
                    id: template.id,
                    name: template.metadata.name,
                    description: template.metadata.description,
                    token_start: template.metadata.token_start,
                    token_stop: template.metadata.token_stop,
                    variables: template.metadata.variables,
                })
                .collect::<Vec<_>>(),
        ),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed_to_list_templates",
            err,
        ),
    }
}

async fn api_list_cas(State(state): State<AppState>) -> Response {
    let cfg = match read_minica_config(&state.root) {
        Ok(cfg) => cfg,
        Err(err) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "minica_config_missing",
                err,
            );
        }
    };
    match minica_list_cas(&state, &cfg).await {
        Ok(cas) => api_ok(cas),
        Err(err) => api_error(StatusCode::BAD_GATEWAY, "failed_to_list_cas", err),
    }
}

async fn api_issue_config(
    State(state): State<AppState>,
    payload: Result<Json<IssueConfigRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(request) = match payload {
        Ok(payload) => payload,
        Err(err) => {
            return api_error(StatusCode::BAD_REQUEST, "invalid_json", err);
        }
    };
    let _guard = state.update_lock.lock().await;
    let ca_id = match resolve_api_ca_id(&state, request.ca_id.as_deref()) {
        Ok(ca_id) => ca_id,
        Err(err) => return api_failure(err),
    };
    let input = IssueConfigInput {
        template_id: request.template_id,
        ca_id,
        client_name: request.client_name,
        tags: request.tags,
        parameters: request.parameters,
    };
    match issue_openvpn_config(&state, input).await {
        Ok(profile) => api_ok(profile),
        Err(err) => api_failure(err),
    }
}

fn resolve_api_ca_id(state: &AppState, requested: Option<&str>) -> Result<String, ApiFailure> {
    if let Some(ca_id) = requested.map(str::trim).filter(|value| !value.is_empty()) {
        return Ok(ca_id.to_string());
    }
    let cfg = read_minica_config(&state.root).map_err(|err| ApiFailure {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "minica_config_missing",
        message: err.to_string(),
    })?;
    if cfg.default_ca_id.trim().is_empty() {
        return Err(ApiFailure {
            status: StatusCode::BAD_REQUEST,
            code: "default_ca_missing",
            message: "ca_id was omitted and no default CA ID is configured".to_string(),
        });
    }
    Ok(cfg.default_ca_id)
}

async fn api_list_profiles(State(state): State<AppState>) -> Response {
    match load_profiles(&state.root) {
        Ok(profiles) => api_ok(
            profiles
                .into_iter()
                .map(|(id, metadata)| ApiProfileSummary { id, metadata })
                .collect::<Vec<_>>(),
        ),
        Err(err) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed_to_list_profiles",
            err,
        ),
    }
}

async fn api_get_profile(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    match load_api_profile(&state.root, &id) {
        Ok(profile) => api_ok(profile),
        Err(err) => api_error(StatusCode::NOT_FOUND, "profile_not_found", err),
    }
}

async fn openapi_json() -> Json<Value> {
    Json(openapi_spec())
}

async fn swagger_explorer() -> Html<String> {
    page(
        "Swagger Explorer",
        r#"
        <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
        <section class="panel swagger-panel">
          <div id="swagger-ui"></div>
        </section>
        <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
        <script>
          window.addEventListener('load', () => {
            window.ui = SwaggerUIBundle({
              url: '/vpnman/api/openapi.json',
              dom_id: '#swagger-ui',
              deepLinking: true,
              presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
              ],
              layout: 'BaseLayout',
              requestInterceptor: (request) => {
                request.credentials = 'same-origin';
                return request;
              }
            });
          });
        </script>
        "#,
    )
}

fn load_api_profile(root: &FsPath, id: &str) -> Result<ApiProfile, String> {
    if !valid_storage_id(id) {
        return Err("profile ID is not valid".to_string());
    }
    let dir = profiles_dir(root).join(id);
    let metadata =
        read_yaml::<ProfileMetadata>(&dir.join("metadata.yaml")).map_err(|err| err.to_string())?;
    let profile = fs::read_to_string(dir.join("profile.ovpn")).map_err(|err| err.to_string())?;
    Ok(ApiProfile {
        id: id.to_string(),
        metadata,
        profile,
    })
}

fn api_ok<T: Serialize>(data: T) -> Response {
    Json(VpnmanEnvelope {
        success: true,
        error_code: String::new(),
        error_message: String::new(),
        data: Some(data),
    })
    .into_response()
}

fn api_failure(err: ApiFailure) -> Response {
    api_error(err.status, err.code, err.message)
}

fn api_error<E: ToString>(status: StatusCode, code: &str, message: E) -> Response {
    (
        status,
        Json(VpnmanEnvelope::<Value> {
            success: false,
            error_code: code.to_string(),
            error_message: message.to_string(),
            data: None,
        }),
    )
        .into_response()
}

fn openapi_spec() -> Value {
    serde_json::json!({
        "openapi": "3.0.3",
        "info": {
            "title": "VPN Manager API",
            "version": "0.1.0"
        },
        "servers": [{"url": "/vpnman"}],
        "security": [{"basicAuth": []}],
        "paths": {
            "/api/templates": {
                "get": {
                    "summary": "List OpenVPN templates",
                    "responses": {"200": {"description": "Envelope containing templates"}}
                }
            },
            "/api/cas": {
                "get": {
                    "summary": "List certificate authorities",
                    "responses": {"200": {"description": "Envelope containing CAs"}}
                }
            },
            "/api/configs": {
                "post": {
                    "summary": "Issue an OpenVPN config",
                    "description": "If ca_id is omitted or blank, the configured default CA ID is used.",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IssueConfigRequest"},
                                "example": {
                                    "template_id": "template-id",
                                    "ca_id": "ca-id",
                                    "client_name": "laptop-01",
                                    "tags": ["laptop", "team=engineering"],
                                    "parameters": {
                                        "proto": "udp",
                                        "server_host": "vpn.example.com",
                                        "server_port": "1194"
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Envelope containing generated profile and id"}}
                }
            },
            "/api/profiles": {
                "get": {
                    "summary": "List OpenVPN profiles",
                    "responses": {"200": {"description": "Envelope containing profile metadata"}}
                }
            },
            "/api/profiles/{id}": {
                "get": {
                    "summary": "Retrieve an OpenVPN profile",
                    "parameters": [{"name": "id", "in": "path", "required": true, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Envelope containing profile text and metadata"}}
                }
            }
        },
        "components": {
            "securitySchemes": {
                "basicAuth": {
                    "type": "http",
                    "scheme": "basic"
                }
            },
            "schemas": {
                "Envelope": {
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "error_code": {"type": "string"},
                        "error_message": {"type": "string"},
                        "data": {}
                    }
                },
                "IssueConfigRequest": {
                    "type": "object",
                    "required": ["template_id", "client_name"],
                    "properties": {
                        "template_id": {"type": "string"},
                        "ca_id": {"type": "string", "description": "Optional. Uses configured default CA ID when omitted or blank."},
                        "client_name": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "parameters": {"type": "object", "additionalProperties": {"type": "string"}}
                    }
                }
            }
        }
    })
}

async fn minica_list_cas(state: &AppState, cfg: &MinicaConfig) -> Result<Vec<MinicaCa>, String> {
    minica_get_data(state, cfg, "/api/cas").await
}

async fn minica_get_ca(
    state: &AppState,
    cfg: &MinicaConfig,
    ca_id: &str,
) -> Result<MinicaCa, String> {
    minica_get_data(state, cfg, &format!("/api/cas/{ca_id}")).await
}

async fn minica_find_or_create_cert(
    state: &AppState,
    cfg: &MinicaConfig,
    ca_id: &str,
    common_name: &str,
) -> Result<MinicaCert, String> {
    if let Ok(found) = minica_get_cert_id_by_cn(state, cfg, ca_id, common_name).await {
        return minica_get_data(state, cfg, &format!("/api/cas/{ca_id}/certs/{}", found.id)).await;
    }

    minica_create_cert(state, cfg, ca_id, common_name).await
}

async fn minica_create_cert(
    state: &AppState,
    cfg: &MinicaConfig,
    ca_id: &str,
    common_name: &str,
) -> Result<MinicaCert, String> {
    let payload = serde_json::json!({
        "common_name": common_name,
        "valid_days": cfg.cert_defaults.valid_days,
        "country_code": cfg.cert_defaults.country_code,
        "organization": cfg.cert_defaults.organization,
        "state": cfg.cert_defaults.state,
        "city": cfg.cert_defaults.city,
        "organization_unit": cfg.cert_defaults.organization_unit,
        "digest_algorithm": cfg.cert_defaults.digest_algorithm,
        "key_profile": cfg.cert_defaults.key_profile,
        "dns_list": cfg.cert_defaults.dns_list,
        "ip_list": cfg.cert_defaults.ip_list,
    });
    let csrf = minica_get_csrf(state, cfg).await?;
    let url = format!(
        "{}/api/cas/{ca_id}/certs",
        cfg.base_url.trim_end_matches('/')
    );
    let envelope = state
        .http
        .put(url)
        .basic_auth(&cfg.username, Some(&cfg.password))
        .header("X-CSRF-Token", csrf)
        .json(&payload)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .json::<ApiEnvelope<MinicaCert>>()
        .await
        .map_err(|err| err.to_string())?;
    unwrap_envelope(envelope)
}

async fn minica_delete_cert(
    state: &AppState,
    cfg: &MinicaConfig,
    ca_id: &str,
    cert_id: &str,
) -> Result<(), String> {
    let csrf = minica_get_csrf(state, cfg).await?;
    let url = format!(
        "{}/api/cas/{ca_id}/certs/{cert_id}",
        cfg.base_url.trim_end_matches('/')
    );
    let envelope = state
        .http
        .delete(url)
        .basic_auth(&cfg.username, Some(&cfg.password))
        .header("X-CSRF-Token", csrf)
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .json::<ApiEnvelope<serde_json::Value>>()
        .await
        .map_err(|err| err.to_string())?;
    if envelope.success {
        Ok(())
    } else {
        unwrap_envelope(envelope).map(|_: serde_json::Value| ())
    }
}

async fn minica_get_cert_id_by_cn(
    state: &AppState,
    cfg: &MinicaConfig,
    ca_id: &str,
    common_name: &str,
) -> Result<CertIdResponse, String> {
    let url = format!(
        "{}/api/cas/{ca_id}/certs_by_cn",
        cfg.base_url.trim_end_matches('/')
    );
    let envelope = state
        .http
        .get(url)
        .basic_auth(&cfg.username, Some(&cfg.password))
        .query(&[("cn", common_name)])
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .json::<ApiEnvelope<CertIdResponse>>()
        .await
        .map_err(|err| err.to_string())?;
    unwrap_envelope(envelope)
}

async fn minica_get_csrf(state: &AppState, cfg: &MinicaConfig) -> Result<String, String> {
    #[derive(Deserialize)]
    struct CsrfData {
        #[serde(rename = "headerName")]
        _header_name: String,
        token: String,
    }
    let data: CsrfData = minica_get_data(state, cfg, "/api/csrf").await?;
    Ok(data.token)
}

async fn minica_get_data<T: for<'de> Deserialize<'de>>(
    state: &AppState,
    cfg: &MinicaConfig,
    path: &str,
) -> Result<T, String> {
    let url = format!("{}{}", cfg.base_url.trim_end_matches('/'), path);
    let envelope = state
        .http
        .get(url)
        .basic_auth(&cfg.username, Some(&cfg.password))
        .send()
        .await
        .map_err(|err| err.to_string())?
        .error_for_status()
        .map_err(|err| err.to_string())?
        .json::<ApiEnvelope<T>>()
        .await
        .map_err(|err| err.to_string())?;
    unwrap_envelope(envelope)
}

fn unwrap_envelope<T>(envelope: ApiEnvelope<T>) -> Result<T, String> {
    if envelope.success {
        envelope
            .data
            .ok_or_else(|| "Minica response did not include data".to_string())
    } else {
        let message = envelope
            .error
            .map(|err| match err.status {
                Some(status) => format!("{} ({status})", err.message),
                None => err.message,
            })
            .unwrap_or_else(|| "Minica request failed".to_string());
        Err(message)
    }
}

fn render_template_variable_inputs(template: &Template) -> String {
    template
        .variables
        .iter()
        .filter(|var| !is_reserved(var))
        .map(|var| {
            let meta = template.metadata.variables.get(var).cloned().unwrap_or_else(|| default_variable(var));
            let name = format!("var_{var}");
            let required = if meta.required { " required" } else { "" };
            let help = esc(&meta.description);
            match meta.kind {
                VariableKind::Number => {
                    let min = meta
                        .min
                        .map(|value| format!(" min=\"{value}\""))
                        .unwrap_or_default();
                    let max = meta
                        .max
                        .map(|value| format!(" max=\"{value}\""))
                        .unwrap_or_default();
                    format!(
                        r#"<div class="field"><label>{}</label><input name="{}" type="number" value="{}"{}{}{}><small>{}</small></div>"#,
                        esc(var),
                        esc(&name),
                        esc(&meta.default),
                        min,
                        max,
                        required,
                        help
                    )
                }
                VariableKind::Textarea => format!(
                    r#"<div class="field"><label>{}</label><textarea name="{}" rows="4"{}>{}</textarea><small>{}</small></div>"#,
                    esc(var),
                    esc(&name),
                    required,
                    esc(&meta.default),
                    help
                ),
                VariableKind::DropdownCsv => {
                    let options = parse_csv(&meta.options)
                        .iter()
                        .map(|opt| {
                            let selected = if *opt == meta.default { " selected" } else { "" };
                            format!("<option value=\"{}\"{}>{}</option>", esc(opt), selected, esc(opt))
                        })
                        .collect::<String>();
                    format!(
                        r#"<div class="field"><label>{}</label><select name="{}"{}>{}</select><small>{}</small></div>"#,
                        esc(var),
                        esc(&name),
                        required,
                        options,
                        help
                    )
                }
                VariableKind::Text => format!(
                    r#"<div class="field"><label>{}</label><input name="{}" value="{}"{}><small>{}</small></div>"#,
                    esc(var),
                    esc(&name),
                    esc(&meta.default),
                    required,
                    help
                ),
            }
        })
        .collect::<String>()
}

fn load_templates(root: &FsPath) -> io::Result<Vec<Template>> {
    let mut templates = Vec::new();
    for entry in fs::read_dir(templates_dir(root))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(id) = entry.file_name().to_str() {
                if let Ok(template) = load_template(root, id) {
                    templates.push(template);
                }
            }
        }
    }
    templates.sort_by(|a, b| a.metadata.name.cmp(&b.metadata.name));
    Ok(templates)
}

fn load_template(root: &FsPath, id: &str) -> io::Result<Template> {
    let dir = templates_dir(root).join(id);
    let body = fs::read_to_string(dir.join("template.ovpn"))?;
    let mut metadata = read_yaml::<TemplateMetadata>(&dir.join("metadata.yaml"))?;
    normalize_template_metadata(&mut metadata);
    let variables = extract_variables(&body, &metadata);
    for var in &variables {
        if let Some(meta) = metadata.variables.get_mut(var) {
            normalize_variable_metadata(var, meta);
        }
    }
    Ok(Template {
        id: id.to_string(),
        body,
        metadata,
        variables,
    })
}

fn load_profiles(root: &FsPath) -> io::Result<Vec<(String, ProfileMetadata)>> {
    let mut profiles = Vec::new();
    for entry in fs::read_dir(profiles_dir(root))? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            if let Some(id) = entry.file_name().to_str() {
                if let Ok(meta) = read_yaml::<ProfileMetadata>(&entry.path().join("metadata.yaml"))
                {
                    profiles.push((id.to_string(), meta));
                }
            }
        }
    }
    profiles.sort_by(|a, b| b.1.created_at.cmp(&a.1.created_at));
    Ok(profiles)
}

fn validate_unique_template_name(
    root: &FsPath,
    name: &str,
    current_id: Option<&str>,
) -> Result<(), String> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err("template name is required".to_string());
    }
    for template in load_templates(root).unwrap_or_default() {
        if current_id == Some(template.id.as_str()) {
            continue;
        }
        if template.metadata.name.trim().to_ascii_lowercase() == normalized {
            return Err(format!("another template already uses the name '{name}'"));
        }
    }
    Ok(())
}

fn unique_template_name(root: &FsPath, base: &str, current_id: Option<&str>) -> String {
    if validate_unique_template_name(root, base, current_id).is_ok() {
        return base.to_string();
    }
    for index in 2.. {
        let candidate = format!("{base} {index}");
        if validate_unique_template_name(root, &candidate, current_id).is_ok() {
            return candidate;
        }
    }
    unreachable!("unbounded template name search should always return")
}

fn validate_variable_value(var: &str, meta: &VariableMetadata, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Ok(());
    }
    if matches!(meta.kind, VariableKind::DropdownCsv) {
        let options = parse_csv(&meta.options);
        if !options.is_empty() && !options.iter().any(|option| option == value) {
            return Err(format!("{var} must be one of: {}", options.join(", ")));
        }
    }
    if matches!(meta.kind, VariableKind::Number) || meta.min.is_some() || meta.max.is_some() {
        let parsed = value
            .trim()
            .parse::<i64>()
            .map_err(|_| format!("{var} must be a number"))?;
        if let Some(min) = meta.min {
            if parsed < min {
                return Err(format!("{var} must be at least {min}"));
            }
        }
        if let Some(max) = meta.max {
            if parsed > max {
                return Err(format!("{var} must be at most {max}"));
            }
        }
    }
    Ok(())
}

fn validate_token_delimiters(metadata: &TemplateMetadata) -> Result<(), String> {
    if metadata.token_start.is_empty() {
        return Err("token start is required".to_string());
    }
    if metadata.token_stop.is_empty() {
        return Err("token stop is required".to_string());
    }
    Ok(())
}

fn validate_variable_definitions(metadata: &TemplateMetadata) -> Result<(), String> {
    for (var, meta) in &metadata.variables {
        if let Some(min) = meta.min {
            if let Some(max) = meta.max {
                if min > max {
                    return Err(format!("{var} has min greater than max"));
                }
            }
        }
        if matches!(meta.kind, VariableKind::DropdownCsv) && parse_csv(&meta.options).is_empty() {
            return Err(format!("{var} dropdown requires options"));
        }
        if !meta.default.trim().is_empty() {
            validate_variable_value(var, meta, &meta.default)
                .map_err(|err| format!("{var} default is invalid: {err}"))?;
        }
    }
    Ok(())
}

fn sync_metadata_with_body(body: &str, metadata: &mut TemplateMetadata) {
    normalize_template_metadata(metadata);
    let variables = extract_variables(body, metadata);
    let wanted = variables.iter().cloned().collect::<BTreeSet<_>>();
    metadata
        .variables
        .retain(|key, _| wanted.contains(key) && !is_reserved(key));
    for var in variables {
        if !is_reserved(&var) {
            metadata
                .variables
                .entry(var.clone())
                .or_insert_with(|| default_variable(&var));
            if let Some(meta) = metadata.variables.get_mut(&var) {
                normalize_variable_metadata(&var, meta);
            }
        }
    }
}

fn normalize_template_metadata(metadata: &mut TemplateMetadata) {
    if metadata.token_start.is_empty() {
        metadata.token_start = default_token_start();
    }
    if metadata.token_stop.is_empty() {
        metadata.token_stop = default_token_stop();
    }
}

fn normalize_variable_metadata(name: &str, meta: &mut VariableMetadata) {
    let old_default_description = meta.description == format!("Value for {name}");
    if name == "proto"
        && old_default_description
        && matches!(meta.kind, VariableKind::Text)
        && meta.default.is_empty()
        && meta.options.is_empty()
    {
        *meta = default_variable(name);
    }
    if (name.ends_with("port") || name.ends_with("_port"))
        && old_default_description
        && matches!(meta.kind, VariableKind::Text)
        && meta.default.is_empty()
        && meta.options.is_empty()
        && meta.min.is_none()
        && meta.max.is_none()
    {
        *meta = default_variable(name);
    }
}

fn extract_variables(body: &str, metadata: &TemplateMetadata) -> Vec<String> {
    let pattern = format!(
        "{}([A-Za-z_][A-Za-z0-9_]*){}",
        regex::escape(&metadata.token_start),
        regex::escape(&metadata.token_stop)
    );
    let re = Regex::new(&pattern).expect("valid variable regex");
    let mut vars = BTreeSet::new();
    for cap in re.captures_iter(body) {
        vars.insert(cap[1].to_string());
    }
    vars.into_iter().collect()
}

fn render_template(
    body: &str,
    metadata: &TemplateMetadata,
    replacements: &BTreeMap<String, String>,
) -> String {
    let mut rendered = body.to_string();
    for (key, value) in replacements {
        rendered = rendered.replace(
            &format!("{}{key}{}", metadata.token_start, metadata.token_stop),
            value,
        );
    }
    rendered
}

fn default_variable(name: &str) -> VariableMetadata {
    if name == "proto" {
        return VariableMetadata {
            kind: VariableKind::DropdownCsv,
            description: "VPN transport protocol".to_string(),
            default: "udp".to_string(),
            options: "tcp,udp".to_string(),
            min: None,
            max: None,
            required: true,
        };
    }
    if name.ends_with("port") || name.ends_with("_port") {
        return VariableMetadata {
            kind: VariableKind::Number,
            description: format!("Port for {name}"),
            default: "1194".to_string(),
            options: String::new(),
            min: Some(1),
            max: Some(65535),
            required: true,
        };
    }
    VariableMetadata {
        kind: VariableKind::Text,
        description: format!("Value for {name}"),
        default: String::new(),
        options: String::new(),
        min: None,
        max: None,
        required: true,
    }
}

fn sample_template() -> String {
    r#"client
dev tun
proto %proto%
remote %server_host% %server_port%
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verb 3

<ca>
%ca_cert%
</ca>
<cert>
%client_cert%
</cert>
<key>
%client_key%
</key>
"#
    .to_string()
}

fn read_minica_config(root: &FsPath) -> io::Result<MinicaConfig> {
    read_yaml(&minica_config_path(root))
}

fn ensure_dirs(root: &FsPath) -> io::Result<()> {
    fs::create_dir_all(config_dir(root))?;
    fs::create_dir_all(templates_dir(root))?;
    fs::create_dir_all(profiles_dir(root))?;
    Ok(())
}

fn ensure_default_config(root: &FsPath) -> io::Result<()> {
    let path = minica_config_path(root);
    if !path.exists() {
        write_yaml(&path, &default_minica_config())?;
    }
    Ok(())
}

fn default_minica_config() -> MinicaConfig {
    MinicaConfig {
        base_url: "http://localhost:9988".to_string(),
        username: "admin".to_string(),
        password: "adminpass".to_string(),
        default_ca_id: String::new(),
        cert_defaults: CertDefaults {
            valid_days: 7300,
            country_code: "SG".to_string(),
            organization: "Home".to_string(),
            state: "Singapore".to_string(),
            city: "Singapore".to_string(),
            organization_unit: "VPN".to_string(),
            digest_algorithm: "sha512".to_string(),
            key_profile: default_key_profile(),
            dns_list: Vec::new(),
            ip_list: Vec::new(),
        },
    }
}

fn read_yaml<T: for<'de> Deserialize<'de>>(path: &FsPath) -> io::Result<T> {
    let text = fs::read_to_string(path)?;
    serde_yaml::from_str(&text).map_err(io::Error::other)
}

fn write_yaml<T: Serialize>(path: &FsPath, value: &T) -> io::Result<()> {
    let text = serde_yaml::to_string(value).map_err(io::Error::other)?;
    fs::write(path, text)
}

fn config_dir(root: &FsPath) -> PathBuf {
    root.join("config")
}

fn templates_dir(root: &FsPath) -> PathBuf {
    root.join("templates")
}

fn profiles_dir(root: &FsPath) -> PathBuf {
    root.join("profiles")
}

fn minica_config_path(root: &FsPath) -> PathBuf {
    config_dir(root).join("minica.yaml")
}

fn parse_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn key_profile_options(selected: &str) -> String {
    [
        "rsa:2048",
        "rsa:4096",
        "rsa:8192",
        "ecdsa:prime256v1",
        "ecdsa:secp384r1",
        "ecdsa:secp521r1",
    ]
    .iter()
    .map(|profile| {
        let selected_attr = if *profile == selected {
            " selected"
        } else {
            ""
        };
        format!(
            "<option value=\"{}\"{}>{}</option>",
            esc(profile),
            selected_attr,
            esc(profile)
        )
    })
    .collect()
}

fn ca_select_options(cas: &[MinicaCa], selected: &str) -> String {
    let mut options = String::new();
    if selected.trim().is_empty() {
        options.push_str("<option value=\"\">Select a CA</option>");
    }
    let mut found_selected = false;
    for ca in cas {
        if ca.id == selected {
            found_selected = true;
        }
        let selected_attr = if ca.id == selected { " selected" } else { "" };
        options.push_str(&format!(
            "<option value=\"{}\"{}>{} ({})</option>",
            esc(&ca.id),
            selected_attr,
            esc(&ca.common_name),
            esc(&ca.id)
        ));
    }
    if !selected.trim().is_empty() && !found_selected {
        options.insert_str(
            0,
            &format!(
                "<option value=\"{}\" selected>{}</option>",
                esc(selected),
                esc(selected)
            ),
        );
    }
    options
}

fn render_parameter_chips(values: &BTreeMap<String, String>) -> String {
    if values.is_empty() {
        return "<span class=\"muted\">None</span>".to_string();
    }
    values
        .iter()
        .map(|(key, value)| {
            format!(
                "<span class=\"param-chip\"><span class=\"param-key\">{}</span><span class=\"param-value\">{}</span></span>",
                esc(key),
                esc(value)
            )
        })
        .collect::<String>()
}

fn unique_id(prefix: &str) -> String {
    format!(
        "{}-{}-{}",
        Utc::now().format("%Y%m%d%H%M%S"),
        prefix,
        Uuid::new_v4().simple()
    )
}

fn slugify(value: &str) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() {
        "profile".to_string()
    } else {
        slug
    }
}

fn is_reserved(value: &str) -> bool {
    RESERVED_VARS.contains(&value)
}

fn valid_storage_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

fn days_ago_title(created_at: DateTime<Utc>) -> String {
    let days = Utc::now()
        .signed_duration_since(created_at)
        .num_days()
        .max(0);
    match days {
        0 => "today".to_string(),
        1 => "1 day ago".to_string(),
        _ => format!("{days} days ago"),
    }
}

fn iso8601_seconds(created_at: DateTime<Utc>) -> String {
    created_at.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn error_page<E: ToString>(title: &str, err: E) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        page(title, &format!("<p class=\"error\">{}</p><p><a class=\"button\" href=\"/vpnman/\">Back to dashboard</a></p>", esc(&err.to_string()))),
    )
        .into_response()
}

fn page(title: &str, body: &str) -> Html<String> {
    page_with_heading(title, body, true, title)
}

fn page_without_heading(title: &str, body: &str) -> Html<String> {
    page_with_heading(title, body, false, title)
}

fn template_page(title: &str, body: &str) -> Html<String> {
    page_with_heading(title, body, true, "OpenVPN Templates")
}

fn config_page(title: &str, body: &str) -> Html<String> {
    page_with_heading(title, body, true, "OpenVPN Configs")
}

fn page_with_heading(
    title: &str,
    body: &str,
    show_heading: bool,
    active_nav: &str,
) -> Html<String> {
    let heading = if show_heading {
        format!("<h1>{}</h1>", esc(title))
    } else {
        String::new()
    };
    let home_class = nav_class(active_nav, "VPN Manager");
    let configs_class = nav_class(active_nav, "OpenVPN Configs");
    let templates_class = nav_class(active_nav, "OpenVPN Templates");
    let ca_class = nav_class(active_nav, "Certificate Authority Config");
    let swagger_class = nav_class(active_nav, "Swagger Explorer");
    Html(format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{}</title>
  <style>{}</style>
</head>
<body>
  <header>
    <nav>
      <div class="brand-mark" aria-label="VPN Manager">
        <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2.5 19 5.4v5.3c0 4.8-2.8 9.1-7 10.8-4.2-1.7-7-6-7-10.8V5.4l7-2.9Zm0 2.2L7 6.8v3.9c0 3.6 1.9 6.9 5 8.4 3.1-1.5 5-4.8 5-8.4V6.8l-5-2.1Z"/></svg>
        <span>VPN Manager</span>
      </div>
      <a class="{}" href="/vpnman/">Home</a>
      <a class="{}" href="/vpnman/profiles">OpenVPN Configs</a>
      <a class="{}" href="/vpnman/templates">OpenVPN Templates</a>
      <a class="{}" href="/vpnman/settings/minica">Certificate Authority Config</a>
      <a class="{}" href="/vpnman/api/swagger">Swagger Explorer</a>
    </nav>
  </header>
  <main>
    {}
    {}
  </main>
  <div class="modal-backdrop" id="app-modal" hidden>
    <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="app-modal-title">
      <div class="modal-header">
        <h2 id="app-modal-title">Confirm</h2>
        <button class="modal-close" type="button" aria-label="Close">&times;</button>
      </div>
      <div class="modal-body" id="app-modal-body"></div>
      <div class="modal-footer">
        <button class="button" type="button" data-modal-cancel>Cancel</button>
        <button class="button primary" type="button" data-modal-confirm>Confirm</button>
      </div>
    </div>
  </div>
  <script>{}</script>
</body>
</html>"#,
        esc(title),
        CSS,
        home_class,
        configs_class,
        templates_class,
        ca_class,
        swagger_class,
        heading,
        body,
        JS
    ))
}

fn nav_class(title: &str, active_title: &str) -> &'static str {
    if title == active_title {
        "nav-link active"
    } else {
        "nav-link"
    }
}

fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const CSS: &str = r#"
:root {
  color-scheme: light;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --text: #20242a;
  --muted: #667085;
  --line: #d9dde3;
  --accent: #176d63;
  --accent-dark: #0f554e;
  --danger: #b42318;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg);
  color: var(--text);
}
header {
  background: #fff;
  border-bottom: 1px solid var(--line);
}
nav {
  max-width: 1160px;
  margin: 0 auto;
  height: 58px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 22px;
}
nav a {
  color: #364152;
  text-decoration: none;
  font-size: 14px;
}
.brand-mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 9px;
  min-height: 40px;
  margin-right: auto;
  color: var(--accent);
  font-size: 18px;
  font-weight: 750;
  white-space: nowrap;
}
.brand-mark svg {
  width: 31px;
  height: 31px;
  fill: currentColor;
}
.brand-mark span {
  color: var(--text);
}
.nav-link {
  display: inline-flex;
  align-items: center;
  min-height: 34px;
  padding: 6px 10px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
}
.nav-link.active {
  color: #fff;
  background: var(--accent);
  border-color: var(--accent);
  font-weight: 650;
}
main {
  max-width: 1160px;
  margin: 0 auto;
  padding: 30px 22px 60px;
}
h1 {
  margin: 0 0 22px;
  font-size: 28px;
  line-height: 1.2;
}
h2 {
  margin: 8px 0 10px;
  font-size: 17px;
}
.toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 18px;
}
.toolbar.compact {
  margin-bottom: 0;
}
.grid {
  display: grid;
  gap: 16px;
  align-items: stretch;
}
.grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.panel {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 18px;
}
.panel + .panel {
  margin-top: 18px;
}
.grid > .panel {
  margin-top: 0 !important;
}
.panel h2:first-child {
  margin-top: 0;
}
.summary-card {
  height: 150px;
  min-height: 150px;
  display: grid;
  grid-template-rows: 1fr auto;
  align-content: center;
}
.metric {
  display: block;
  font-size: 38px;
  font-weight: 700;
  line-height: 1.2;
}
.metric.status {
  font-size: 20px;
  line-height: 1.3;
  min-height: 46px;
  display: flex;
  align-items: center;
}
.label, .muted, small {
  color: var(--muted);
}
.form {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
label {
  font-weight: 650;
  font-size: 13px;
}
input, textarea, select {
  width: 100%;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #fff;
  color: var(--text);
  padding: 10px 11px;
  font: inherit;
}
textarea.code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.45;
}
textarea.raw {
  min-height: 420px;
}
.button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 8px 12px;
  color: var(--text);
  background: #fff;
  text-decoration: none;
  font: inherit;
  cursor: pointer;
}
.button.primary {
  color: #fff;
  background: var(--accent);
  border-color: var(--accent);
}
.button.primary:hover { background: var(--accent-dark); }
.button.danger {
  color: #fff;
  background: var(--danger);
  border-color: var(--danger);
}
.button.small {
  min-height: 30px;
  padding: 5px 9px;
  font-size: 13px;
}
table {
  width: 100%;
  border-collapse: collapse;
  background: #fff;
  border: 1px solid var(--line);
  border-radius: 8px;
  overflow: hidden;
}
th, td {
  text-align: left;
  padding: 11px 12px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
}
th {
  font-size: 12px;
  color: #475467;
  background: #f8fafc;
  text-transform: uppercase;
}
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
}
.inline {
  display: inline;
}
.error {
  color: var(--danger);
  font-weight: 650;
}
.success {
  color: var(--accent);
  font-weight: 650;
}
.test-result {
  display: none;
  margin: 0;
}
.test-result:not(:empty) {
  display: block;
}
.configs-table td:first-child {
  font-weight: 650;
}
.configs-table td:nth-child(3) {
  min-width: 280px;
}
.param-chip {
  display: grid;
  grid-template-columns: minmax(96px, max-content) minmax(0, 1fr);
  align-items: baseline;
  gap: 10px;
  max-width: 100%;
  margin: 0 0 6px;
  padding: 6px 8px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: #f8fafc;
  overflow-wrap: anywhere;
}
.param-chip:last-child {
  margin-bottom: 0;
}
.param-key, .param-key-cell {
  color: var(--muted);
  font-size: 12px;
  font-weight: 700;
}
.param-value, .param-value-cell {
  color: var(--text);
  font-family: inherit;
}
.parameters-table .param-key-cell {
  width: 180px;
}
.parameters-table .param-value-cell {
  overflow-wrap: anywhere;
}
.swagger-panel {
  padding: 0;
  overflow: hidden;
}
.swagger-panel .swagger-ui {
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.swagger-panel .swagger-ui .wrapper {
  padding: 0 18px;
}
.details {
  display: grid;
  grid-template-columns: 180px minmax(0, 1fr);
  gap: 10px 16px;
  margin: 0;
}
.details dt {
  color: var(--muted);
  font-weight: 650;
}
.details dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}
.modal-backdrop {
  position: fixed;
  inset: 0;
  z-index: 1000;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 18px;
  background: rgba(16, 24, 40, 0.45);
}
.modal-backdrop[hidden] {
  display: none;
}
.modal-dialog {
  width: min(520px, 100%);
  background: #fff;
  border-radius: 8px;
  box-shadow: 0 18px 48px rgba(16, 24, 40, 0.24);
  overflow: hidden;
}
.modal-header, .modal-footer {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 16px;
  border-bottom: 1px solid var(--line);
}
.modal-header h2 {
  margin: 0;
}
.modal-close {
  margin-left: auto;
  border: 0;
  background: transparent;
  font-size: 26px;
  line-height: 1;
  cursor: pointer;
}
.modal-body {
  padding: 16px;
  white-space: pre-wrap;
}
.modal-footer {
  justify-content: flex-end;
  border-top: 1px solid var(--line);
  border-bottom: 0;
}
@media (max-width: 760px) {
  nav { gap: 12px; overflow-x: auto; }
  .grid.two, .grid.three, .row { grid-template-columns: 1fr; }
  .details { grid-template-columns: 1fr; }
  table { display: block; overflow-x: auto; }
}
"#;

const JS: &str = r#"
function formBody(form) {
  return new URLSearchParams(new FormData(form));
}

function syncCertificateDefaultsCaFields() {
  const sourceForm = document.querySelector('form[data-test-url="/vpnman/settings/minica/test"]');
  const defaultsForm = document.querySelector('form[data-test-url="/vpnman/settings/minica/cert-defaults/test"]');
  if (!sourceForm || !defaultsForm) return;
  defaultsForm.querySelectorAll('.js-ca-shadow').forEach((field) => {
    const source = sourceForm.elements[field.dataset.source];
    if (source) field.value = source.value;
  });
}

function updateCaSelect(cas, selectedValue) {
  const select = document.querySelector('.js-ca-select');
  if (!select || !Array.isArray(cas)) return;
  const selected = selectedValue || select.value || select.dataset.current || '';
  select.innerHTML = '';
  if (!selected) {
    select.append(new Option('Select a CA', ''));
  }
  let found = false;
  cas.forEach((ca) => {
    const label = `${ca.common_name || ca.id} (${ca.id})`;
    const option = new Option(label, ca.id);
    if (ca.id === selected) {
      option.selected = true;
      found = true;
    }
    select.append(option);
  });
  if (selected && !found) {
    const option = new Option(selected, selected);
    option.selected = true;
    select.prepend(option);
  }
  syncCertificateDefaultsCaFields();
}

async function runInlineTest(form, options = {}) {
  syncCertificateDefaultsCaFields();
  const status = form.querySelector('.test-result');
  const url = form.dataset.testUrl;
  if (!status || !url) return { ok: false, message: 'Not OK: test is not configured' };
  if (!options.silent) {
    status.className = 'test-result muted';
    status.textContent = 'Testing...';
  }
  try {
    const response = await fetch(url, {
      method: 'POST',
      body: formBody(form),
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
      }
    });
    const contentType = response.headers.get('content-type') || '';
    const result = contentType.includes('application/json')
      ? await response.json()
      : { ok: false, message: 'Not OK: ' + (await response.text()).slice(0, 160) };
    if (Array.isArray(result.cas)) updateCaSelect(result.cas);
    if (!options.silent) {
      status.className = result.ok ? 'test-result success' : 'test-result error';
      status.textContent = result.message;
    }
    return result;
  } catch (error) {
    const result = { ok: false, message: 'Not OK: ' + error };
    if (!options.silent) {
      status.className = 'test-result error';
      status.textContent = result.message;
    }
    return result;
  }
}

function modalConfirm(title, message, confirmText = 'Confirm') {
  const modal = document.getElementById('app-modal');
  const titleNode = document.getElementById('app-modal-title');
  const bodyNode = document.getElementById('app-modal-body');
  const confirmButton = modal.querySelector('[data-modal-confirm]');
  const cancelButton = modal.querySelector('[data-modal-cancel]');
  const closeButton = modal.querySelector('.modal-close');
  titleNode.textContent = title;
  bodyNode.textContent = message;
  confirmButton.textContent = confirmText;
  modal.hidden = false;
  confirmButton.focus();
  return new Promise((resolve) => {
    const finish = (value) => {
      modal.hidden = true;
      confirmButton.removeEventListener('click', onConfirm);
      cancelButton.removeEventListener('click', onCancel);
      closeButton.removeEventListener('click', onCancel);
      modal.removeEventListener('click', onBackdrop);
      document.removeEventListener('keydown', onKeydown);
      resolve(value);
    };
    const onConfirm = () => finish(true);
    const onCancel = () => finish(false);
    const onBackdrop = (event) => {
      if (event.target === modal) finish(false);
    };
    const onKeydown = (event) => {
      if (event.key === 'Escape') finish(false);
    };
    confirmButton.addEventListener('click', onConfirm);
    cancelButton.addEventListener('click', onCancel);
    closeButton.addEventListener('click', onCancel);
    modal.addEventListener('click', onBackdrop);
    document.addEventListener('keydown', onKeydown);
  });
}

document.querySelectorAll('.js-inline-test').forEach((button) => {
  button.addEventListener('click', () => runInlineTest(button.form));
});

document.querySelectorAll('.js-test-form').forEach((form) => {
  form.addEventListener('submit', async (event) => {
    if (form.dataset.confirmed === 'true') return;
    event.preventDefault();
    const result = await runInlineTest(form);
    const message = `${form.dataset.saveConfirm || 'Save changes?'}\n\nTest result: ${result.message}`;
    if (await modalConfirm('Confirm Save', message, 'Save')) {
      form.dataset.confirmed = 'true';
      form.submit();
    }
  });
});

document.querySelectorAll('.js-confirm-delete').forEach((form) => {
  form.addEventListener('submit', async (event) => {
    if (form.dataset.confirmed === 'true') return;
    event.preventDefault();
    if (await modalConfirm('Confirm Delete', form.dataset.confirm || 'Delete this item?', 'Delete')) {
      form.dataset.confirmed = 'true';
      form.submit();
    }
  });
});

const minicaForm = document.querySelector('form[data-test-url="/vpnman/settings/minica/test"]');
if (minicaForm) {
  ['base_url', 'username', 'password'].forEach((name) => {
    const field = minicaForm.elements[name];
    if (field) {
      field.addEventListener('change', () => runInlineTest(minicaForm, { silent: true }));
      field.addEventListener('blur', () => runInlineTest(minicaForm, { silent: true }));
    }
  });
  const caSelect = minicaForm.elements.default_ca_id;
  if (caSelect) caSelect.addEventListener('change', syncCertificateDefaultsCaFields);
}
syncCertificateDefaultsCaFields();
"#;
