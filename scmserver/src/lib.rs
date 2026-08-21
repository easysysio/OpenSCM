// =============================================================================
// lib.rs — AppState, Tera initialisation, router construction, public API
//
// Exposes all CE modules as a library so that the SaaS binary can depend on
// this crate directly. create_core_router() builds the full Axum Router with
// all CE routes; the SaaS binary merges additional routes on top.
// =============================================================================

// Module Declarations (public so the SaaS crate can access them)
pub mod models;
pub mod handlers;
pub mod config;
pub mod schema;
pub mod auth;
pub mod agents;
pub mod audit;
pub mod client;
pub mod dashboard;
pub mod systems;
pub mod groups;
pub mod auto_groups;
pub mod auto_groups_admin;
pub mod enrollment;
pub mod tests;
pub mod pdf;
pub mod tour;
pub mod policies;
pub mod reports;
pub mod users;
pub mod settings;
pub mod scheduler;
pub mod install;
pub mod email;
pub mod directories;

// 2. Imports needed for the public API
use std::{sync::{Arc, atomic::{AtomicBool, Ordering}, OnceLock}, path::PathBuf, error::Error};

// ─────────────────────────────────────────────────────────────────────────────
// PostInstallFn — optional async hook called by install_post after the CE
// schema and migrations have completed.  SaaS registers this via
// `.layer(Extension(hook))` on the app router so that its own migrations run
// inside the same process on fresh installs, not only on the next restart.
// ─────────────────────────────────────────────────────────────────────────────
pub type PostInstallFn = Arc<
    dyn Fn(sqlx::SqlitePool) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    + Send + Sync
>;

// Version registry — set once at binary startup so EE/SaaS show their own version.
static APP_VERSION: OnceLock<String> = OnceLock::new();

// ─────────────────────────────────────────────────────────────────────────────
// Helper: set_app_version / app_version
// Version registry — set once at binary startup so EE/SaaS show their own
// version string instead of the CE crate version.
// ─────────────────────────────────────────────────────────────────────────────
pub fn set_app_version(version: &str) {
    let _ = APP_VERSION.set(version.to_string());
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: app_version
// Returns the version set by set_app_version, or CE crate version as fallback.
// ─────────────────────────────────────────────────────────────────────────────
pub fn app_version() -> &'static str {
    APP_VERSION.get().map(|s| s.as_str()).unwrap_or(env!("CARGO_PKG_VERSION"))
}

// Edition registry — "Community Edition", "SaaS Edition"
static APP_EDITION: OnceLock<String> = OnceLock::new();

// ─────────────────────────────────────────────────────────────────────────────
// Helper: set_app_edition / app_edition
// Edition registry — "Community Edition", "Enterprise Edition", etc.
// ─────────────────────────────────────────────────────────────────────────────
pub fn set_app_edition(edition: &str) {
    let _ = APP_EDITION.set(edition.to_string());
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: app_edition
// Returns the edition set by set_app_edition, or "Community Edition" as fallback.
// ─────────────────────────────────────────────────────────────────────────────
pub fn app_edition() -> &'static str {
    APP_EDITION.get().map(|s| s.as_str()).unwrap_or("Community Edition")
}
use axum::{Router, Extension, response::IntoResponse, routing::{get, post}, http::{header, StatusCode}, body::{Bytes, Body}};
use axum::middleware;
use tera::Tera;
use include_dir::{include_dir, Dir};
use tracing::info;

// 3. Re-exporting static assets so the SaaS version can find them
pub static TEMPLATES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/templates");
pub static STATIC_FILES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/static");

// 4. The Shared Application State
// This struct is the "glue" between your Core logic and the Enterprise wrapper.
#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::SqlitePool,
    pub tera: Arc<Tera>,
    pub config: Arc<config::Config>,
    pub sync_tx: tokio::sync::mpsc::Sender<()>,
    /// False on a brand-new install until /install setup completes.
    pub is_initialized: Arc<AtomicBool>,
}

// 5. Utility functions moved from main.rs
// ─────────────────────────────────────────────────────────────────────────────
// Helper: init_tera
// Loads all embedded CE templates into a Tera instance. Calls
// init_tera_with_overrides with an empty override list.
// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// Helper: collect_templates
// Every embedded template, including those in subdirectories.
//
// include_dir's `Dir::files()` is NOT recursive — it yields only the files
// directly inside the directory it is called on. Templates under
// templates/partials/ were therefore never registered, and because Tera
// resolves `{% include %}` at RENDER time rather than at add_raw_template
// time, nothing failed at startup: the first request to a page using the
// partial returned a 500 instead. Same failure shape as the 0.7.4 template
// crash-loop, just deferred to request time, and covered by
// tests/templates_parse.rs::subdirectory_templates_are_registered.
// ─────────────────────────────────────────────────────────────────────────────
fn collect_templates(dir: &'static include_dir::Dir<'static>) -> Vec<&'static include_dir::File<'static>> {
    let mut out: Vec<_> = dir.files().collect();
    for sub in dir.dirs() {
        out.extend(collect_templates(sub));
    }
    out
}

pub fn init_tera() -> Result<Tera, Box<dyn Error>> {
    init_tera_with_overrides(&[])
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: init_tera_with_overrides
// Like init_tera, but lets callers (EE/SaaS) substitute specific templates by
// name before the CE templates are loaded, preserving inheritance chains.
// ─────────────────────────────────────────────────────────────────────────────
pub fn init_tera_with_overrides(overrides: &[(&str, &str)]) -> Result<Tera, Box<dyn Error>> {
    let mut tera = Tera::default();

    // Load base.html FIRST. Tera 1.x validates `extends` parents at
    // add_raw_template time, so the base template must already be in the
    // registry before any child that extends it can be added. include_dir's
    // .files() iterator yields files in alphabetical order, so a child whose
    // name sorts before "base.html" (e.g. "audit_log.html") would otherwise
    // be added first and trip MissingParent.
    if !overrides.iter().any(|(name, _)| *name == "base.html") {
        if let Some(base) = TEMPLATES_DIR.get_file("base.html") {
            let content = std::str::from_utf8(base.contents())
                .map_err(|e| format!("base.html contains invalid UTF-8: {}", e))?;
            tera.add_raw_template("base.html", content)?;
        }
    }

    // Load the remaining CE templates. Skipped: (1) base.html, already loaded
    // above; (2) any file the caller supplied as an override (added in the
    // second loop below and wholly replaces the CE version).
    for file in collect_templates(&TEMPLATES_DIR) {
        let path = file.path().to_str()
            .ok_or_else(|| format!("Template path is not valid UTF-8: {:?}", file.path()))?;

        if path == "base.html" {
            continue;
        }
        if overrides.iter().any(|(name, _)| *name == path) {
            continue;
        }

        let content = std::str::from_utf8(file.contents())
            .map_err(|e| format!("Template '{}' contains invalid UTF-8: {}", path, e))?
            .to_owned();

        tera.add_raw_template(path, &content)?;
    }

    // Overlay overrides on top. Names that match a CE template replace it;
    // names unique to the overrides are added as new templates.
    for (name, content) in overrides {
        tera.add_raw_template(name, content)?;
    }

    tera.build_inheritance_chains()?;
    tera.check_macro_files()?;
    Ok(tera)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: check_required_directories
// Ensures config, DB, and key parent directories exist; creates them if not.
// ─────────────────────────────────────────────────────────────────────────────
pub fn check_required_directories() -> Result<(), Box<dyn Error>> {
    use crate::config::{config_path, private_key_path, db_path};
    let targets = [config_path(), db_path(), private_key_path()];

    for target in targets {
        if let Some(parent) = std::path::Path::new(&target).parent() {
            if !parent.exists() {
                info!("Required directory {:?} is missing. Attempting to create...", parent);
                std::fs::create_dir_all(parent)?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = if target == private_key_path() { 0o700 } else { 0o755 };
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(mode));
            }
        }
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: serve_embedded_static_file
// Serves a static asset from the embedded STATIC_FILES_DIR directory.
// Returns 404 if the path is not found in the bundle.
//
// Caching: every page pulls ~4.8 MB of vendor JS/CSS (AdminLTE, jQuery,
// DataTables, Chart.js, pdfmake …). Without validators the browser re-fetched
// all of it on every navigation, which dominated page-load time. Assets are
// compiled into the binary, so their content is fixed for a given build: we
// emit a strong ETag derived from the build version + path + length and answer
// If-None-Match with 304, turning repeat loads into a few hundred bytes.
// max-age is deliberately short (1 h) rather than "immutable" because the URLs
// carry no content hash — after an upgrade the changed ETag makes the first
// revalidation serve the new file instead of pinning stale assets for a year.
// ─────────────────────────────────────────────────────────────────────────────
pub async fn serve_embedded_static_file(
    path: PathBuf,
    req_headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let path_str = path.to_str().unwrap_or("");
    match STATIC_FILES_DIR.get_file(path_str) {
        Some(file) => {
            // Build-scoped validator: app_version changes on every release, so
            // upgrades invalidate; length guards edits within one version.
            let etag = format!(
                "\"{}-{:x}\"",
                app_version(),
                {
                    // Cheap FNV-1a over path + length — no hashing of the whole
                    // file on every request (some assets are megabytes).
                    let mut h: u64 = 0xcbf29ce484222325;
                    for b in path_str.as_bytes().iter().chain(&file.contents().len().to_le_bytes()) {
                        h ^= *b as u64;
                        h = h.wrapping_mul(0x100000001b3);
                    }
                    h
                }
            );

            // Conditional request → 304 with no body.
            if let Some(inm) = req_headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
                if inm.split(',').any(|t| t.trim() == etag) {
                    return axum::response::Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header(header::ETAG, &etag)
                        .header(header::CACHE_CONTROL, "public, max-age=3600")
                        .body(Body::empty())
                        .unwrap();
                }
            }

            let mime_type = mime_guess::from_path(path).first_or_octet_stream();
            axum::response::Response::builder()
                .header(header::CONTENT_TYPE, mime_type.to_string())
                .header(header::ETAG, &etag)
                .header(header::CACHE_CONTROL, "public, max-age=3600")
                .body(Body::from(Bytes::from(file.contents())))
                .unwrap()
        }
        None => axum::response::Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Static file not found"))
            .unwrap(),
    }
}

// 6. Initialisation guard middleware
// Redirects every request to /install when the DB has not been set up yet,
// and redirects /install to /login once setup is complete.
// NOTE: called via closure in create_core_router so the Arc is captured
// directly rather than extracted from an Extension (which would not be
// available at the outermost middleware layer).
// ─────────────────────────────────────────────────────────────────────────────
// Middleware: init_guard
// Redirects every request to /install when the DB has not been set up yet,
// and redirects /install to /login once setup is complete.
// Static assets are always let through so the install page renders correctly.
// ─────────────────────────────────────────────────────────────────────────────
async fn init_guard(
    is_initialized: Arc<AtomicBool>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path().to_owned();
    let initialized = is_initialized.load(Ordering::SeqCst);

    // Let static assets and health probes through unconditionally. /health
    // and /ready must answer even before the DB is initialised so k8s can
    // bring the pod up cleanly during a fresh install or upgrade.
    let is_asset = path == "/health"
        || path == "/ready"
        || path.starts_with("/static/")
        || path.starts_with("/agents/")   // public client-binary downloads
        || {
        let p = path.as_str();
        p.ends_with(".css") || p.ends_with(".js") || p.ends_with(".png")
            || p.ends_with(".ico") || p.ends_with(".svg") || p.ends_with(".woff2")
    };

    if is_asset {
        return next.run(request).await;
    }

    if !initialized && !path.starts_with("/install") {
        return axum::response::Redirect::to("/install").into_response();
    }
    if initialized && path == "/install" {
        return axum::response::Redirect::to("/login").into_response();
    }

    next.run(request).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: create_core_router
// Builds and returns the full CE Axum Router with all routes, extensions, and
// the init_guard middleware. EE/SaaS merge additional routes on top.
// ─────────────────────────────────────────────────────────────────────────────
pub fn create_core_router(state: AppState, cookie_key: axum_extra::extract::cookie::Key) -> Router {
    Router::new()
        // Probes — must come first so they're not shadowed by anything else
        // and are easy to find. The init_guard middleware whitelists them so
        // they answer even before /install completes.
        .route("/health", get(handlers::health))
        .route("/ready",  get(handlers::ready))
        .route("/install", get(install::install_get).post(install::install_post))
        .route("/", get(dashboard::dashboard))
        .route("/login", get(auth::login).post(auth::login_submit))
        .route("/logout", get(auth::logout))
        .route("/notifications/clear", get(handlers::clear_notifications))
        // Guided first-run tour. Both are per-user and touch only the calling
        // user's own row, so Viewer is the correct floor.
        .route("/tour/dismiss", post(tour::tour_dismiss))
        .route("/tour/reopen", get(tour::tour_reopen))
        .route("/admin/audit-log", get(audit::audit_log_view))
        .route("/users", get(users::users))
        .route("/users/add", get(users::users_add).post(users::users_add_save))
        .route("/users/delete/{id}", get(users::users_delete))
        .route("/users/edit/{id}", get(users::users_edit).post(users::users_edit_save))
        .route("/users/changepassword/{id}", post(users::change_password))
        .route("/systems", get(systems::systems))
        .route("/systems/report/{id}", get(systems::system_report))
        .route("/systems/{id}/containers/{cid}", get(systems::container_detail))
        .route("/systems/report/{system_id}/run/{policy_id}", post(systems::system_report_run_policy))
        .route("/systems/report/{system_id}/exclude/{test_id}", post(systems::system_report_exclude))
        .route("/systems/report/{system_id}/unexclude/{test_id}", post(systems::system_report_unexclude))
        .route("/systems/report/{id}/save", get(reports::system_report_save))
        .route("/systems/report/{id}/download", get(reports::system_report_live_download))
        .route("/systems/report/{id}/email", post(reports::system_report_live_email))
        .route("/systems/delete/{id}", get(systems::systems_delete))
        .route("/systems/edit/{id}", get(systems::systems_edit).post(systems::systems_edit_save))
        .route("/systems/pending", get(systems::systems_pending))
        .route("/systems/tokens", get(enrollment::tokens_page))
        .route("/systems/tokens/create", post(enrollment::tokens_create))
        .route("/systems/tokens/toggle/{id}", post(enrollment::tokens_toggle))
        .route("/systems/tokens/delete/{id}", get(enrollment::tokens_delete))
        .route("/systems/approve/{id}", get(systems::systems_approve))
        .route("/systems/bulk/approve", post(systems::systems_bulk_approve))
        .route("/systems/bulk/delete", post(systems::systems_bulk_delete))
        .route("/systems/bulk/add_group", post(systems::systems_bulk_add_group))
        .route("/system_groups", get(groups::system_groups))
        .route("/system_groups/add", get(groups::system_groups_add).post(groups::system_groups_add_save))
        .route("/system_groups/delete/{id}", get(groups::system_groups_delete))
        .route("/system_groups/edit/{id}", get(groups::system_groups_edit).post(groups::system_groups_edit_save))
        .route("/system_groups/auto/add",
               get(auto_groups_admin::auto_add).post(auto_groups_admin::auto_add_save))
        .route("/system_groups/auto/edit/{id}",
               get(auto_groups_admin::auto_edit).post(auto_groups_admin::auto_edit_save))
        .route("/system_groups/auto/toggle/{id}",
               post(auto_groups_admin::auto_toggle))
        .route("/tests", get(tests::tests))
        .route("/tests/add", get(tests::tests_add).post(tests::tests_add_save))
        .route("/tests/delete/{id}", get(tests::tests_delete))
        .route("/tests/bulk/delete", post(tests::tests_bulk_delete))
        .route("/tests/bulk/add_policy", post(tests::tests_bulk_add_policy))
        .route("/tests/edit/{id}", get(tests::tests_edit).post(tests::tests_edit_save))
        .route("/policies", get(policies::policies))
        .route("/policies/add", get(policies::policies_add).post(policies::policies_add_save))
        .route("/policies/edit/{id}", get(policies::policies_edit).post(policies::policies_edit_save))
        .route("/policies/delete/{id}", get(policies::policies_delete))
        .route("/policies/run/{id}", get(policies::policies_run))
        .route("/policies/report/{id}", get(policies::policies_report))
        .route("/policies/report/{policy_id}/exclude/{system_id}/{test_id}", post(policies::policies_report_exclude))
        .route("/policies/report/{policy_id}/unexclude/{system_id}/{test_id}", post(policies::policies_report_unexclude))
        .route("/policies/download/{id}", get(policies::policies_report_download))
        .route("/policies/email/{id}", post(policies::policies_report_email))
        .route("/policies/export/{id}", get(policies::policies_export))
        .route("/policies/import", post(policies::policies_import))
        .route("/reports", get(reports::reports))
        .route("/reports/save/{id}", get(reports::reports_save))
        .route("/reports/view/{id}", get(reports::reports_view))
        .route("/reports/diff",      get(reports::reports_diff))
        .route("/reports/delete/{id}", get(reports::reports_delete))
        .route("/reports/bulk/delete", post(reports::reports_bulk_delete))
        .route("/reports/download/{id}", get(reports::reports_download))
        .route("/reports/email/{id}", post(reports::reports_email))
        .route("/reports/system/view/{id}", get(reports::system_reports_view))
        .route("/reports/system/diff",      get(reports::system_reports_diff))
        .route("/reports/system/download/{id}", get(reports::system_reports_download))
        .route("/reports/system/email/{id}", post(reports::system_reports_email))
        .route("/reports/system/delete/{id}", get(reports::system_reports_delete))
        .route("/reports/system/bulk/delete", post(reports::system_reports_bulk_delete))
        .route("/settings", get(settings::settings))
        .route("/settings/save", post(settings::settings_save))
        .route("/settings/test-email", post(settings::settings_test_email))
        .route("/settings/reset", post(settings::settings_reset))
        .route("/settings/rotate-keys", post(settings::settings_rotate_keys))
        .route("/admin/directories",              get(directories::list_view))
        .route("/admin/directories/add",          get(directories::add_form).post(directories::add_submit))
        .route("/admin/directories/edit/{id}",    get(directories::edit_form).post(directories::edit_submit))
        .route("/admin/directories/delete/{id}",  post(directories::delete))
        .route("/admin/directories/test/{id}",    post(directories::test))
        .route("/systems/upgrade/{id}", post(systems::systems_upgrade))
        .route("/systems/bulk/upgrade", post(systems::systems_bulk_upgrade))
        .route("/systems/upgrade_all",  post(systems::systems_upgrade_all))
        .route("/send", post(client::send))
        .route("/result", post(client::receive_result))
        .route("/{*path}", get(|axum::extract::Path(path): axum::extract::Path<String>,
                                headers: axum::http::HeaderMap| async move {
            serve_embedded_static_file(PathBuf::from(path), headers).await
        }))
        .fallback(handlers::not_found)
        .layer(Extension(state.pool))
        .layer(Extension(state.tera))
        .layer(Extension(state.config))
        .layer(Extension(state.sync_tx))
        .layer(Extension(state.is_initialized.clone()))   // available to handlers
        .layer({                                           // middleware uses closure, not Extension
            let flag = state.is_initialized.clone();
            middleware::from_fn(move |req, next| {
                let flag = flag.clone();
                async move { init_guard(flag, req, next).await }
            })
        })
        // Compress responses (gzip/brotli, negotiated via Accept-Encoding).
        // The UI ships megabytes of vendor JS/CSS plus large HTML report
        // tables, all highly compressible. Outermost so it applies to every
        // route; tower-http adds `Vary: accept-encoding` and skips responses
        // that are already encoded or too small to be worth it.
        .layer(tower_http::compression::CompressionLayer::new())
        .with_state(cookie_key)
}
