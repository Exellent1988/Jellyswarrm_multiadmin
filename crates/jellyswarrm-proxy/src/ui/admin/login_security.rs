use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use tracing::error;

use crate::{config::save_config, ui::admin::ownership::CurrentAdmin, AppState};

#[derive(Template)]
#[template(path = "admin/login_security.html")]
pub struct LoginSecurityPageTemplate {
    pub ui_route: String,
}

pub struct BlockedEntryView {
    pub identifier: String,
    pub failure_count: i64,
    pub seconds_remaining: i64,
}

#[derive(Template)]
#[template(path = "admin/login_security_panel.html")]
pub struct LoginSecurityPanelTemplate {
    pub enabled: bool,
    pub max_attempts: i64,
    pub window_secs: i64,
    pub cooldown_secs: i64,
    pub blocked: Vec<BlockedEntryView>,
    pub ui_route: String,
}

/// Main login security page. Reachable by every console admin (not
/// superadmin-gated): this protects the shared login endpoint itself, so
/// every admin has a stake in seeing and managing it, unlike per-instance
/// settings that only a superadmin should change.
pub async fn login_security_page(
    State(state): State<AppState>,
    _admin: CurrentAdmin,
) -> impl IntoResponse {
    let template = LoginSecurityPageTemplate {
        ui_route: state.get_ui_route().await,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render login security page: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

async fn render_panel(state: &AppState) -> Result<String, String> {
    let cfg = state.config.read().await.clone();
    let entries = state
        .login_rate_limit
        .list_blocked()
        .await
        .map_err(|e| e.to_string())?;

    let now = chrono::Utc::now();
    let blocked = entries
        .into_iter()
        .map(|entry| {
            let seconds_remaining = entry
                .blocked_until
                .map(|blocked_until| (blocked_until - now).num_seconds().max(0))
                .unwrap_or(0);
            BlockedEntryView {
                identifier: entry.identifier,
                failure_count: entry.failure_count,
                seconds_remaining,
            }
        })
        .collect();

    let template = LoginSecurityPanelTemplate {
        enabled: cfg.login_rate_limit_enabled,
        max_attempts: cfg.login_rate_limit_max_attempts,
        window_secs: cfg.login_rate_limit_window_secs,
        cooldown_secs: cfg.login_rate_limit_cooldown_secs,
        blocked,
        ui_route: state.get_ui_route().await,
    };
    template.render().map_err(|e| e.to_string())
}

async fn panel_response(state: &AppState) -> Response {
    match render_panel(state).await {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render login security panel: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response()
        }
    }
}

pub async fn get_login_security_panel(
    State(state): State<AppState>,
    _admin: CurrentAdmin,
) -> impl IntoResponse {
    panel_response(&state).await
}

#[derive(Deserialize)]
pub struct SaveLoginSecurityForm {
    #[serde(default)]
    pub enabled: bool,
    pub max_attempts: i64,
    pub window_secs: i64,
    pub cooldown_secs: i64,
}

pub async fn save_login_security(
    State(state): State<AppState>,
    _admin: CurrentAdmin,
    Form(form): Form<SaveLoginSecurityForm>,
) -> Response {
    if form.max_attempts < 1 || form.window_secs < 1 || form.cooldown_secs < 1 {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Values must be positive</div>"),
        )
            .into_response();
    }

    {
        let mut cfg = state.config.write().await;
        cfg.login_rate_limit_enabled = form.enabled;
        cfg.login_rate_limit_max_attempts = form.max_attempts;
        cfg.login_rate_limit_window_secs = form.window_secs;
        cfg.login_rate_limit_cooldown_secs = form.cooldown_secs;
        if let Err(e) = save_config(&cfg) {
            error!("Save failed: {}", e);
        }
    }

    panel_response(&state).await
}

pub async fn unblock_login_rate_limit(
    State(state): State<AppState>,
    _admin: CurrentAdmin,
    Path(identifier): Path<String>,
) -> Response {
    if let Err(e) = state.login_rate_limit.unblock(&identifier).await {
        error!("Failed to unblock '{}': {}", identifier, e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html("<div class=\"alert alert-error\">Failed to unblock</div>"),
        )
            .into_response();
    }

    panel_response(&state).await
}
