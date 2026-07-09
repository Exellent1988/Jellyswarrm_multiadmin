use askama::Template;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    Form,
};
use serde::Deserialize;
use tracing::{error, info};

use crate::{
    config::MediaStreamingMode,
    encryption::{encrypt_password, Password},
    server_id::ServerId,
    server_storage::Server,
    ui::admin::ownership::{require_owner_or_superadmin, CurrentAdmin},
    AppState,
};

#[derive(Template)]
#[template(path = "admin/servers.html")]
pub struct ServersPageTemplate {
    pub ui_route: String,
}

pub struct ServerWithAdmin {
    pub server: Server,
    pub has_admin: bool,
    pub is_redirect: bool,
    pub is_proxy: bool,
    /// Owning admin's username, resolved only when the viewer is a
    /// superadmin (the only audience the owner column is shown to).
    pub owner_username: Option<String>,
}

#[derive(Template)]
#[template(path = "admin/server_list.html")]
pub struct ServerListTemplate {
    pub servers: Vec<ServerWithAdmin>,
    pub ui_route: String,
    pub is_superadmin: bool,
}

#[derive(Deserialize)]
pub struct AddServerForm {
    pub name: String,
    pub url: String,
    pub priority: i32,
    pub media_streaming_mode: String,
}

#[derive(Deserialize)]
pub struct UpdatePriorityForm {
    pub priority: i32,
}

#[derive(Deserialize)]
pub struct UpdateMediaStreamingModeForm {
    pub media_streaming_mode: String,
}

#[derive(Deserialize)]
pub struct AddServerAdminForm {
    pub username: String,
    pub password: Password,
}

/// Servers the viewer is allowed to manage: every server for a superadmin,
/// only their own otherwise. This is the sole place that decides which
/// servers show up in the admin UI's list/mutation surface -- the
/// end-user-facing merged library (`server_storage.list_servers()` called
/// from federation/handlers code) is never filtered this way.
async fn visible_servers(
    state: &AppState,
    viewer: &CurrentAdmin,
) -> Result<Vec<Server>, sqlx::Error> {
    if viewer.is_superadmin {
        state.server_storage.list_servers().await
    } else {
        state.server_storage.list_servers_owned_by(viewer.id).await
    }
}

async fn render_server_list(state: &AppState, viewer: &CurrentAdmin) -> Result<String, String> {
    match visible_servers(state, viewer).await {
        Ok(servers) => {
            let mut servers_with_admin = Vec::new();
            for server in servers {
                let has_admin = state
                    .server_storage
                    .get_server_admin(server.id)
                    .await
                    .unwrap_or(None)
                    .is_some();
                let is_redirect = server.media_streaming_mode == MediaStreamingMode::Redirect;
                let owner_username = if viewer.is_superadmin {
                    match server.owner_admin_id {
                        Some(owner_id) => state
                            .console_admins
                            .get_admin_by_id(owner_id)
                            .await
                            .ok()
                            .flatten()
                            .map(|admin| admin.username),
                        None => None,
                    }
                } else {
                    None
                };
                servers_with_admin.push(ServerWithAdmin {
                    server,
                    has_admin,
                    is_redirect,
                    is_proxy: !is_redirect,
                    owner_username,
                });
            }

            let template = ServerListTemplate {
                servers: servers_with_admin,
                ui_route: state.get_ui_route().await,
                is_superadmin: viewer.is_superadmin,
            };

            template.render().map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Main servers management page
pub async fn servers_page(State(state): State<AppState>) -> impl IntoResponse {
    let template = ServersPageTemplate {
        ui_route: state.get_ui_route().await,
    };

    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render servers template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

/// Get server list partial (for HTMX)
pub async fn get_server_list(
    State(state): State<AppState>,
    admin: CurrentAdmin,
) -> impl IntoResponse {
    server_list_response(&state, &admin).await
}

/// Renders the server list partial as a `Response`, for handlers that
/// already have `state`/`admin` in scope and want to return the refreshed
/// list after a mutation (mirrors what re-calling the `get_server_list`
/// handler would do, without needing to re-run extraction).
async fn server_list_response(state: &AppState, admin: &CurrentAdmin) -> Response {
    match render_server_list(state, admin).await {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render server list: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response()
        }
    }
}

/// Add a new server
pub async fn add_server(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Form(form): Form<AddServerForm>,
) -> Response {
    // Validate the form data
    if form.name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Server name cannot be empty</div>"),
        )
            .into_response();
    }

    if form.url.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Server URL cannot be empty</div>"),
        )
            .into_response();
    }

    if form.priority < 1 || form.priority > 999 {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Priority must be between 1 and 999</div>"),
        )
            .into_response();
    }

    let media_streaming_mode = match form.media_streaming_mode.parse::<MediaStreamingMode>() {
        Ok(mode) => mode,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Html("<div class=\"alert alert-error\">Invalid streaming mode</div>"),
            )
                .into_response()
        }
    };

    // Try to add the server, owned by whoever's creating it.
    match state
        .server_storage
        .add_server_with_owner(
            form.name.trim(),
            form.url.trim(),
            form.priority,
            media_streaming_mode,
            Some(admin.id),
        )
        .await
    {
        Ok(server_id) => {
            info!(
                "Added new server: {} ({}) with ID: {} (owner admin {})",
                form.name, form.url, server_id, admin.id
            );

            // Force Update server state
            state.server_storage.check_servers_health().await;

            // Return updated server list
            server_list_response(&state, &admin).await
        }
        Err(e) => {
            error!("Failed to add server: {}", e);

            let error_message = if let sqlx::Error::Database(db_error) = &e {
                let constraint = db_error.constraint().unwrap_or_default();
                let message = db_error.message();
                if constraint == "idx_servers_url_unique"
                    || message.contains("idx_servers_url_unique")
                    || message.contains("servers.url")
                {
                    "A server with that URL already exists"
                } else if message.contains("servers.name")
                    || message.contains("UNIQUE constraint failed")
                {
                    "A server with that name already exists"
                } else {
                    "Failed to add server"
                }
            } else if e.to_string().contains("Invalid URL") {
                "Invalid URL format"
            } else {
                "Failed to add server"
            };

            (
                StatusCode::BAD_REQUEST,
                Html(format!(
                    "<div class=\"alert alert-error\">{error_message}</div>"
                )),
            )
                .into_response()
        }
    }
}

/// Update server media streaming mode
pub async fn update_server_media_streaming_mode(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Path(server_id): Path<ServerId>,
    Form(form): Form<UpdateMediaStreamingModeForm>,
) -> Response {
    if let Err(rejection) = require_owner_or_superadmin(&state, &admin, server_id).await {
        return rejection;
    }

    let media_streaming_mode = match form.media_streaming_mode.parse::<MediaStreamingMode>() {
        Ok(mode) => mode,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Html("<div class=\"alert alert-error\">Invalid streaming mode</div>"),
            )
                .into_response()
        }
    };

    match state
        .server_storage
        .update_server_media_streaming_mode(server_id, media_streaming_mode)
        .await
    {
        Ok(true) => {
            info!(
                "Updated server {} media streaming mode to {}",
                server_id, media_streaming_mode
            );
            server_list_response(&state, &admin).await
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Server not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update server media streaming mode: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to update streaming mode</div>"),
            )
                .into_response()
        }
    }
}

/// Delete a server
pub async fn delete_server(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Path(server_id): Path<ServerId>,
) -> Response {
    if let Err(rejection) = require_owner_or_superadmin(&state, &admin, server_id).await {
        return rejection;
    }

    match state.server_storage.delete_server(server_id).await {
        Ok(true) => {
            state
                .play_sessions
                .remove_sessions_for_server(server_id)
                .await;
            info!("Deleted server with ID: {}", server_id);
            // Return updated server list
            server_list_response(&state, &admin).await
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Server not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete server: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to delete server</div>"),
            )
                .into_response()
        }
    }
}

/// Update server priority
pub async fn update_server_priority(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Path(server_id): Path<ServerId>,
    Form(form): Form<UpdatePriorityForm>,
) -> Response {
    if let Err(rejection) = require_owner_or_superadmin(&state, &admin, server_id).await {
        return rejection;
    }

    if form.priority < 1 || form.priority > 999 {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Priority must be between 1 and 999</div>"),
        )
            .into_response();
    }

    match state
        .server_storage
        .update_server_priority(server_id, form.priority)
        .await
    {
        Ok(true) => {
            info!("Updated server {} priority to {}", server_id, form.priority);
            // Return updated server list
            server_list_response(&state, &admin).await
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Server not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update server priority: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to update priority</div>"),
            )
                .into_response()
        }
    }
}

/// Add server admin
pub async fn add_server_admin(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Path(server_id): Path<ServerId>,
    Form(form): Form<AddServerAdminForm>,
) -> Response {
    // 1. Get server details, only for the owning admin (or a superadmin) --
    // this manages the *upstream* Jellyfin admin credentials used for
    // federation sync, still a management-plane action scoped to whoever
    // owns the server.
    let server = match require_owner_or_superadmin(&state, &admin, server_id).await {
        Ok(server) => server,
        Err(rejection) => return rejection,
    };

    // 2. Verify credentials with upstream Jellyfin and check admin status
    let client_info = crate::config::CLIENT_INFO.clone();

    let client = match jellyfin_api::JellyfinClient::new(server.url.as_str(), client_info) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to create jellyfin client: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div style=\"background-color: #e74c3c; color: white; padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem;\">Client error</div>"),
            )
                .into_response();
        }
    };

    match client
        .authenticate_by_name(&form.username, form.password.as_str())
        .await
    {
        Ok(user) => {
            // Check if user is admin
            let is_admin = user.policy.map(|p| p.is_administrator).unwrap_or(false);

            if !is_admin {
                return (
                    StatusCode::OK,
                    Html("<div style=\"background-color: #e74c3c; color: white; padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem;\">User is not an administrator on this server</div>"),
                )
                    .into_response();
            }

            // 3. Encrypt password with admin master password
            let config = state.config.read().await;
            let encrypted_password = match encrypt_password(&form.password, &config.password.clone().into()) {
                Ok(p) => p,
                Err(e) => {
                    error!("Encryption failed: {}", e);
                    return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Html("<div style=\"background-color: #e74c3c; color: white; padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem;\">Encryption failed</div>"),
                        )
                            .into_response();
                }
            };

            // 4. Save to database
            match state
                .server_storage
                .add_server_admin(server_id, &form.username, &encrypted_password)
                .await
            {
                Ok(_) => {
                    info!("Added admin for server {}", server.name);
                    match render_server_list(&state, &admin).await {
                        Ok(html) => Html(format!(
                            r#"<div id="server-list" hx-swap-oob="innerHTML">{}</div>"#,
                            html
                        ))
                        .into_response(),
                        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
                    }
                }
                Err(e) => {
                    error!("Failed to add server admin: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Html("<div style=\"background-color: #e74c3c; color: white; padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem;\">Database error</div>"),
                    )
                        .into_response()
                }
            }
        }
        Err(jellyfin_api::error::Error::AuthenticationFailed(_)) => {
            (
                StatusCode::OK,
                Html("<div style=\"background-color: #e74c3c; color: white; padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem;\">Invalid credentials</div>"),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to authenticate with upstream: {}", e);
            (
                StatusCode::OK,
                Html(format!(
                    "<div style=\"background-color: #e74c3c; color: white; padding: 0.75rem; border-radius: 0.25rem; margin-bottom: 1rem;\">Connection error: {}</div>",
                    e
                )),
            )
                .into_response()
        }
    }
}

/// Delete server admin
pub async fn delete_server_admin(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Path(server_id): Path<ServerId>,
) -> Response {
    if let Err(rejection) = require_owner_or_superadmin(&state, &admin, server_id).await {
        return rejection;
    }

    match state.server_storage.delete_server_admin(server_id).await {
        Ok(true) => {
            info!("Deleted admin for server ID: {}", server_id);
            server_list_response(&state, &admin).await
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Admin not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete server admin: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to delete admin</div>"),
            )
                .into_response()
        }
    }
}
