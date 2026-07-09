//! Superadmin-only management of console admin accounts (multi-admin
//! support). Modeled on `admin::servers`'s HTMX partial-swap pattern.

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
    admin_id::AdminId, console_admin_service::ConsoleAdmin, encryption::Password,
    ui::admin::ownership::SuperAdmin, AppState,
};

#[derive(Template)]
#[template(path = "admin/admins.html")]
pub struct AdminsPageTemplate {
    pub ui_route: String,
}

#[derive(Template)]
#[template(path = "admin/admin_list.html")]
pub struct AdminListTemplate {
    pub admins: Vec<ConsoleAdmin>,
    pub ui_route: String,
}

#[derive(Deserialize)]
pub struct AddAdminForm {
    pub username: String,
    pub password: Password,
    #[serde(default)]
    pub is_superadmin: bool,
}

#[derive(Deserialize)]
pub struct UpdatePasswordForm {
    pub password: Password,
}

async fn render_admin_list(state: &AppState) -> Result<String, String> {
    match state.console_admins.list_admins().await {
        Ok(admins) => {
            let template = AdminListTemplate {
                admins,
                ui_route: state.get_ui_route().await,
            };
            template.render().map_err(|e| e.to_string())
        }
        Err(e) => Err(e.to_string()),
    }
}

async fn admin_list_response(state: &AppState) -> Response {
    match render_admin_list(state).await {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render admin list: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Error").into_response()
        }
    }
}

/// Main admins management page
pub async fn admins_page(State(state): State<AppState>, _admin: SuperAdmin) -> impl IntoResponse {
    let template = AdminsPageTemplate {
        ui_route: state.get_ui_route().await,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render admins template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

/// Get admin list partial (for HTMX)
pub async fn get_admin_list(
    State(state): State<AppState>,
    _admin: SuperAdmin,
) -> impl IntoResponse {
    admin_list_response(&state).await
}

/// Add a new console admin
pub async fn add_admin(
    State(state): State<AppState>,
    _admin: SuperAdmin,
    Form(form): Form<AddAdminForm>,
) -> Response {
    let username = form.username.trim();
    if username.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Username cannot be empty</div>"),
        )
            .into_response();
    }
    if form.password.as_str().len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Password must be at least 8 characters</div>"),
        )
            .into_response();
    }

    match state
        .console_admins
        .create_admin(username, form.password.as_str(), form.is_superadmin)
        .await
    {
        Ok(admin) => {
            info!(
                "Created console admin '{}' (id {})",
                admin.username, admin.id
            );
            admin_list_response(&state).await
        }
        Err(e) => {
            error!("Failed to create console admin: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Html("<div class=\"alert alert-error\">Failed to create admin (username may already be taken)</div>"),
            )
                .into_response()
        }
    }
}

/// Delete a console admin. Refuses to delete the last remaining superadmin,
/// so the instance can never end up with nobody able to manage admins or
/// global settings.
pub async fn delete_admin(
    State(state): State<AppState>,
    _admin: SuperAdmin,
    Path(admin_id): Path<AdminId>,
) -> Response {
    let admins = match state.console_admins.list_admins().await {
        Ok(admins) => admins,
        Err(e) => {
            error!("Failed to list admins: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    let Some(target) = admins.iter().find(|a| a.id == admin_id) else {
        return (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Admin not found</div>"),
        )
            .into_response();
    };

    if target.is_superadmin && admins.iter().filter(|a| a.is_superadmin).count() <= 1 {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Cannot delete the last remaining superadmin</div>"),
        )
            .into_response();
    }

    match state.console_admins.delete_admin(admin_id).await {
        Ok(true) => {
            info!("Deleted console admin id {}", admin_id);
            // Servers this admin owned become ownerless (ON DELETE SET NULL
            // at the DB level) -- they stay in the shared library, just
            // needing reassignment by a superadmin.
            admin_list_response(&state).await
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Admin not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to delete admin {}: {}", admin_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
        }
    }
}

/// Reset a console admin's password
pub async fn update_admin_password(
    State(state): State<AppState>,
    _admin: SuperAdmin,
    Path(admin_id): Path<AdminId>,
    Form(form): Form<UpdatePasswordForm>,
) -> Response {
    if form.password.as_str().len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Password must be at least 8 characters</div>"),
        )
            .into_response();
    }

    match state
        .console_admins
        .update_password(admin_id, form.password.as_str())
        .await
    {
        Ok(true) => {
            info!("Updated password for console admin id {}", admin_id);
            admin_list_response(&state).await
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Admin not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to update password for admin {}: {}", admin_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
        }
    }
}
