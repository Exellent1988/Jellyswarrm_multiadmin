//! Shared ownership-scoping building blocks for the admin UI: recovering
//! *which* console admin is logged in, and checking whether they may act on
//! a given server. Kept in one place so the rule (owner or superadmin) isn't
//! duplicated across every servers.rs/users.rs handler.

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    admin_id::AdminId,
    server_id::ServerId,
    server_storage::Server,
    ui::auth::{parse_console_admin_id, AuthenticatedUser, UserRole},
    AppState,
};

/// The currently logged-in console admin, resolved from the session and
/// verified against the `console_admins` table (catches the account having
/// been deleted since the session was issued).
pub struct CurrentAdmin {
    pub id: AdminId,
    pub is_superadmin: bool,
}

impl FromRequestParts<AppState> for CurrentAdmin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let AuthenticatedUser(user) = AuthenticatedUser::from_request_parts(parts, state)
            .await
            .map_err(|status| status.into_response())?;

        if user.role != UserRole::Admin {
            return Err(StatusCode::FORBIDDEN.into_response());
        }

        let id = parse_console_admin_id(&user.id)
            .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

        let admin = state
            .console_admins
            .get_admin_by_id(id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
            .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;

        Ok(CurrentAdmin {
            id: admin.id,
            is_superadmin: admin.is_superadmin,
        })
    }
}

/// The currently logged-in console admin, verified to be a superadmin.
/// Gates instance-wide settings and admin-account management, which affect
/// every admin/user, not just servers the caller owns -- plain `CurrentAdmin`
/// isn't enough for those.
///
/// A layer-based approach (`axum::middleware::from_fn`) would be the more
/// usual way to gate a whole sub-router like this, but `from_fn` pins its
/// middleware state to `()` unless given a live `AppState` value via
/// `from_fn_with_state` -- which isn't available inside a pure
/// `Router<AppState>` builder function (state is only attached once, in
/// `main.rs`, after the whole router tree is assembled). An extractor
/// doesn't have that problem, since it receives the state directly from
/// whichever concrete `Router<AppState>` ends up serving the request.
pub struct SuperAdmin;

impl FromRequestParts<AppState> for SuperAdmin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let admin = CurrentAdmin::from_request_parts(parts, state).await?;
        if admin.is_superadmin {
            Ok(SuperAdmin)
        } else {
            Err(StatusCode::FORBIDDEN.into_response())
        }
    }
}

/// Whether `admin` may act on `server` -- owns it, or is a superadmin.
/// Superadmins can operate on any server for support/debugging purposes;
/// this never affects the end-user-facing shared library, which is never
/// filtered by ownership at all. Exported for callers (e.g. mapping
/// add/delete in `admin::users`) that already have the `Server` in hand and
/// don't need `require_owner_or_superadmin`'s extra DB fetch.
pub fn may_act_on(admin: &CurrentAdmin, server: &Server) -> bool {
    admin.is_superadmin || server.owner_admin_id == Some(admin.id)
}

/// Loads `server_id` and ensures `admin` may act on it (see [`may_act_on`]).
pub async fn require_owner_or_superadmin(
    state: &AppState,
    admin: &CurrentAdmin,
    server_id: ServerId,
) -> Result<Server, Response> {
    let server = state
        .server_storage
        .get_server_by_id(server_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    if may_act_on(admin, &server) {
        Ok(server)
    } else {
        Err(StatusCode::FORBIDDEN.into_response())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MediaStreamingMode;
    use crate::server_url::ServerUrl;

    fn server_owned_by(owner: Option<AdminId>) -> Server {
        let now = chrono::Utc::now();
        Server {
            id: ServerId::new(1),
            name: "test".to_string(),
            url: ServerUrl::parse("http://example.test").unwrap(),
            priority: 100,
            media_streaming_mode: MediaStreamingMode::Redirect,
            created_at: now,
            updated_at: now,
            owner_admin_id: owner,
        }
    }

    fn admin(id: i64, is_superadmin: bool) -> CurrentAdmin {
        CurrentAdmin {
            id: AdminId::new(id),
            is_superadmin,
        }
    }

    #[test]
    fn owner_may_act_on_their_own_server() {
        let server = server_owned_by(Some(AdminId::new(1)));
        assert!(may_act_on(&admin(1, false), &server));
    }

    #[test]
    fn non_owner_non_superadmin_is_rejected() {
        let server = server_owned_by(Some(AdminId::new(1)));
        assert!(!may_act_on(&admin(2, false), &server));
    }

    #[test]
    fn superadmin_may_act_on_any_server() {
        let server = server_owned_by(Some(AdminId::new(1)));
        assert!(may_act_on(&admin(2, true), &server));
    }

    #[test]
    fn non_owner_is_rejected_even_for_an_ownerless_server() {
        let server = server_owned_by(None);
        assert!(!may_act_on(&admin(1, false), &server));
    }
}
