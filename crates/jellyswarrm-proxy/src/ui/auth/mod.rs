use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use axum_login::{AuthUser, AuthnBackend, UserId};
use serde::{Deserialize, Serialize};
use tokio::task;
use tracing::info;

use crate::{
    admin_id::AdminId, console_admin_service::ConsoleAdminService, encryption::HashedPassword,
    user_authorization_service::UserAuthorizationService,
};

/// Prefix used in `User::id` for console admin accounts, so `Backend` can
/// tell an admin session apart from an end-user session without a separate
/// enum variant on `UserRole` (which would ripple through every existing
/// `role == UserRole::Admin` check). Parsed back out by `parse_console_admin_id`.
const CONSOLE_ADMIN_ID_PREFIX: &str = "console:";

/// Extracts the numeric admin id from a `User::id` produced for an admin
/// session, or `None` if `user_id` isn't a console-admin id. Used by the
/// `CurrentAdmin` extractor in `ui::admin::ownership` to recover *which*
/// admin is logged in for ownership checks.
pub fn parse_console_admin_id(user_id: &str) -> Option<AdminId> {
    user_id
        .strip_prefix(CONSOLE_ADMIN_ID_PREFIX)
        .and_then(|s| s.parse::<i64>().ok())
        .map(AdminId::new)
}

fn console_admin_user_id(id: AdminId) -> String {
    format!("{CONSOLE_ADMIN_ID_PREFIX}{id}")
}

mod routes;

pub use routes::router;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UserRole {
    Admin,
    User,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: HashedPassword,
    pub role: UserRole,
}

pub struct AuthenticatedUser(pub User);

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_session = AuthSession::from_request_parts(parts, state)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        match auth_session.user {
            Some(user) => Ok(AuthenticatedUser(user)),
            None => Err(StatusCode::UNAUTHORIZED),
        }
    }
}

// Here we've implemented `Debug` manually to avoid accidentally logging the
// password hash.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("role", &self.role)
            .finish()
    }
}

impl AuthUser for User {
    type Id = String;

    fn id(&self) -> Self::Id {
        self.id.clone()
    }

    fn session_auth_hash(&self) -> &[u8] {
        self.password_hash.as_str().as_bytes() // We use the password hash as the auth
                                               // hash--what this means
                                               // is when the user changes their password the
                                               // auth session becomes invalid.
    }
}

// This allows us to extract the authentication fields from forms. We use this
// to authenticate requests with the backend.
#[derive(Debug, Clone, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Backend {
    user_auth: Arc<UserAuthorizationService>,
    console_admins: Arc<ConsoleAdminService>,
}

impl Backend {
    pub fn new(
        user_auth: Arc<UserAuthorizationService>,
        console_admins: Arc<ConsoleAdminService>,
    ) -> Self {
        Self {
            user_auth,
            console_admins,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    TaskJoin(#[from] task::JoinError),
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

impl AuthnBackend for Backend {
    type User = User;
    type Credentials = Credentials;
    type Error = Error;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        info!("Authenticating user: {}", creds.username);

        if let Some(admin) = self
            .console_admins
            .verify_credentials(&creds.username, &creds.password)
            .await?
        {
            info!("Admin authentication successful: {}", admin.username);
            let user = User {
                id: console_admin_user_id(admin.id),
                username: admin.username,
                password_hash: HashedPassword::from_hashed(admin.password_hash),
                role: UserRole::Admin,
            };
            return Ok(Some(user));
        }

        let password = creds.password.into();
        if let Some(user) = self
            .user_auth
            .get_user_by_credentials(&creds.username, &password)
            .await?
        {
            info!("User authentication successful: {}", user.original_username);
            let user = User {
                id: user.id,
                username: user.original_username,
                password_hash: user.original_password_hash,
                role: UserRole::User,
            };
            return Ok(Some(user));
        }

        info!("Authentication failed for user: {}", creds.username);
        Ok(None)
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        if let Some(admin_id) = parse_console_admin_id(user_id) {
            return Ok(self
                .console_admins
                .get_admin_by_id(admin_id)
                .await?
                .map(|admin| User {
                    id: console_admin_user_id(admin.id),
                    username: admin.username,
                    password_hash: HashedPassword::from_hashed(admin.password_hash),
                    role: UserRole::Admin,
                }));
        }

        if let Some(user) = self.user_auth.get_user_by_id(user_id).await? {
            let user = User {
                id: user.id,
                username: user.original_username,
                password_hash: user.original_password_hash,
                role: UserRole::User,
            };
            return Ok(Some(user));
        }

        Ok(None)
    }
}

// We use a type alias for convenience.
//
// Note that we've supplied our concrete backend here.
pub type AuthSession = axum_login::AuthSession<Backend>;
