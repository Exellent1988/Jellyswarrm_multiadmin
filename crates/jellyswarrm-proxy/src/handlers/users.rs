use axum::{
    extract::{Path, State},
    Json,
};
use hyper::{HeaderMap, StatusCode};
use tracing::{debug, error, info, warn};

use crate::{
    encryption::Password,
    extractors::{RequireUser, RequireUserSession},
    handlers::common::execute_json_request,
    models::{AuthenticateRequest, AuthenticateResponse, Authorization, SyncPlayUserAccessType},
    url_helper::join_server_url,
    AppState,
};

use anyhow::Result;

async fn process_user(
    server_user: crate::models::User,
    user: &crate::user_authorization_service::User,
    state: &AppState,
) -> Result<crate::models::User> {
    let mut server_user = server_user;

    server_user.id = user.id.clone();
    server_user.name = user.original_username.clone();
    server_user.policy.is_administrator = false;

    server_user.server_id = state.config.read().await.server_id.clone();

    Ok(server_user)
}

// http://foo:3000/users/public?)
pub async fn handle_public(
    _state: State<AppState>,
) -> Result<Json<Vec<crate::models::User>>, StatusCode> {
    // For now, return an empty list
    Ok(Json(vec![]))
}

pub async fn handle_get_me(
    State(state): State<AppState>,
    RequireUser { preprocessed, user }: RequireUser,
) -> Result<Json<crate::models::User>, StatusCode> {
    // Execute request and parse JSON response
    let server_user: crate::models::User =
        execute_json_request(&state.reqwest_client, preprocessed.request).await?;

    let server_user = process_user(server_user, &user, &state)
        .await
        .map_err(|e| {
            error!("Failed to process user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(server_user))
}

pub async fn handle_get_user_by_id(
    State(state): State<AppState>,
    Path(_user_id): Path<String>,
    RequireUserSession {
        preprocessed,
        user,
        session,
    }: RequireUserSession,
) -> Result<Json<crate::models::User>, StatusCode> {
    // Build request URL using helper function to preserve subdirectories
    let user_path = format!("/Users/{}", session.original_user_id);
    let user_url = join_server_url(&preprocessed.server.url, &user_path);

    let mut request = preprocessed.request;
    *request.url_mut() = user_url;

    // Execute request and parse JSON response
    let server_user: crate::models::User =
        execute_json_request(&state.reqwest_client, request).await?;

    let server_user = process_user(server_user, &user, &state)
        .await
        .map_err(|e| {
            error!("Failed to process user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(server_user))
}

// Authenticates a user by trying all configured servers in parallel
pub async fn handle_authenticate_by_name(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<AuthenticateRequest>,
) -> Result<Json<AuthenticateResponse>, StatusCode> {
    let client_ip = crate::client_ip::extract_client_ip(&headers);
    let rate_limit_enabled = { state.config.read().await.login_rate_limit_enabled };

    if rate_limit_enabled {
        if let Some(seconds_remaining) = state
            .login_rate_limit
            .seconds_until_unblocked(&client_ip)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        {
            warn!(
                "Rejecting login for '{}' from {}: rate-limited for {}s more",
                payload.username, client_ip, seconds_remaining
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    let mut servers = state
        .server_storage
        .list_servers()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if servers.is_empty() {
        tracing::warn!("No servers configured for authentication");
        return Err(StatusCode::NOT_FOUND);
    }

    let authentication = extract_auth_header(&headers).map_err(|_| {
        error!("No valid authorization header found in authentication request");
        StatusCode::BAD_REQUEST
    })?;

    info!(
        "Got login request with authentication header: {}",
        authentication.to_redacted_header_value()
    );

    info!(
        "Attempting authentication for user '{}' across {} servers",
        payload.username,
        servers.len()
    );

    let mut mapped_tasks = Vec::with_capacity(servers.len());

    let existing_user = state
        .user_authorization
        .get_user_by_username(&payload.username)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if existing_user.is_none() && !state.auto_create_users_on_login().await {
        warn!(
            "Auto user creation disabled; rejecting login for non-existing local user '{}'",
            payload.username
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    if let Some(user) = existing_user {
        let server_mappings = state
            .user_authorization
            .list_server_mappings(&user.id)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if !server_mappings.is_empty() {
            for server_mapping in server_mappings {
                if let Some(pos) = servers
                    .iter()
                    .position(|s| s.id == server_mapping.server_id)
                {
                    let server = servers.remove(pos);
                    info!(
                        "Using server mapping for user '{}' on server '{}'",
                        &payload.username, server.name
                    );
                    {
                        let state = state.clone();
                        let authentication = authentication.clone();
                        let payload = payload.clone();
                        mapped_tasks.push(tokio::spawn(async move {
                            authenticate_on_server(
                                state.clone(),
                                authentication.clone(),
                                payload.clone(),
                                server,
                                Some(server_mapping),
                            )
                            .await
                        }));
                    }
                }
            }
        }
    }

    let mapped_server_count = mapped_tasks.len();

    // Await the mapped-server attempts *before* deciding how to handle any
    // unmapped ones. Whether auto-create may run below hinges on whether
    // this exact login already proved itself with real credentials the
    // submitter can't have just made up -- that can only be known once these
    // are in, not while they're still in flight.
    let mut successful_auths: Vec<SuccessfulServerAuth> = Vec::new();
    for task in mapped_tasks {
        match task.await {
            Ok(Ok(auth_response)) => {
                info!("Successfully authenticated user: {}", payload.username);
                successful_auths.push(auth_response);
            }
            Ok(Err(e)) => {
                tracing::debug!("Authentication attempt failed: {:?}", e);
            }
            Err(join_err) => {
                tracing::error!("Authentication task failed: {}", join_err);
            }
        }
    }

    // Whatever's left in `servers` has no mapping for this user yet -- probe
    // it with the freshly-submitted credentials regardless of whether the
    // user is brand new or already has mappings elsewhere. Without this, a
    // user whose first-ever login only matched a subset of servers (e.g.
    // different/nonexistent credentials on another server at the time) would
    // never automatically pick up that server later, even after it becomes
    // reachable with the same password -- the only way in would have been an
    // admin manually adding a mapping. `add_server_mapping` is an upsert
    // keyed on (user_id, server_id), so re-probing an already-mapped server
    // here would be harmless too, but there's nothing left to probe for
    // those since the loop above already removed them from `servers`.
    //
    // This is a *plain* probe -- no auto-create yet. Whether auto-create may
    // run at all depends on whether this same request proves the submitter
    // already holds valid credentials somewhere, and a server they don't yet
    // have an account on obviously can't be the server that proves that.
    if !servers.is_empty() {
        info!(
            "Probing {} unmapped server(s) for user '{}'",
            servers.len(),
            payload.username
        );
    }
    let unmapped_server_count = servers.len();
    let unmapped_probe_tasks: Vec<_> = servers
        .into_iter()
        .map(|server| {
            let state = state.clone();
            let authentication = authentication.clone();
            let payload = payload.clone();
            let server_for_retry = server.clone();
            info!(
                "No server mapping found for user '{}' on server '{}'",
                payload.username, server.name
            );

            tokio::spawn(async move {
                let result =
                    authenticate_on_server(state, authentication, payload, server, None).await;
                (server_for_retry, result)
            })
        })
        .collect();

    let mut unmapped_failures: Vec<crate::server_storage::Server> = Vec::new();
    for task in unmapped_probe_tasks {
        match task.await {
            Ok((_, Ok(auth_response))) => {
                info!("Successfully authenticated user: {}", payload.username);
                successful_auths.push(auth_response);
            }
            Ok((server, Err(e))) => {
                tracing::debug!("Authentication attempt failed: {:?}", e);
                unmapped_failures.push(server);
            }
            Err(join_err) => {
                tracing::error!("Authentication task failed: {}", join_err);
            }
        }
    }

    // Auto-create must never be the *only* thing standing between an
    // arbitrary username/password and a freshly-provisioned account on every
    // federated server -- that would turn the login form into open
    // self-registration. It may only fire once this exact request has
    // already proven, via a real credential match (an existing mapping OR a
    // plain probe above), that the submitter genuinely holds valid
    // credentials somewhere. A brand new username with zero matches
    // anywhere never satisfies that, no matter how many servers have admin
    // credentials configured.
    let user_has_verified_access = !successful_auths.is_empty();

    if user_has_verified_access && !unmapped_failures.is_empty() {
        info!(
            "User '{}' already verified this login on {} server(s); retrying {} unmapped server(s) with auto-create",
            payload.username,
            successful_auths.len(),
            unmapped_failures.len()
        );

        let auto_create_tasks: Vec<_> = unmapped_failures
            .into_iter()
            .map(|server| {
                let state = state.clone();
                let authentication = authentication.clone();
                let payload = payload.clone();
                tokio::spawn(async move {
                    attempt_auto_create_then_authenticate(state, authentication, payload, server)
                        .await
                })
            })
            .collect();

        for task in auto_create_tasks {
            match task.await {
                Ok(Ok(auth_response)) => {
                    info!(
                        "Successfully auto-created and authenticated user: {}",
                        payload.username
                    );
                    successful_auths.push(auth_response);
                }
                Ok(Err(e)) => {
                    tracing::debug!("Auto-create authentication attempt failed: {:?}", e);
                }
                Err(join_err) => {
                    tracing::error!("Auto-create authentication task failed: {}", join_err);
                }
            }
        }
    }

    let total_servers = mapped_server_count + unmapped_server_count;

    if successful_auths.is_empty() {
        tracing::warn!(
            "All authentication attempts failed for user: {}",
            payload.username
        );
        if rate_limit_enabled {
            let (max_attempts, window_secs, cooldown_secs) = {
                let config = state.config.read().await;
                (
                    config.login_rate_limit_max_attempts,
                    config.login_rate_limit_window_secs,
                    config.login_rate_limit_cooldown_secs,
                )
            };
            match state
                .login_rate_limit
                .record_failure(&client_ip, max_attempts, window_secs, cooldown_secs)
                .await
            {
                Ok(true) => warn!(
                    "Client {} exceeded {} failed login attempts; blocking for {}s",
                    client_ip, max_attempts, cooldown_secs
                ),
                Ok(false) => {}
                Err(e) => error!("Failed to record login failure for {}: {}", client_ip, e),
            }
        }
        Err(StatusCode::UNAUTHORIZED)
    } else {
        if rate_limit_enabled {
            if let Err(e) = state.login_rate_limit.record_success(&client_ip).await {
                error!("Failed to clear login rate limit for {}: {}", client_ip, e);
            }
        }

        let user =
            resolve_or_create_login_user(&state, &payload.username, &payload.password).await?;

        persist_successful_auths(
            &state,
            &user,
            &payload.password,
            &authentication,
            &successful_auths,
        )
        .await?;

        let auth_response =
            decorate_auth_response(&state, &user, &payload.username, &successful_auths[0]).await;

        info!(
            "User '{}' successfully authenticated on {} out of {} servers and stored in authorization storage",
            payload.username,
            successful_auths.len(),
            total_servers
        );
        Ok(Json(auth_response))
    }
}

async fn resolve_or_create_login_user(
    state: &AppState,
    username: &str,
    password: &Password,
) -> Result<crate::user_authorization_service::User, StatusCode> {
    state
        .user_authorization
        .get_or_create_user(username, password)
        .await
        .map_err(|e| {
            tracing::error!("Error resolving local user for login: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

async fn persist_successful_auths(
    state: &AppState,
    user: &crate::user_authorization_service::User,
    login_password: &Password,
    login_authorization: &Authorization,
    successful_auths: &[SuccessfulServerAuth],
) -> Result<(), StatusCode> {
    for successful in successful_auths {
        state
            .user_authorization
            .add_server_mapping(
                &user.id,
                &successful.server,
                &successful.final_username,
                &successful.final_password,
                Some(&login_password.clone().into()),
            )
            .await
            .map_err(|e| {
                tracing::error!("Error updating server mapping after authentication: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let mut auth_to_store = login_authorization.clone();
        auth_to_store.token = Some(successful.auth_response.access_token.clone());

        state
            .user_authorization
            .store_authorization_session(
                &user.id,
                &successful.server,
                &auth_to_store,
                successful.auth_response.access_token.clone(),
                successful.auth_response.user.id.clone(),
                None,
            )
            .await
            .map_err(|e| {
                tracing::error!("Error storing authorization session: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
    }

    Ok(())
}

async fn decorate_auth_response(
    state: &AppState,
    user: &crate::user_authorization_service::User,
    login_username: &str,
    successful_auth: &SuccessfulServerAuth,
) -> AuthenticateResponse {
    let mut auth_response = successful_auth.auth_response.clone();
    let server_id = state.config.read().await.server_id.clone();
    auth_response.server_id = server_id.clone();
    auth_response.user.server_id = server_id.clone();
    auth_response.session_info.server_id = server_id;
    auth_response.session_info.user_id = user.id.clone();
    auth_response.user.name = login_username.to_string();
    auth_response.session_info.user_name = login_username.to_string();
    auth_response.user.policy.is_administrator = false;
    auth_response.user.policy.sync_play_access = SyncPlayUserAccessType::CreateAndJoinGroups;
    auth_response.access_token = user.virtual_key.clone();
    auth_response.user.id = user.id.clone();
    auth_response
}

/// Authenticates a user on a specific server
async fn authenticate_on_server(
    state: AppState,
    authorization: Authorization,
    payload: AuthenticateRequest,
    server: crate::server_storage::Server,
    server_mapping: Option<crate::user_authorization_service::ServerMapping>,
) -> Result<SuccessfulServerAuth, AuthError> {
    let auth_url = join_server_url(&server.url, "/Users/AuthenticateByName");

    info!(
        "Authenticating user '{}' at server '{}' ({})",
        payload.username, server.name, auth_url
    );

    // Get user mapping for this server
    let config = state.config.read().await;
    let admin_password = &config.password;

    let given_password = payload.password.clone();

    let (final_username, final_password) = if let Some(mapping) = &server_mapping {
        (
            mapping.mapped_username.clone(),
            state.user_authorization.decrypt_server_mapping_password(
                mapping,
                &given_password.clone().into(),
                &admin_password.into(),
                Some(&given_password),
                Some(admin_password),
            ),
        )
    } else {
        (payload.username.clone(), payload.password.clone())
    };

    // Create authentication payload
    let auth_payload = AuthenticateRequest {
        username: final_username.clone(),
        password: final_password.clone(),
    };

    // Make authentication request
    let response = state
        .reqwest_client
        .post(auth_url.as_str())
        .header("Authorization", authorization.to_header_value())
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .json(&auth_payload)
        .send()
        .await
        .map_err(|e| {
            tracing::error!(
                "Failed to send authentication request to {}: {}",
                server.name,
                e
            );
            AuthError::NetworkError(e.to_string())
        })?;

    // Check response status
    if !response.status().is_success() {
        tracing::warn!(
            "Authentication failed for server '{}' with status: {}",
            server.name,
            response.status()
        );
        return Err(AuthError::InvalidCredentials);
    }

    // Parse response
    let response_text = response.text().await.map_err(|e| {
        tracing::error!(
            "Failed to read authentication response from {}: {}",
            server.name,
            e
        );
        AuthError::NetworkError(e.to_string())
    })?;

    tracing::trace!(
        "Received authentication response from {} ({} bytes)",
        server.name,
        response_text.len()
    );

    let auth_response =
        serde_json::from_str::<AuthenticateResponse>(&response_text).map_err(|e| {
            tracing::error!(
                "Failed to parse authentication response from {}: {}. Response body: {}",
                server.name,
                e,
                response_text
            );
            AuthError::ParseError(e.to_string())
        })?;

    info!(
        "Successfully authenticated user '{}' on server '{}'",
        payload.username, server.name
    );
    Ok(SuccessfulServerAuth {
        server,
        auth_response,
        final_username,
        final_password,
    })
}

/// Creates (or verifies) the submitted credentials as a real account on
/// `server` via the same admin-credential path used for federated user sync,
/// then retries the plain-credential login once. Never recreates a user an
/// admin has explicitly kicked-and-blocked from that server (see
/// `user_authorization_service::block_user_on_server`).
async fn attempt_auto_create_then_authenticate(
    state: AppState,
    authorization: Authorization,
    payload: AuthenticateRequest,
    server: crate::server_storage::Server,
) -> Result<SuccessfulServerAuth, AuthError> {
    if !state.auto_create_users_on_login().await {
        return Err(AuthError::InvalidCredentials);
    }

    match state
        .user_authorization
        .is_user_blocked_on_server(server.id, &payload.username)
        .await
    {
        Ok(true) => {
            info!(
                "Not auto-creating user '{}' on server '{}': blocked by an admin",
                payload.username, server.name
            );
            return Err(AuthError::InvalidCredentials);
        }
        Ok(false) => {}
        Err(e) => {
            error!(
                "Failed to check user block status on server '{}': {}",
                server.name, e
            );
            return Err(AuthError::InvalidCredentials);
        }
    }

    let user = match state
        .user_authorization
        .get_or_create_user(&payload.username, &payload.password)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            error!(
                "Failed to resolve local user for auto-create on server '{}': {}",
                server.name, e
            );
            return Err(AuthError::InvalidCredentials);
        }
    };

    let sync_result = state
        .federated_users
        .sync_user_to_server(&server, &payload.username, &payload.password, &user.id)
        .await;

    match sync_result.status {
        crate::federated_users::SyncStatus::Created
        | crate::federated_users::SyncStatus::AlreadyExists => {
            info!(
                "Auto-created/synced user '{}' on server '{}' during login; retrying authentication",
                payload.username, server.name
            );
            authenticate_on_server(state, authorization, payload, server, None).await
        }
        other_status => {
            debug!(
                "Auto-create on server '{}' for user '{}' did not yield a usable account (status: {:?})",
                server.name, payload.username, other_status
            );
            Err(AuthError::InvalidCredentials)
        }
    }
}

/// Extracts authorization header
fn extract_auth_header(headers: &HeaderMap) -> Result<Authorization, AuthError> {
    if let Some(raw_auth) = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        if let Ok(auth) = Authorization::parse(raw_auth) {
            debug!("Extracted 'Authorization' header: {}", auth);
            Ok(auth)
        } else {
            warn!("Invalid 'Authorization' header format");
            Err(AuthError::ParseError(
                "Invalid 'Authorization' header format".to_string(),
            ))
        }
    } else if let Some(raw_auth) = headers
        .get("x-emby-authorization")
        .and_then(|value| value.to_str().ok())
    {
        if let Ok(auth) = Authorization::parse_with_legacy(raw_auth, true) {
            debug!("Extracted 'X-Emby-Authorization' header: {}", auth);
            Ok(auth)
        } else {
            warn!("Invalid 'X-Emby-Authorization' header format");
            Err(AuthError::ParseError(
                "Invalid 'X-Emby-Authorization' header format".to_string(),
            ))
        }
    } else {
        error!("No 'Authorization' header found in login request");

        Err(AuthError::ParseError(
            "No 'Authorization' header found in login request!".to_string(),
        ))
    }
}

/// Custom error type for authentication operations
#[derive(Debug)]
#[allow(dead_code)]
enum AuthError {
    NetworkError(String),
    InvalidCredentials,
    ParseError(String),
    InternalError,
}

#[derive(Debug, Clone)]
struct SuccessfulServerAuth {
    server: crate::server_storage::Server,
    auth_response: AuthenticateResponse,
    final_username: String,
    final_password: crate::encryption::Password,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{AppConfig, MediaStreamingMode, MIGRATOR},
        console_admin_service::ConsoleAdminService,
        media_storage_service::MediaStorageService,
        models::{SessionInfo, SyncPlayUserAccessType, User, UserPolicy},
        server_storage::ServerStorageService,
        session_storage::SessionStorage,
        user_authorization_service::UserAuthorizationService,
        DataContext, ProxyProcessors,
    };
    use hyper::http::HeaderValue;
    use sqlx::SqlitePool;
    use std::{collections::HashMap, sync::Arc};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    async fn create_test_app_state() -> AppState {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();

        let data_context = DataContext {
            user_authorization: Arc::new(UserAuthorizationService::new(pool.clone())),
            server_storage: Arc::new(ServerStorageService::new(pool.clone())),
            media_storage: Arc::new(MediaStorageService::new(pool.clone())),
            merged_library_service: Arc::new(
                crate::merged_library_service::MergedLibraryService::new(pool.clone()),
            ),
            play_sessions: Arc::new(SessionStorage::new()),
            config: Arc::new(tokio::sync::RwLock::new(AppConfig::default())),
        };

        let processors = ProxyProcessors::new(data_context.clone());

        AppState::new(
            reqwest::Client::new(),
            reqwest::Client::new(),
            data_context,
            processors,
            crate::handlers::quick_connect::QuickConnectStorage::new(),
            Arc::new(ConsoleAdminService::new(pool)),
        )
    }

    fn login_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static(
                "MediaBrowser Client=\"Jellyfin Web\", Device=\"Firefox\", DeviceId=\"test-device\", Version=\"10.10.7\"",
            ),
        );
        headers
    }

    fn mock_authenticate_response(username: &str) -> AuthenticateResponse {
        AuthenticateResponse {
            user: User {
                name: username.to_string(),
                server_id: "upstream-server".to_string(),
                id: "upstream-user-id".to_string(),
                policy: UserPolicy {
                    is_administrator: false,
                    sync_play_access: SyncPlayUserAccessType::None,
                    extra: HashMap::new(),
                },
                extra: HashMap::new(),
            },
            session_info: SessionInfo {
                user_id: "upstream-user-id".to_string(),
                user_name: username.to_string(),
                server_id: "upstream-server".to_string(),
                extra: HashMap::new(),
            },
            access_token: "upstream-token".to_string(),
            server_id: "upstream-server".to_string(),
        }
    }

    async fn mount_authenticate_success(server: &MockServer, username: &str) {
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(mock_authenticate_response(username)),
            )
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn existing_user_picks_up_mapping_to_newly_reachable_unmapped_server() {
        let state = create_test_app_state().await;

        let mock_a = MockServer::start().await;
        let mock_b = MockServer::start().await;
        mount_authenticate_success(&mock_a, "Exellent").await;
        mount_authenticate_success(&mock_b, "Exellent").await;

        let server_a_id = state
            .server_storage
            .add_server("Server A", &mock_a.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        let server_a = state
            .server_storage
            .get_server_by_id(server_a_id)
            .await
            .unwrap()
            .unwrap();
        state
            .server_storage
            .add_server("Server B", &mock_b.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();

        // Pre-seed: user already exists locally with exactly one mapping, to
        // server A -- simulates their very first login only having matched
        // one of the two configured servers.
        let user = state
            .user_authorization
            .get_or_create_user("Exellent", &"correct-password".into())
            .await
            .unwrap();
        let original_mapping_id = state
            .user_authorization
            .add_server_mapping(
                &user.id,
                &server_a,
                "Exellent",
                &"correct-password".into(),
                None,
            )
            .await
            .unwrap();

        // Log in again -- server B is now reachable/valid with the same
        // credentials (e.g. the account was created there since, or it was
        // just added to federation).
        let response = handle_authenticate_by_name(
            State(state.clone()),
            login_headers(),
            Json(AuthenticateRequest {
                username: "Exellent".to_string(),
                password: "correct-password".into(),
            }),
        )
        .await
        .expect("login should succeed");
        assert_eq!(response.0.user.id, user.id);

        let mappings = state
            .user_authorization
            .list_server_mappings(&user.id)
            .await
            .unwrap();
        assert_eq!(
            mappings.len(),
            2,
            "expected mappings to both servers, got {:#?}",
            mappings
        );

        let mapping_a = mappings
            .iter()
            .find(|m| m.server_id == server_a.id)
            .expect("server A mapping should still exist");
        assert_eq!(
            mapping_a.id, original_mapping_id,
            "server A's existing mapping should be reused, not recreated"
        );

        assert!(
            mappings.iter().any(|m| m.server_id != server_a.id),
            "server B should have picked up a new mapping"
        );
    }

    #[tokio::test]
    async fn new_user_still_probes_all_servers() {
        let state = create_test_app_state().await;

        let mock_a = MockServer::start().await;
        let mock_b = MockServer::start().await;
        mount_authenticate_success(&mock_a, "Fresh").await;
        mount_authenticate_success(&mock_b, "Fresh").await;

        state
            .server_storage
            .add_server("Server A", &mock_a.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        state
            .server_storage
            .add_server("Server B", &mock_b.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();

        let response = handle_authenticate_by_name(
            State(state.clone()),
            login_headers(),
            Json(AuthenticateRequest {
                username: "Fresh".to_string(),
                password: "some-password".into(),
            }),
        )
        .await
        .expect("login should succeed");

        let mappings = state
            .user_authorization
            .list_server_mappings(&response.0.user.id)
            .await
            .unwrap();
        assert_eq!(
            mappings.len(),
            2,
            "brand new user should map to both servers"
        );
    }

    async fn add_server_admin_creds(state: &AppState, server_id: crate::server_id::ServerId) {
        let master_password: crate::encryption::HashedPassword =
            state.config.read().await.password.clone().into();
        let encrypted =
            crate::encryption::encrypt_password(&"admin-secret".into(), &master_password).unwrap();
        state
            .server_storage
            .add_server_admin(server_id, "admin", &encrypted)
            .await
            .unwrap();
    }

    /// Sets up two servers: `server_a` is already mapped for `username` with
    /// working credentials (so a login proves "verified access" this
    /// request); `server_b` has admin creds configured but no mapping yet,
    /// and no account for `username` -- the auto-create candidate.
    async fn setup_verified_user_plus_auto_create_candidate(
        state: &AppState,
        username: &str,
        password: &str,
    ) -> (MockServer, MockServer) {
        let mock_a = MockServer::start().await;
        let mock_b = MockServer::start().await;
        mount_authenticate_success(&mock_a, username).await;

        let server_a_id = state
            .server_storage
            .add_server("Server A", &mock_a.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        let server_a = state
            .server_storage
            .get_server_by_id(server_a_id)
            .await
            .unwrap()
            .unwrap();
        let server_b_id = state
            .server_storage
            .add_server("Server B", &mock_b.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        add_server_admin_creds(state, server_b_id).await;

        let user = state
            .user_authorization
            .get_or_create_user(username, &password.into())
            .await
            .unwrap();
        state
            .user_authorization
            .add_server_mapping(&user.id, &server_a, username, &password.into(), None)
            .await
            .unwrap();

        (mock_a, mock_b)
    }

    #[tokio::test]
    async fn auto_create_fires_only_for_a_user_already_verified_on_another_server_this_login() {
        use wiremock::matchers::body_partial_json;

        let state = create_test_app_state().await;
        assert!(
            state.auto_create_users_on_login().await,
            "auto-create should default to on"
        );

        let (_mock_a, mock_b) =
            setup_verified_user_plus_auto_create_candidate(&state, "verifieduser", "correct-pw")
                .await;

        // Admin login on server B for the sync/federation path.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(serde_json::json!({"Username": "admin"})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(mock_authenticate_response("admin")),
            )
            .mount(&mock_b)
            .await;

        // The user's very first plain-credential probe on B fails (no account there yet).
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(
                serde_json::json!({"Username": "verifieduser"}),
            ))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&mock_b)
            .await;

        // After auto-create, the retry succeeds.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(
                serde_json::json!({"Username": "verifieduser"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mock_authenticate_response("verifieduser")),
            )
            .with_priority(2)
            .mount(&mock_b)
            .await;

        // No account exists remotely yet on B.
        Mock::given(method("GET"))
            .and(path("/Users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&mock_b)
            .await;

        // Account creation call.
        Mock::given(method("POST"))
            .and(path("/Users/New"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Id": "remote-new-user-id",
                "Name": "verifieduser",
                "ServerId": "upstream-server",
                "Policy": {"IsAdministrator": false, "SyncPlayAccess": "None"},
            })))
            .mount(&mock_b)
            .await;

        let response = handle_authenticate_by_name(
            State(state.clone()),
            login_headers(),
            Json(AuthenticateRequest {
                username: "verifieduser".to_string(),
                password: "correct-pw".into(),
            }),
        )
        .await
        .expect("login should succeed after auto-create");

        let mappings = state
            .user_authorization
            .list_server_mappings(&response.0.user.id)
            .await
            .unwrap();
        assert_eq!(
            mappings.len(),
            2,
            "should now be mapped to both the already-verified server and the auto-created one"
        );
    }

    #[tokio::test]
    async fn first_ever_login_with_real_accounts_on_some_servers_auto_creates_the_rest() {
        // The scenario that matters most: this user has NEVER logged into
        // jellyswarm before (no local user, no mappings at all), but already
        // has real, valid Jellyfin accounts on 2 of 3 configured servers.
        // Because two of those three succeed via genuine credential matches
        // in this very request, that's proof enough to auto-create the
        // account on the third (which has admin creds configured but no
        // matching account yet) -- without ever having needed a pre-existing
        // mapping to establish trust.
        use wiremock::matchers::body_partial_json;

        let state = create_test_app_state().await;

        let mock_a = MockServer::start().await;
        let mock_b = MockServer::start().await;
        let mock_c = MockServer::start().await;
        mount_authenticate_success(&mock_a, "multiuser").await;
        mount_authenticate_success(&mock_b, "multiuser").await;

        state
            .server_storage
            .add_server("Server A", &mock_a.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        state
            .server_storage
            .add_server("Server B", &mock_b.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        let server_c_id = state
            .server_storage
            .add_server("Server C", &mock_c.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        add_server_admin_creds(&state, server_c_id).await;

        // Admin login on C for the sync/federation path.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(serde_json::json!({"Username": "admin"})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(mock_authenticate_response("admin")),
            )
            .mount(&mock_c)
            .await;

        // The user's first plain-credential probe on C fails (no account there yet).
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(
                serde_json::json!({"Username": "multiuser"}),
            ))
            .respond_with(ResponseTemplate::new(401))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&mock_c)
            .await;

        // After auto-create, the retry succeeds.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(
                serde_json::json!({"Username": "multiuser"}),
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(mock_authenticate_response("multiuser")),
            )
            .with_priority(2)
            .mount(&mock_c)
            .await;

        Mock::given(method("GET"))
            .and(path("/Users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(Vec::<serde_json::Value>::new()))
            .mount(&mock_c)
            .await;

        Mock::given(method("POST"))
            .and(path("/Users/New"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Id": "remote-new-user-id",
                "Name": "multiuser",
                "ServerId": "upstream-server",
                "Policy": {"IsAdministrator": false, "SyncPlayAccess": "None"},
            })))
            .mount(&mock_c)
            .await;

        let response = handle_authenticate_by_name(
            State(state.clone()),
            login_headers(),
            Json(AuthenticateRequest {
                username: "multiuser".to_string(),
                password: "correct-pw".into(),
            }),
        )
        .await
        .expect("login should succeed via A and B, and auto-create on C");

        let mappings = state
            .user_authorization
            .list_server_mappings(&response.0.user.id)
            .await
            .unwrap();
        assert_eq!(
            mappings.len(),
            3,
            "should be mapped to A and B (real accounts) plus C (auto-created)"
        );
    }

    #[tokio::test]
    async fn brand_new_username_is_never_auto_created_anywhere() {
        // The critical guard: a completely unknown username/password combo
        // must NOT get an account auto-provisioned on a server just because
        // that server has admin credentials configured and the toggle is
        // on. Auto-create may only ever kick in for someone who has already
        // proven, in this same request, that they hold valid credentials on
        // at least one other server -- otherwise the login form becomes
        // open self-registration onto every federated server.
        use wiremock::matchers::body_partial_json;

        let state = create_test_app_state().await;
        assert!(state.auto_create_users_on_login().await);

        let mock = MockServer::start().await;
        let server_id = state
            .server_storage
            .add_server("Server A", &mock.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();
        add_server_admin_creds(&state, server_id).await;

        // Only the failing plain-credential probe should ever be hit -- if
        // auto-create incorrectly ran anyway, there'd be no mock for the
        // admin auth/list/create calls it would try to make, and this test
        // would fail with a connection/parse error instead of a clean 401,
        // making the bug visible either way.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(
                serde_json::json!({"Username": "totally-new-nobody"}),
            ))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;

        let result = handle_authenticate_by_name(
            State(state.clone()),
            login_headers(),
            Json(AuthenticateRequest {
                username: "totally-new-nobody".to_string(),
                password: "whatever-i-just-typed".into(),
            }),
        )
        .await;

        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);

        let user = state
            .user_authorization
            .get_user_by_username("totally-new-nobody")
            .await
            .unwrap();
        assert!(
            user.is_none(),
            "a failed login for an unknown user must not create a local user record either"
        );
    }

    #[tokio::test]
    async fn blocked_user_is_not_auto_created_even_when_verified_elsewhere() {
        use wiremock::matchers::body_partial_json;

        let state = create_test_app_state().await;

        let (_mock_a, mock_b) =
            setup_verified_user_plus_auto_create_candidate(&state, "kicked", "correct-pw").await;

        let server_b_id = state
            .server_storage
            .list_servers()
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.name == "Server B")
            .unwrap()
            .id;

        state
            .user_authorization
            .block_user_on_server(server_b_id, "kicked", None)
            .await
            .unwrap();

        // Only the failing plain-credential probe on B should ever be hit --
        // if auto-create incorrectly ran despite the block, there'd be no
        // mock for the admin auth/list/create calls it would try to make.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(serde_json::json!({"Username": "kicked"})))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_b)
            .await;

        let response = handle_authenticate_by_name(
            State(state.clone()),
            login_headers(),
            Json(AuthenticateRequest {
                username: "kicked".to_string(),
                password: "correct-pw".into(),
            }),
        )
        .await
        .expect("login should still succeed via the already-mapped, non-blocked server A");

        let mappings = state
            .user_authorization
            .list_server_mappings(&response.0.user.id)
            .await
            .unwrap();
        assert_eq!(
            mappings.len(),
            1,
            "blocked user must not get a mapping created on the blocked server"
        );
        assert_ne!(
            mappings[0].server_id, server_b_id,
            "the surviving mapping must be server A, not the blocked server B"
        );
    }

    #[tokio::test]
    async fn repeated_failed_logins_from_same_ip_get_rate_limited() {
        let state = create_test_app_state().await;

        let mock = MockServer::start().await;
        state
            .server_storage
            .add_server("Server A", &mock.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();

        // AppConfig::default() sets max_attempts=5; this mock must be hit
        // exactly that many times -- if the 6th (blocked) attempt still
        // reached the network, `mock.verify()` below would fail.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .respond_with(ResponseTemplate::new(401))
            .expect(5)
            .mount(&mock)
            .await;

        let mut headers = login_headers();
        headers.insert(
            "x-forwarded-for",
            hyper::http::HeaderValue::from_static("9.9.9.9"),
        );

        for _ in 0..5 {
            let result = handle_authenticate_by_name(
                State(state.clone()),
                headers.clone(),
                Json(AuthenticateRequest {
                    username: "attacker".to_string(),
                    password: "wrong".into(),
                }),
            )
            .await;
            assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
        }

        let result = handle_authenticate_by_name(
            State(state.clone()),
            headers.clone(),
            Json(AuthenticateRequest {
                username: "attacker".to_string(),
                password: "wrong-again".into(),
            }),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            StatusCode::TOO_MANY_REQUESTS,
            "6th attempt should be rate-limited"
        );

        mock.verify().await;
    }

    #[tokio::test]
    async fn different_client_ips_are_not_rate_limited_together() {
        let state = create_test_app_state().await;

        let mock = MockServer::start().await;
        state
            .server_storage
            .add_server("Server A", &mock.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();

        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;

        let mut headers_a = login_headers();
        headers_a.insert(
            "x-forwarded-for",
            hyper::http::HeaderValue::from_static("1.1.1.1"),
        );
        let mut headers_b = login_headers();
        headers_b.insert(
            "x-forwarded-for",
            hyper::http::HeaderValue::from_static("2.2.2.2"),
        );

        for _ in 0..5 {
            handle_authenticate_by_name(
                State(state.clone()),
                headers_a.clone(),
                Json(AuthenticateRequest {
                    username: "attacker".to_string(),
                    password: "wrong".into(),
                }),
            )
            .await
            .unwrap_err();
        }

        // IP A is now blocked; IP B, having made no attempts, must still get
        // a normal (non-rate-limited) auth failure.
        let result_b = handle_authenticate_by_name(
            State(state.clone()),
            headers_b.clone(),
            Json(AuthenticateRequest {
                username: "attacker".to_string(),
                password: "wrong".into(),
            }),
        )
        .await;
        assert_eq!(result_b.unwrap_err(), StatusCode::UNAUTHORIZED);

        let result_a = handle_authenticate_by_name(
            State(state.clone()),
            headers_a.clone(),
            Json(AuthenticateRequest {
                username: "attacker".to_string(),
                password: "wrong".into(),
            }),
        )
        .await;
        assert_eq!(result_a.unwrap_err(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn successful_login_resets_the_rate_limit_counter() {
        use wiremock::matchers::body_partial_json;

        let state = create_test_app_state().await;
        let mock = MockServer::start().await;
        state
            .server_storage
            .add_server("Server A", &mock.uri(), 100, MediaStreamingMode::Redirect)
            .await
            .unwrap();

        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(serde_json::json!({"Pw": "wrong"})))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .and(body_partial_json(serde_json::json!({"Pw": "correct"})))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(mock_authenticate_response("resetuser")),
            )
            .mount(&mock)
            .await;

        let mut headers = login_headers();
        headers.insert(
            "x-forwarded-for",
            hyper::http::HeaderValue::from_static("8.8.8.8"),
        );

        for _ in 0..4 {
            let result = handle_authenticate_by_name(
                State(state.clone()),
                headers.clone(),
                Json(AuthenticateRequest {
                    username: "resetuser".to_string(),
                    password: "wrong".into(),
                }),
            )
            .await;
            assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
        }

        let _ = handle_authenticate_by_name(
            State(state.clone()),
            headers.clone(),
            Json(AuthenticateRequest {
                username: "resetuser".to_string(),
                password: "correct".into(),
            }),
        )
        .await
        .expect("login should succeed");

        // If the successful login hadn't reset the counter, these 4 more
        // failures (8 total) would have tripped the 5-attempt limit well
        // before this loop finishes.
        for _ in 0..4 {
            let result = handle_authenticate_by_name(
                State(state.clone()),
                headers.clone(),
                Json(AuthenticateRequest {
                    username: "resetuser".to_string(),
                    password: "wrong".into(),
                }),
            )
            .await;
            assert_eq!(
                result.unwrap_err(),
                StatusCode::UNAUTHORIZED,
                "should still be a plain auth failure, not rate-limited, since the counter reset after the success"
            );
        }
    }
}
