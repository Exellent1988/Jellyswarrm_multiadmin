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

    let mut auth_tasks = Vec::with_capacity(servers.len());

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
                        auth_tasks.push(tokio::spawn(async move {
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
    if !servers.is_empty() {
        info!(
            "Probing {} unmapped server(s) for user '{}'",
            servers.len(),
            payload.username
        );
    }
    let mut leftover_tasks: Vec<_> = servers
        .into_iter()
        .map(|server| {
            let state = state.clone();
            let authentication = authentication.clone();
            let payload = payload.clone();
            info!(
                "No server mapping found for user '{}' on server '{}'",
                payload.username, server.name
            );

            tokio::spawn(async move {
                authenticate_on_server(state, authentication, payload, server, None).await
            })
        })
        .collect();

    auth_tasks.append(&mut leftover_tasks);

    // Wait for all authentication attempts to complete
    let mut successful_auths: Vec<SuccessfulServerAuth> = Vec::new();
    let total_servers = auth_tasks.len();

    for task in auth_tasks {
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

    if successful_auths.is_empty() {
        tracing::warn!(
            "All authentication attempts failed for user: {}",
            payload.username
        );
        Err(StatusCode::UNAUTHORIZED)
    } else {
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
}
