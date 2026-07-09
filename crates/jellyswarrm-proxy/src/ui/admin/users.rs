use askama::Template;
use axum::{
    extract::{Path, State},
    http::{header::HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    Form,
};
use jellyfin_api::JellyfinClient;
use serde::Deserialize;
use std::collections::HashMap;
use tracing::{error, info};

use crate::{
    encryption::Password,
    federated_users::ServerSyncResult,
    server_id::ServerId,
    server_storage::Server,
    ui::admin::ownership::{may_act_on, CurrentAdmin},
    user_authorization_service::{ServerMapping, User},
    AppState,
};

#[derive(Template)]
#[template(path = "admin/users.html")]
pub struct UsersPageTemplate {
    pub ui_route: String,
}

pub struct UserWithMappings {
    pub user: User,
    pub mappings: Vec<(ServerMapping, Server, i64)>, // per mapping session count
    pub available_servers: Vec<Server>,              // servers not yet mapped
    pub total_sessions: i64,
}

#[derive(Template)]
#[template(path = "admin/user_list.html")]
pub struct UserListTemplate {
    pub users: Vec<UserWithMappings>,
    pub ui_route: String,
    pub sync_report: Option<Vec<ServerSyncResult>>,
}

#[derive(Template)]
#[template(path = "admin/user_item.html")]
pub struct UserItemTemplate {
    pub uwm: UserWithMappings,
    pub ui_route: String,
}

#[derive(Deserialize)]
pub struct AddUserForm {
    pub username: String,
    pub password: Password,
    #[serde(default)]
    pub enable_federation: bool,
}

#[derive(Deserialize)]
pub struct AddMappingForm {
    pub user_id: String,
    pub server_id: ServerId,
    pub mapped_username: String,
    pub mapped_password: Password,
}

pub async fn create_user_with_mappings(
    state: &AppState,
    user: User,
    servers: &[Server],
) -> UserWithMappings {
    // Session counts keyed by canonical server URL for template display.
    let mut session_counts: HashMap<String, i64> = HashMap::new();
    if let Ok(rows) = state
        .user_authorization
        .session_counts_by_server(&user.id)
        .await
    {
        for (url, cnt) in rows {
            session_counts.insert(url, cnt);
        }
    }

    let mappings_fetch = state
        .user_authorization
        .list_server_mappings(&user.id)
        .await;
    let mut mappings_vec: Vec<(ServerMapping, Server, i64)> = Vec::new();
    let mut mapped_server_ids: Vec<ServerId> = Vec::new();
    match mappings_fetch {
        Ok(mappings) => {
            for mapping in mappings {
                if let Some(server) = servers.iter().find(|srv| srv.id == mapping.server_id) {
                    let count = session_counts
                        .get(server.url.as_str())
                        .cloned()
                        .unwrap_or(0);
                    mappings_vec.push((mapping, server.clone(), count));
                    mapped_server_ids.push(server.id);
                }
            }
        }
        Err(e) => {
            error!("Failed to list mappings: {}", e);
        }
    }
    let available_servers: Vec<Server> = servers
        .iter()
        .filter(|srv| !mapped_server_ids.contains(&srv.id))
        .cloned()
        .collect();
    let user_total_sessions: i64 = mappings_vec.iter().map(|(_, _, c)| *c).sum();
    UserWithMappings {
        user,
        mappings: mappings_vec,
        available_servers,
        total_sessions: user_total_sessions,
    }
}

/// Main users page
pub async fn users_page(State(state): State<AppState>) -> impl IntoResponse {
    let template = UsersPageTemplate {
        ui_route: state.get_ui_route().await,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Failed to render users template: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

pub async fn get_user_item(state: &AppState, user_id: &str) -> impl IntoResponse {
    let servers = match state.server_storage.list_servers().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to list servers: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    let user = match state.user_authorization.get_user_by_id(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Html("<div class=\"alert alert-error\">User not found</div>"),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch user by id {}: {}", user_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    // Build UserWithMappings and render single item template
    let uwm = create_user_with_mappings(state, user, &servers).await;
    let template = UserItemTemplate {
        uwm,
        ui_route: state.get_ui_route().await,
    };
    match template.render() {
        Ok(html) => Html(html).into_response(),
        Err(e) => {
            error!("Render error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
        }
    }
}

fn with_popup(mut response: Response, message: String) -> Response {
    let payload = serde_json::json!({
        "admin-popup": {
            "message": message,
        }
    })
    .to_string();

    match HeaderValue::from_str(&payload) {
        Ok(value) => {
            response.headers_mut().insert("HX-Trigger", value);
        }
        Err(e) => {
            error!("Failed to set HX-Trigger popup header: {}", e);
        }
    }

    response
}

async fn user_item_with_popup(state: &AppState, user_id: &str, message: String) -> Response {
    let response = get_user_item(state, user_id).await.into_response();
    with_popup(response, message)
}

async fn get_user_list_impl(
    state: &AppState,
    report: Option<Vec<ServerSyncResult>>,
) -> impl IntoResponse {
    // Fetch servers once for mapping lookup
    let servers = match state.server_storage.list_servers().await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to list servers: {}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    match state.user_authorization.list_users().await {
        Ok(users) => {
            let mut result = Vec::new();
            for user in users {
                result.push(create_user_with_mappings(state, user, &servers).await);
            }

            let template = UserListTemplate {
                users: result,
                ui_route: state.get_ui_route().await,
                sync_report: report,
            };
            match template.render() {
                Ok(html) => Html(html).into_response(),
                Err(e) => {
                    error!("Render error: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Template error").into_response()
                }
            }
        }
        Err(e) => {
            error!("Failed to list users: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response()
        }
    }
}

/// List users with mappings
pub async fn get_user_list(State(state): State<AppState>) -> impl IntoResponse {
    get_user_list_impl(&state, None).await
}

/// Add user
pub async fn add_user(State(state): State<AppState>, Form(form): Form<AddUserForm>) -> Response {
    if form.username.trim().is_empty() || form.password.as_str().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Html("<div class=\"alert alert-error\">Username and password required</div>"),
        )
            .into_response();
    }
    match state
        .user_authorization
        .create_user(&form.username, &form.password)
        .await
    {
        Ok(user) => {
            info!("Created user {}", form.username);

            // Sync to all servers if enabled
            let report = if form.enable_federation {
                Some(
                    state
                        .federated_users
                        .sync_user_to_all_servers(&form.username, &form.password, &user.id)
                        .await,
                )
            } else {
                None
            };

            get_user_list_impl(&state, report).await.into_response()
        }
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => (
            StatusCode::CONFLICT,
            Html("<div class=\"alert alert-error\">User already exists</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to create user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to create user</div>"),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct DeleteUserForm {
    #[serde(default)]
    pub delete_federated: bool,
}

/// Delete user
pub async fn delete_user(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    Form(form): Form<DeleteUserForm>,
) -> Response {
    // 1. Get user to get username for remote deletion
    let username = match state.user_authorization.get_user_by_id(&user_id).await {
        Ok(Some(u)) => u.original_username,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Html("<div class=\"alert alert-error\">User not found</div>"),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to fetch user by id {}: {}", user_id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Database error</div>"),
            )
                .into_response();
        }
    };

    // 2. Delete from federated servers if requested
    let report = if form.delete_federated {
        Some(
            state
                .federated_users
                .delete_user_from_all_servers(&username)
                .await,
        )
    } else {
        None
    };

    // 3. Delete locally
    match state.user_authorization.delete_user(&user_id).await {
        Ok(true) => get_user_list_impl(&state, report).await.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">User not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Delete user error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to delete user</div>"),
            )
                .into_response()
        }
    }
}

/// Add mapping
pub async fn add_mapping(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Form(form): Form<AddMappingForm>,
) -> Response {
    if form.mapped_username.trim().is_empty() || form.mapped_password.as_str().is_empty() {
        return user_item_with_popup(
            &state,
            &form.user_id,
            "Mapping username and password are required.".to_string(),
        )
        .await;
    }

    info!(
        "Validating mapping credentials for local user '{}' on '{}' as mapped user '{}'.",
        form.user_id, form.server_id, form.mapped_username
    );

    let all_servers = match state.server_storage.list_servers().await {
        Ok(servers) => servers,
        Err(e) => {
            error!("Failed to list servers while adding mapping: {}", e);
            return user_item_with_popup(
                &state,
                &form.user_id,
                "Could not load servers while validating this mapping.".to_string(),
            )
            .await;
        }
    };

    let server = match all_servers.into_iter().find(|s| s.id == form.server_id) {
        Some(server) => server,
        None => {
            return user_item_with_popup(
                &state,
                &form.user_id,
                "Selected server was not found. Please refresh and try again.".to_string(),
            )
            .await;
        }
    };

    if !may_act_on(&admin, &server) {
        return user_item_with_popup(
            &state,
            &form.user_id,
            "You don't have permission to add mappings for that server.".to_string(),
        )
        .await;
    }

    let client = match JellyfinClient::new(server.url.as_str(), crate::config::CLIENT_INFO.clone())
    {
        Ok(client) => client,
        Err(e) => {
            error!(
                "Failed to create jellyfin client for {}: {}",
                server.name, e
            );
            return user_item_with_popup(
                &state,
                &form.user_id,
                format!("Failed to connect to selected server '{}'.", server.name),
            )
            .await;
        }
    };

    match client
        .authenticate_by_name(&form.mapped_username, form.mapped_password.as_str())
        .await
    {
        Ok(_) => {
            info!(
                "Mapping credentials validated for local user '{}' on server '{}' as mapped user '{}'.",
                form.user_id, server.name, form.mapped_username
            );
        }
        Err(jellyfin_api::error::Error::AuthenticationFailed(_)) => {
            info!(
                "Mapping validation failed for local user '{}' on server '{}' as mapped user '{}': invalid credentials.",
                form.user_id, server.name, form.mapped_username
            );
            return user_item_with_popup(
                &state,
                &form.user_id,
                format!(
                    "Validation failed on server '{}': username or password is incorrect.",
                    server.name
                ),
            )
            .await;
        }
        Err(e) => {
            error!(
                "Failed to validate mapping credentials for user '{}' on server '{}': {}",
                form.user_id, server.name, e
            );
            return user_item_with_popup(
                &state,
                &form.user_id,
                format!(
                    "Could not validate credentials on server '{}': {}",
                    server.name, e
                ),
            )
            .await;
        }
    }

    let admin_password = {
        let config = state.config.read().await;
        (&config.password).into()
    };

    match state
        .user_authorization
        .add_server_mapping(
            &form.user_id,
            &server,
            &form.mapped_username,
            &form.mapped_password,
            Some(&admin_password),
        )
        .await
    {
        Ok(mapping_id) => {
            info!(
                "Saved mapping {} for local user '{}' to server '{}' as mapped user '{}'.",
                mapping_id, form.user_id, server.name, form.mapped_username
            );
            get_user_item(&state, &form.user_id).await.into_response()
        }
        Err(e) => {
            error!(
                "Failed to save mapping for local user '{}' to server '{}': {}",
                form.user_id, server.name, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to add mapping</div>"),
            )
                .into_response()
        }
    }
}

/// Delete mapping
pub async fn delete_mapping(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Path((user_id, mapping_id)): Path<(String, i64)>,
) -> Response {
    // Resolve which server this mapping belongs to first, so we can apply
    // the same ownership rule as adding a mapping -- only the owning admin
    // (or a superadmin) may remove it.
    match state
        .user_authorization
        .get_server_mapping_by_id(mapping_id)
        .await
    {
        Ok(Some(mapping)) => {
            let server = match state
                .server_storage
                .get_server_by_id(mapping.server_id)
                .await
            {
                Ok(Some(server)) => server,
                Ok(None) => {
                    return (
                        StatusCode::NOT_FOUND,
                        Html("<div class=\"alert alert-error\">Server not found</div>"),
                    )
                        .into_response();
                }
                Err(e) => {
                    error!("Failed to load server for mapping {}: {}", mapping_id, e);
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
                }
            };
            if !may_act_on(&admin, &server) {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Html("<div class=\"alert alert-error\">Mapping not found</div>"),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to load mapping {}: {}", mapping_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    }

    match state
        .user_authorization
        .delete_server_mapping(mapping_id)
        .await
    {
        Ok(true) => get_user_item(&state, &user_id).await.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Html("<div class=\"alert alert-error\">Mapping not found</div>"),
        )
            .into_response(),
        Err(e) => {
            error!("Delete mapping error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to delete mapping</div>"),
            )
                .into_response()
        }
    }
}

/// Kick a user from one of their mapped servers: deletes the real upstream
/// Jellyfin account there (owner-scoped, same as `delete_mapping`), removes
/// the local mapping/sessions, and blocks the username on that server so
/// "Auto Create Users On Login" can never silently recreate it.
pub async fn kick_user(
    State(state): State<AppState>,
    admin: CurrentAdmin,
    Path((user_id, mapping_id)): Path<(String, i64)>,
) -> Response {
    let mapping = match state
        .user_authorization
        .get_server_mapping_by_id(mapping_id)
        .await
    {
        Ok(Some(mapping)) => mapping,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Html("<div class=\"alert alert-error\">Mapping not found</div>"),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to load mapping {}: {}", mapping_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    let server = match state
        .server_storage
        .get_server_by_id(mapping.server_id)
        .await
    {
        Ok(Some(server)) => server,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Html("<div class=\"alert alert-error\">Server not found</div>"),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to load server for mapping {}: {}", mapping_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    if !may_act_on(&admin, &server) {
        return StatusCode::FORBIDDEN.into_response();
    }

    let username = match state.user_authorization.get_user_by_id(&user_id).await {
        Ok(Some(u)) => u.original_username,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Html("<div class=\"alert alert-error\">User not found</div>"),
            )
                .into_response();
        }
        Err(e) => {
            error!("Failed to fetch user by id {}: {}", user_id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Database error").into_response();
        }
    };

    let sync_result = state
        .federated_users
        .delete_user_from_server(&server, &username)
        .await;

    if let Err(e) = state
        .user_authorization
        .delete_server_mapping(mapping_id)
        .await
    {
        error!(
            "Failed to delete local mapping {} while kicking user: {}",
            mapping_id, e
        );
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Html("<div class=\"alert alert-error\">Failed to remove local mapping</div>"),
        )
            .into_response();
    }

    if let Err(e) = state
        .user_authorization
        .block_user_on_server(server.id, &username, Some(admin.id.as_i64()))
        .await
    {
        error!(
            "Failed to record block for user '{}' on server '{}': {}",
            username, server.name, e
        );
        return user_item_with_popup(
            &state,
            &user_id,
            format!(
                "Kicked '{}' from '{}' but failed to persist the block -- they may be recreated on next login.",
                username, server.name
            ),
        )
        .await;
    }

    info!(
        "Kicked and blocked user '{}' on server '{}' (remote delete status: {:?})",
        username, server.name, sync_result.status
    );

    user_item_with_popup(
        &state,
        &user_id,
        format!(
            "Kicked '{}' from '{}' (remote account: {:?}). They will not be auto-recreated there.",
            username, server.name, sync_result.status
        ),
    )
    .await
}

/// Delete sessions
pub async fn delete_sessions(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Response {
    match state
        .user_authorization
        .delete_all_sessions_for_user(&user_id)
        .await
    {
        Ok(_) => get_user_item(&state, &user_id).await.into_response(),
        Err(e) => {
            error!("Delete user error: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html("<div class=\"alert alert-error\">Failed to delete usersessions</div>"),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod kick_tests {
    use super::*;
    use crate::{
        admin_id::AdminId,
        config::{AppConfig, MediaStreamingMode, MIGRATOR},
        console_admin_service::ConsoleAdminService,
        encryption::{encrypt_password, HashedPassword},
        media_storage_service::MediaStorageService,
        session_storage::SessionStorage,
        user_authorization_service::UserAuthorizationService,
        DataContext, ProxyProcessors,
    };
    use sqlx::SqlitePool;
    use std::sync::Arc;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    async fn create_test_app_state() -> AppState {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();

        let data_context = DataContext {
            user_authorization: Arc::new(UserAuthorizationService::new(pool.clone())),
            server_storage: Arc::new(crate::server_storage::ServerStorageService::new(
                pool.clone(),
            )),
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

    async fn setup_server_with_mapped_user(
        state: &AppState,
        owner: Option<AdminId>,
    ) -> (crate::server_storage::Server, User, i64, MockServer) {
        let mock = MockServer::start().await;

        let server_id = state
            .server_storage
            .add_server_with_owner(
                "Server A",
                &mock.uri(),
                100,
                MediaStreamingMode::Redirect,
                owner,
            )
            .await
            .unwrap();
        let server = state
            .server_storage
            .get_server_by_id(server_id)
            .await
            .unwrap()
            .unwrap();

        let master_password: HashedPassword = state.config.read().await.password.clone().into();
        let encrypted_admin_password =
            encrypt_password(&"admin-secret".into(), &master_password).unwrap();
        state
            .server_storage
            .add_server_admin(server_id, "admin", &encrypted_admin_password)
            .await
            .unwrap();

        let user = state
            .user_authorization
            .create_user("kickme", &"userpass".into())
            .await
            .unwrap();
        let mapping_id = state
            .user_authorization
            .add_server_mapping(&user.id, &server, "kickme", &"userpass".into(), None)
            .await
            .unwrap();

        // Admin auth for the remote delete call.
        Mock::given(method("POST"))
            .and(path("/Users/AuthenticateByName"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "AccessToken": "admin-token",
                "ServerId": "upstream-server",
                "User": {
                    "Id": "admin-id", "Name": "admin", "ServerId": "upstream-server",
                    "Policy": {"IsAdministrator": true, "SyncPlayAccess": "None"}
                },
                "SessionInfo": {"UserId": "admin-id", "UserName": "admin", "ServerId": "upstream-server"}
            })))
            .mount(&mock)
            .await;

        Mock::given(method("GET"))
            .and(path("/Users"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
                    "Id": "remote-kickme-id", "Name": "kickme", "ServerId": "upstream-server",
                    "Policy": {"IsAdministrator": false, "SyncPlayAccess": "None"}
                })]),
            )
            .mount(&mock)
            .await;

        Mock::given(method("DELETE"))
            .and(path("/Users/remote-kickme-id"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&mock)
            .await;

        (server, user, mapping_id, mock)
    }

    #[tokio::test]
    async fn kick_removes_mapping_and_blocks_recreation() {
        let state = create_test_app_state().await;
        let owner = AdminId::new(1);
        let (server, user, mapping_id, _mock) =
            setup_server_with_mapped_user(&state, Some(owner)).await;

        let admin = CurrentAdmin {
            id: owner,
            is_superadmin: false,
        };

        let response = kick_user(
            State(state.clone()),
            admin,
            Path((user.id.clone(), mapping_id)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let mappings = state
            .user_authorization
            .list_server_mappings(&user.id)
            .await
            .unwrap();
        assert!(mappings.is_empty(), "mapping should be removed after kick");

        assert!(
            state
                .user_authorization
                .is_user_blocked_on_server(server.id, "kickme")
                .await
                .unwrap(),
            "user should be blocked on the server after kick"
        );
    }

    #[tokio::test]
    async fn kick_forbidden_for_non_owning_admin() {
        let state = create_test_app_state().await;
        let owner = AdminId::new(1);
        let other_admin = AdminId::new(2);
        let (server, user, mapping_id, _mock) =
            setup_server_with_mapped_user(&state, Some(owner)).await;

        let admin = CurrentAdmin {
            id: other_admin,
            is_superadmin: false,
        };

        let response = kick_user(
            State(state.clone()),
            admin,
            Path((user.id.clone(), mapping_id)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let mappings = state
            .user_authorization
            .list_server_mappings(&user.id)
            .await
            .unwrap();
        assert_eq!(
            mappings.len(),
            1,
            "mapping must survive a forbidden kick attempt"
        );

        assert!(
            !state
                .user_authorization
                .is_user_blocked_on_server(server.id, "kickme")
                .await
                .unwrap(),
            "user must not be blocked when the kick attempt was forbidden"
        );
    }
}
