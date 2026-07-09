use std::sync::Arc;

use tracing::{error, info, warn};

use crate::{
    encryption::{decrypt_password, HashedPassword, Password},
    server_storage::{Server, ServerStorageService},
    user_authorization_service::UserAuthorizationService,
    AppState,
};
use jellyfin_api::JellyfinClient;

#[derive(Debug, Clone)]
pub enum SyncStatus {
    Created,
    AlreadyExists,
    ExistsWithDifferentPassword,
    Failed,
    Skipped,
    Deleted,
    NotFound,
}

#[derive(Debug, Clone)]
pub struct ServerSyncResult {
    pub server_name: String,
    pub status: SyncStatus,
    pub message: Option<String>,
}

#[derive(Clone)]
pub struct FederatedUserService {
    server_storage: Arc<ServerStorageService>,
    user_authorization: Arc<UserAuthorizationService>,
    config: Arc<tokio::sync::RwLock<crate::config::AppConfig>>,
}

impl FederatedUserService {
    pub fn new(state: &AppState) -> Self {
        Self {
            server_storage: state.server_storage.clone(),
            user_authorization: state.user_authorization.clone(),
            config: state.config.clone(),
        }
    }

    pub fn new_from_components(
        server_storage: Arc<ServerStorageService>,
        user_authorization: Arc<UserAuthorizationService>,
        config: Arc<tokio::sync::RwLock<crate::config::AppConfig>>,
    ) -> Self {
        Self {
            server_storage,
            user_authorization,
            config,
        }
    }

    /// Syncs a user to all configured servers where an admin account is available.
    /// If the user does not exist on a server, it is created.
    /// If the user exists, we assume it's fine (we don't update passwords for existing users here to avoid conflicts).
    pub async fn sync_user_to_all_servers(
        &self,
        username: &str,
        password: &Password,
        user_id: &str,
    ) -> Vec<ServerSyncResult> {
        let mut results = Vec::new();
        let servers = match self.server_storage.list_servers().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to list servers for sync: {}", e);
                return results;
            }
        };

        for server in servers {
            results.push(
                self.sync_user_to_server(&server, username, password, user_id)
                    .await,
            );
        }

        results
    }

    /// Syncs (creates if missing, or verifies) a user on a single server.
    /// Used both by the all-servers admin-panel sync and by the
    /// auto-create-on-login flow, which only ever needs to touch the one
    /// server it just failed to authenticate a plain-credential probe on.
    pub async fn sync_user_to_server(
        &self,
        server: &Server,
        username: &str,
        password: &Password,
        user_id: &str,
    ) -> ServerSyncResult {
        let config = self.config.read().await;
        let admin_password: HashedPassword = config.password.clone().into();
        drop(config);

        let admin = match self.server_storage.get_server_admin(server.id).await {
            Ok(Some(a)) => a,
            Ok(None) => {
                warn!(
                    "Skipping sync for server {}: No admin credentials configured",
                    server.name
                );
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Skipped,
                    message: Some("No admin credentials".to_string()),
                };
            }
            Err(e) => {
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Failed to get admin creds: {}", e)),
                };
            }
        };

        let decrypted_admin_password = match decrypt_password(&admin.password, &admin_password) {
            Ok(p) => p,
            Err(e) => {
                error!(
                    "Failed to decrypt admin password for server {}: {}",
                    server.name, e
                );
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some("Failed to decrypt admin password".to_string()),
                };
            }
        };

        let client_info = crate::config::CLIENT_INFO.clone();

        let client = match JellyfinClient::new(server.url.as_str(), client_info.clone()) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create jellyfin client: {}", e);
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Client error: {}", e)),
                };
            }
        };

        // Authenticate as admin to get token
        if let Err(e) = client
            .authenticate_by_name(&admin.username, decrypted_admin_password.as_str())
            .await
        {
            error!(
                "Failed to authenticate as admin on server {}: {}",
                server.name, e
            );
            return ServerSyncResult {
                server_name: server.name.clone(),
                status: SyncStatus::Failed,
                message: Some(format!("Admin auth failed: {}", e)),
            };
        }

        // Check if user exists
        let users = match client.get_users().await {
            Ok(u) => u,
            Err(e) => {
                error!("Failed to list users on server {}: {}", server.name, e);
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Failed to list users: {}", e)),
                };
            }
        };

        let existing_user = users.iter().find(|u| u.name.eq_ignore_ascii_case(username));

        if let Some(remote_user) = existing_user {
            // User exists. Check if password matches.
            // We need a new client to check user password
            let user_client = match JellyfinClient::new(server.url.as_str(), client_info.clone()) {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to create jellyfin client: {}", e);
                    return ServerSyncResult {
                        server_name: server.name.clone(),
                        status: SyncStatus::Failed,
                        message: Some(format!("Client error: {}", e)),
                    };
                }
            };

            let (status, should_map) = match user_client
                .authenticate_by_name(username, password.as_str())
                .await
            {
                Ok(_) => (SyncStatus::AlreadyExists, true),
                Err(_) => (SyncStatus::ExistsWithDifferentPassword, false),
            };

            info!(
                "Synced user {} to server {} (Remote ID: {}, Status: {:?})",
                username, server.name, remote_user.id, status
            );

            if !should_map {
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status,
                    message: Some("User exists with different password".to_string()),
                };
            }

            if let Err(e) = self
                .user_authorization
                .add_server_mapping(
                    user_id,
                    server,
                    username,
                    password,
                    Some(&password.into()), // Encrypt with their own password so they can use it
                )
                .await
            {
                error!(
                    "Failed to create local mapping for synced user on server {}: {}",
                    server.name, e
                );
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Failed to save local mapping: {}", e)),
                };
            }

            ServerSyncResult {
                server_name: server.name.clone(),
                status,
                message: None,
            }
        } else {
            // Create user
            match client.create_user(username, Some(password.as_str())).await {
                Ok(new_user) => {
                    info!(
                        "Synced user {} to server {} (Remote ID: {}, Status: Created)",
                        username, server.name, new_user.id
                    );

                    if let Err(e) = self
                        .user_authorization
                        .add_server_mapping(
                            user_id,
                            server,
                            username,
                            password,
                            Some(&password.into()), // Encrypt with their own password so they can use it
                        )
                        .await
                    {
                        error!(
                            "Failed to create local mapping for synced user on server {}: {}",
                            server.name, e
                        );
                        return ServerSyncResult {
                            server_name: server.name.clone(),
                            status: SyncStatus::Failed,
                            message: Some(format!("Failed to save local mapping: {}", e)),
                        };
                    }

                    ServerSyncResult {
                        server_name: server.name.clone(),
                        status: SyncStatus::Created,
                        message: None,
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to sync user {} to server {}: {}",
                        username, server.name, e
                    );
                    ServerSyncResult {
                        server_name: server.name.clone(),
                        status: SyncStatus::Failed,
                        message: Some(format!("Sync failed: {}", e)),
                    }
                }
            }
        }
    }

    pub async fn delete_user_from_all_servers(&self, username: &str) -> Vec<ServerSyncResult> {
        let mut results = Vec::new();
        let servers = match self.server_storage.list_servers().await {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to list servers for delete: {}", e);
                return results;
            }
        };

        for server in servers {
            results.push(self.delete_user_from_server(&server, username).await);
        }

        results
    }

    /// Deletes the real upstream Jellyfin account for `username` on a
    /// single server. Used both by the all-servers admin-panel delete and by
    /// the per-server "kick" action, which must only ever touch the one
    /// server the admin owns.
    pub async fn delete_user_from_server(
        &self,
        server: &Server,
        username: &str,
    ) -> ServerSyncResult {
        let admin_password = {
            let config = self.config.read().await;
            config.password.clone()
        };

        let admin = match self.server_storage.get_server_admin(server.id).await {
            Ok(Some(a)) => a,
            Ok(None) => {
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Skipped,
                    message: Some("No admin credentials".to_string()),
                };
            }
            Err(e) => {
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Failed to get admin creds: {}", e)),
                };
            }
        };

        let decrypted_admin_password =
            match decrypt_password(&admin.password, &admin_password.into()) {
                Ok(p) => p,
                Err(e) => {
                    error!(
                        "Failed to decrypt admin password for server {}: {}",
                        server.name, e
                    );
                    return ServerSyncResult {
                        server_name: server.name.clone(),
                        status: SyncStatus::Failed,
                        message: Some("Failed to decrypt admin password".to_string()),
                    };
                }
            };

        let client_info = crate::config::CLIENT_INFO.clone();

        let client = match JellyfinClient::new(server.url.as_str(), client_info.clone()) {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to create jellyfin client: {}", e);
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Client error: {}", e)),
                };
            }
        };

        if let Err(e) = client
            .authenticate_by_name(&admin.username, decrypted_admin_password.as_str())
            .await
        {
            error!(
                "Failed to authenticate as admin on server {}: {}",
                server.name, e
            );
            return ServerSyncResult {
                server_name: server.name.clone(),
                status: SyncStatus::Failed,
                message: Some(format!("Admin auth failed: {}", e)),
            };
        }

        // Find user ID
        let users = match client.get_users().await {
            Ok(u) => u,
            Err(e) => {
                error!("Failed to list users on server {}: {}", server.name, e);
                return ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Failed to list users: {}", e)),
                };
            }
        };

        let user_id = users
            .iter()
            .find(|u| u.name.eq_ignore_ascii_case(username))
            .map(|u| u.id.clone());

        let Some(id) = user_id else {
            return ServerSyncResult {
                server_name: server.name.clone(),
                status: SyncStatus::NotFound,
                message: None,
            };
        };

        match client.delete_user(&id).await {
            Ok(_) => {
                info!(
                    "Deleted user {} from server {} (Deleted: true)",
                    username, server.name
                );
                ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Deleted,
                    message: None,
                }
            }
            Err(e) => {
                warn!(
                    "Failed to delete user {} from server {}: {}",
                    username, server.name, e
                );
                ServerSyncResult {
                    server_name: server.name.clone(),
                    status: SyncStatus::Failed,
                    message: Some(format!("Delete failed: {}", e)),
                }
            }
        }
    }
}
