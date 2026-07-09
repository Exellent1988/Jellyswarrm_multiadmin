//! Multi-admin support: independent proxy console operator accounts.
//!
//! Distinct from `server_storage::ServerAdmin` ("server_admins" table), which
//! stores per-server *upstream Jellyfin* admin credentials used for
//! federation sync -- an unrelated concept. A `ConsoleAdmin` is someone who
//! logs into this proxy's own `/ui` to manage (a subset of) servers.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};
use tracing::info;

use crate::admin_id::AdminId;
use crate::config::AppConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleAdmin {
    pub id: AdminId,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_superadmin: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl ConsoleAdmin {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: AdminId::new(row.try_get("id")?),
            username: row.try_get("username")?,
            password_hash: row.try_get("password_hash")?,
            is_superadmin: row.try_get("is_superadmin")?,
            created_at: row.try_get("created_at")?,
            updated_at: row.try_get("updated_at")?,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConsoleAdminError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error("password hashing failed: {0}")]
    Hash(String),
}

#[derive(Debug, Clone)]
pub struct ConsoleAdminService {
    pool: SqlitePool,
}

impl ConsoleAdminService {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn hash_password(plaintext: &str) -> Result<String, ConsoleAdminError> {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(plaintext.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| ConsoleAdminError::Hash(e.to_string()))
    }

    fn verify_password(plaintext: &str, hash: &str) -> bool {
        let Ok(parsed_hash) = PasswordHash::new(hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(plaintext.as_bytes(), &parsed_hash)
            .is_ok()
    }

    pub async fn create_admin(
        &self,
        username: &str,
        plaintext_password: &str,
        is_superadmin: bool,
    ) -> Result<ConsoleAdmin, ConsoleAdminError> {
        let password_hash = Self::hash_password(plaintext_password)?;
        let now = chrono::Utc::now();

        let result = sqlx::query(
            r#"
            INSERT INTO console_admins (username, password_hash, is_superadmin, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(username)
        .bind(&password_hash)
        .bind(is_superadmin)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        let id = AdminId::new(result.last_insert_rowid());
        info!("Created console admin '{}' (id {})", username, id);

        Ok(ConsoleAdmin {
            id,
            username: username.to_string(),
            password_hash,
            is_superadmin,
            created_at: now,
            updated_at: now,
        })
    }

    pub async fn get_admin_by_username(
        &self,
        username: &str,
    ) -> Result<Option<ConsoleAdmin>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, is_superadmin, created_at, updated_at
            FROM console_admins
            WHERE username = ?
            "#,
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(ConsoleAdmin::from_row).transpose()
    }

    pub async fn get_admin_by_id(&self, id: AdminId) -> Result<Option<ConsoleAdmin>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, username, password_hash, is_superadmin, created_at, updated_at
            FROM console_admins
            WHERE id = ?
            "#,
        )
        .bind(id.as_i64())
        .fetch_optional(&self.pool)
        .await?;

        row.as_ref().map(ConsoleAdmin::from_row).transpose()
    }

    pub async fn list_admins(&self) -> Result<Vec<ConsoleAdmin>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, username, password_hash, is_superadmin, created_at, updated_at
            FROM console_admins
            ORDER BY username ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.iter().map(ConsoleAdmin::from_row).collect()
    }

    /// Verifies credentials and returns the matching admin, or `None` if the
    /// username doesn't exist or the password is wrong.
    pub async fn verify_credentials(
        &self,
        username: &str,
        plaintext_password: &str,
    ) -> Result<Option<ConsoleAdmin>, sqlx::Error> {
        let Some(admin) = self.get_admin_by_username(username).await? else {
            return Ok(None);
        };
        if admin.password_hash.is_empty() {
            // Unfilled bootstrap sentinel row (see ensure_bootstrap_admin) --
            // never authenticate against an empty hash.
            return Ok(None);
        }
        if Self::verify_password(plaintext_password, &admin.password_hash) {
            Ok(Some(admin))
        } else {
            Ok(None)
        }
    }

    pub async fn update_password(
        &self,
        id: AdminId,
        new_plaintext_password: &str,
    ) -> Result<bool, ConsoleAdminError> {
        let password_hash = Self::hash_password(new_plaintext_password)?;
        let now = chrono::Utc::now();

        let result = sqlx::query(
            r#"
            UPDATE console_admins
            SET password_hash = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(&password_hash)
        .bind(now)
        .bind(id.as_i64())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn set_superadmin(
        &self,
        id: AdminId,
        is_superadmin: bool,
    ) -> Result<bool, sqlx::Error> {
        let now = chrono::Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE console_admins
            SET is_superadmin = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(is_superadmin)
        .bind(now)
        .bind(id.as_i64())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn delete_admin(&self, id: AdminId) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM console_admins WHERE id = ?")
            .bind(id.as_i64())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Fills in the migration's sentinel bootstrap admin row (created with an
    /// empty `password_hash`) from the current `JELLYSWARRM_USERNAME`/
    /// `PASSWORD` config, the first time it's found. Guarded on
    /// `password_hash = ''` so it can never overwrite a real admin's
    /// password on a later restart -- once the sentinel is filled in (or a
    /// real admin already exists), this is a no-op forever after.
    pub async fn ensure_bootstrap_admin(&self, cfg: &AppConfig) -> Result<(), ConsoleAdminError> {
        let sentinel = sqlx::query(
            r#"
            SELECT id, username FROM console_admins
            WHERE password_hash = ''
            ORDER BY id ASC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = sentinel else {
            return Ok(());
        };

        let id: i64 = row.try_get("id")?;
        let password_hash = Self::hash_password(cfg.password.as_str())?;
        let now = chrono::Utc::now();

        sqlx::query(
            r#"
            UPDATE console_admins
            SET username = ?, password_hash = ?, updated_at = ?
            WHERE id = ? AND password_hash = ''
            "#,
        )
        .bind(&cfg.username)
        .bind(&password_hash)
        .bind(now)
        .bind(id)
        .execute(&self.pool)
        .await?;

        info!(
            "Bootstrapped initial console admin '{}' from JELLYSWARRM_USERNAME/PASSWORD",
            cfg.username
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::config::MIGRATOR.run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn create_and_verify_round_trip() {
        let pool = test_pool().await;
        let service = ConsoleAdminService::new(pool);

        service
            .create_admin("alice", "correct horse battery staple", false)
            .await
            .unwrap();

        let ok = service
            .verify_credentials("alice", "correct horse battery staple")
            .await
            .unwrap();
        assert!(ok.is_some());

        let wrong = service
            .verify_credentials("alice", "wrong password")
            .await
            .unwrap();
        assert!(wrong.is_none());
    }

    #[tokio::test]
    async fn duplicate_username_rejected() {
        let pool = test_pool().await;
        let service = ConsoleAdminService::new(pool);

        service.create_admin("bob", "pw1", false).await.unwrap();
        let result = service.create_admin("bob", "pw2", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn bootstrap_is_idempotent_and_never_overwrites_a_changed_password() {
        let pool = test_pool().await;
        let service = ConsoleAdminService::new(pool);

        let cfg = AppConfig {
            username: "admin".to_string(),
            password: "jellyswarrm".to_string().into(),
            ..Default::default()
        };

        // First run fills in the migration's sentinel row.
        service.ensure_bootstrap_admin(&cfg).await.unwrap();
        let admins = service.list_admins().await.unwrap();
        assert_eq!(admins.len(), 1);
        assert!(service
            .verify_credentials("admin", "jellyswarrm")
            .await
            .unwrap()
            .is_some());

        // Operator changes the password through the app afterward.
        let admin_id = admins[0].id;
        service
            .update_password(admin_id, "a new stronger password")
            .await
            .unwrap();

        // A second bootstrap run (e.g. on restart) must not clobber it, even
        // though the env-configured password is still the old default.
        service.ensure_bootstrap_admin(&cfg).await.unwrap();
        assert!(service
            .verify_credentials("admin", "a new stronger password")
            .await
            .unwrap()
            .is_some());
        assert!(service
            .verify_credentials("admin", "jellyswarrm")
            .await
            .unwrap()
            .is_none());

        // Still exactly one admin.
        assert_eq!(service.list_admins().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn migration_creates_exactly_one_sentinel_admin_on_a_fresh_database() {
        let pool = test_pool().await;
        let service = ConsoleAdminService::new(pool);

        let admins = service.list_admins().await.unwrap();
        assert_eq!(admins.len(), 1, "expected exactly the sentinel admin row");
        assert!(admins[0].is_superadmin);
        assert!(
            admins[0].password_hash.is_empty(),
            "sentinel row should start with an empty hash until ensure_bootstrap_admin fills it in"
        );
    }
}
