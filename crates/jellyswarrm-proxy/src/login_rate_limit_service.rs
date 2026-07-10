//! Fail2ban-style protection for the login endpoint. Tracks failed
//! authentication attempts per client identifier (see `client_ip.rs` for how
//! that identifier is derived) in a rolling window, and imposes a cooldown
//! once a configurable threshold is exceeded within that window. A
//! successful login clears the counter. Instance-wide by design -- it
//! protects the login endpoint itself, not any particular server, so it
//! isn't scoped to console-admin ownership the way per-server settings are.

use sqlx::{sqlite::SqliteRow, FromRow, Row, SqlitePool};

#[derive(Debug, Clone)]
pub struct LoginRateLimitEntry {
    pub identifier: String,
    pub failure_count: i64,
    pub blocked_until: Option<chrono::DateTime<chrono::Utc>>,
    pub last_failure_at: chrono::DateTime<chrono::Utc>,
}

impl<'r> FromRow<'r, SqliteRow> for LoginRateLimitEntry {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            identifier: row.try_get("identifier")?,
            failure_count: row.try_get("failure_count")?,
            blocked_until: row.try_get("blocked_until")?,
            last_failure_at: row.try_get("last_failure_at")?,
        })
    }
}

#[derive(Clone)]
pub struct LoginRateLimitService {
    pool: SqlitePool,
}

impl LoginRateLimitService {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Seconds remaining until `identifier` may attempt to log in again, or
    /// `None` if it isn't currently blocked.
    pub async fn seconds_until_unblocked(
        &self,
        identifier: &str,
    ) -> Result<Option<i64>, sqlx::Error> {
        let blocked_until: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            r#"
            SELECT blocked_until
            FROM login_rate_limits
            WHERE identifier = ?
            "#,
        )
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?
        .flatten();

        let Some(blocked_until) = blocked_until else {
            return Ok(None);
        };

        let now = chrono::Utc::now();
        if blocked_until <= now {
            return Ok(None);
        }

        Ok(Some((blocked_until - now).num_seconds().max(1)))
    }

    /// Records a failed login attempt for `identifier`. If the rolling
    /// window has expired since the last failure, the counter resets to 1;
    /// otherwise it increments. Once `max_attempts` is reached within the
    /// window, `blocked_until` is set `cooldown_secs` into the future.
    /// Returns whether this call caused (or extended) a block.
    pub async fn record_failure(
        &self,
        identifier: &str,
        max_attempts: i64,
        window_secs: i64,
        cooldown_secs: i64,
    ) -> Result<bool, sqlx::Error> {
        let now = chrono::Utc::now();

        let existing: Option<(i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
            r#"
            SELECT failure_count, window_started_at
            FROM login_rate_limits
            WHERE identifier = ?
            "#,
        )
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;

        let (failure_count, window_started_at) = match existing {
            Some((count, window_started_at))
                if now.signed_duration_since(window_started_at).num_seconds() < window_secs =>
            {
                (count + 1, window_started_at)
            }
            _ => (1, now),
        };

        let blocked_until = if failure_count >= max_attempts {
            Some(now + chrono::Duration::seconds(cooldown_secs))
        } else {
            None
        };

        sqlx::query(
            r#"
            INSERT INTO login_rate_limits
                (identifier, failure_count, window_started_at, last_failure_at, blocked_until, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(identifier) DO UPDATE SET
                failure_count = excluded.failure_count,
                window_started_at = excluded.window_started_at,
                last_failure_at = excluded.last_failure_at,
                blocked_until = excluded.blocked_until,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(identifier)
        .bind(failure_count)
        .bind(window_started_at)
        .bind(now)
        .bind(blocked_until)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(blocked_until.is_some())
    }

    /// Clears any failure count/block for `identifier`, e.g. after a
    /// successful login.
    pub async fn record_success(&self, identifier: &str) -> Result<(), sqlx::Error> {
        sqlx::query("DELETE FROM login_rate_limits WHERE identifier = ?")
            .bind(identifier)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Manually lifts a block (admin action). Returns whether a row existed.
    pub async fn unblock(&self, identifier: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("DELETE FROM login_rate_limits WHERE identifier = ?")
            .bind(identifier)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Lists identifiers currently under an active cooldown, most recent
    /// failure first, for the admin UI.
    pub async fn list_blocked(&self) -> Result<Vec<LoginRateLimitEntry>, sqlx::Error> {
        sqlx::query_as::<_, LoginRateLimitEntry>(
            r#"
            SELECT identifier, failure_count, blocked_until, last_failure_at
            FROM login_rate_limits
            WHERE blocked_until IS NOT NULL AND blocked_until > ?
            ORDER BY last_failure_at DESC
            "#,
        )
        .bind(chrono::Utc::now())
        .fetch_all(&self.pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MIGRATOR;

    async fn setup_service() -> LoginRateLimitService {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        LoginRateLimitService::new(pool)
    }

    #[tokio::test]
    async fn allows_up_to_max_attempts_then_blocks() {
        let service = setup_service().await;
        let id = "1.2.3.4";

        for _ in 0..4 {
            let blocked = service.record_failure(id, 5, 300, 900).await.unwrap();
            assert!(!blocked, "should not block before reaching max_attempts");
        }

        assert!(
            service.seconds_until_unblocked(id).await.unwrap().is_none(),
            "should not be blocked yet"
        );

        let blocked = service.record_failure(id, 5, 300, 900).await.unwrap();
        assert!(blocked, "5th failure should trigger the block");

        let remaining = service.seconds_until_unblocked(id).await.unwrap();
        assert!(remaining.is_some() && remaining.unwrap() > 0);
    }

    #[tokio::test]
    async fn success_clears_the_counter() {
        let service = setup_service().await;
        let id = "1.2.3.4";

        for _ in 0..4 {
            service.record_failure(id, 5, 300, 900).await.unwrap();
        }

        service.record_success(id).await.unwrap();

        // A fresh run of failures afterward should need the full count again.
        for _ in 0..4 {
            let blocked = service.record_failure(id, 5, 300, 900).await.unwrap();
            assert!(!blocked);
        }
    }

    #[tokio::test]
    async fn manual_unblock_lifts_the_cooldown() {
        let service = setup_service().await;
        let id = "1.2.3.4";

        for _ in 0..5 {
            service.record_failure(id, 5, 300, 900).await.unwrap();
        }
        assert!(service.seconds_until_unblocked(id).await.unwrap().is_some());

        let unblocked = service.unblock(id).await.unwrap();
        assert!(unblocked);
        assert!(service.seconds_until_unblocked(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn different_identifiers_are_tracked_independently() {
        let service = setup_service().await;

        for _ in 0..5 {
            service
                .record_failure("1.1.1.1", 5, 300, 900)
                .await
                .unwrap();
        }

        assert!(service
            .seconds_until_unblocked("1.1.1.1")
            .await
            .unwrap()
            .is_some());
        assert!(service
            .seconds_until_unblocked("2.2.2.2")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn list_blocked_only_returns_currently_active_blocks() {
        let service = setup_service().await;

        for _ in 0..5 {
            service
                .record_failure("3.3.3.3", 5, 300, 900)
                .await
                .unwrap();
        }
        for _ in 0..2 {
            service
                .record_failure("4.4.4.4", 5, 300, 900)
                .await
                .unwrap();
        }

        let blocked = service.list_blocked().await.unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].identifier, "3.3.3.3");
    }
}
