//! Fail2ban-style protection for the login endpoint. Tracks failed
//! authentication attempts per client identifier (see `client_ip.rs` for how
//! that identifier is derived) in a rolling window, and imposes a cooldown
//! once a configurable threshold is exceeded within that window. A
//! successful login clears the counter. Instance-wide by design -- it
//! protects the login endpoint itself, not any particular server, so it
//! isn't scoped to console-admin ownership the way per-server settings are.
//!
//! Repeat offenders escalate: each time an identifier is newly blocked (a
//! fresh cooldown cycle, not a renewal of an existing one), `times_blocked`
//! increments. Once it reaches a configurable threshold, the identifier is
//! blocked permanently instead of just cooling down again -- only a manual
//! admin unblock lifts it (classic fail2ban "recidive" pattern).

use sqlx::{sqlite::SqliteRow, FromRow, Row, SqlitePool};

/// Whether, and how, an identifier is currently blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginBlockStatus {
    /// Blocked for a limited time; will be forgiven once it elapses.
    Cooldown { seconds_remaining: i64 },
    /// Blocked indefinitely after too many repeat offenses; requires a
    /// manual admin unblock.
    Permanent,
}

#[derive(Debug, Clone)]
pub struct LoginRateLimitEntry {
    pub identifier: String,
    pub failure_count: i64,
    pub times_blocked: i64,
    pub permanent: bool,
    pub blocked_until: Option<chrono::DateTime<chrono::Utc>>,
    pub last_failure_at: chrono::DateTime<chrono::Utc>,
}

impl<'r> FromRow<'r, SqliteRow> for LoginRateLimitEntry {
    fn from_row(row: &SqliteRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            identifier: row.try_get("identifier")?,
            failure_count: row.try_get("failure_count")?,
            times_blocked: row.try_get("times_blocked")?,
            permanent: row.try_get("permanent")?,
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

    /// Whether `identifier` is currently blocked, and how (see
    /// `LoginBlockStatus`).
    pub async fn check_blocked(
        &self,
        identifier: &str,
    ) -> Result<Option<LoginBlockStatus>, sqlx::Error> {
        let row: Option<(bool, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            r#"
            SELECT permanent, blocked_until
            FROM login_rate_limits
            WHERE identifier = ?
            "#,
        )
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;

        let Some((permanent, blocked_until)) = row else {
            return Ok(None);
        };

        if permanent {
            return Ok(Some(LoginBlockStatus::Permanent));
        }

        let Some(blocked_until) = blocked_until else {
            return Ok(None);
        };

        let now = chrono::Utc::now();
        if blocked_until <= now {
            return Ok(None);
        }

        Ok(Some(LoginBlockStatus::Cooldown {
            seconds_remaining: (blocked_until - now).num_seconds().max(1),
        }))
    }

    /// Records a failed login attempt for `identifier`. If the rolling
    /// window has expired since the last failure, the counter resets to 1;
    /// otherwise it increments. Once `max_attempts` is reached within the
    /// window, a *new* block cycle begins: `times_blocked` increments, and
    /// either `blocked_until` is set `cooldown_secs` into the future, or --
    /// if `permanent_after_repeats` is positive and now reached -- the
    /// identifier is marked permanently blocked instead. Returns the
    /// resulting block status, if any (including one already in effect from
    /// a prior call, e.g. a permanent block that persists across further
    /// failures).
    pub async fn record_failure(
        &self,
        identifier: &str,
        max_attempts: i64,
        window_secs: i64,
        cooldown_secs: i64,
        permanent_after_repeats: i64,
    ) -> Result<Option<LoginBlockStatus>, sqlx::Error> {
        let now = chrono::Utc::now();

        let existing: Option<(i64, chrono::DateTime<chrono::Utc>, i64, bool)> = sqlx::query_as(
            r#"
            SELECT failure_count, window_started_at, times_blocked, permanent
            FROM login_rate_limits
            WHERE identifier = ?
            "#,
        )
        .bind(identifier)
        .fetch_optional(&self.pool)
        .await?;

        if let Some((_, _, _, true)) = existing {
            // Already permanently blocked; nothing to escalate further.
            return Ok(Some(LoginBlockStatus::Permanent));
        }

        let (failure_count, window_started_at, times_blocked) = match existing {
            Some((count, window_started_at, times_blocked, _))
                if now.signed_duration_since(window_started_at).num_seconds() < window_secs =>
            {
                (count + 1, window_started_at, times_blocked)
            }
            Some((_, _, times_blocked, _)) => (1, now, times_blocked),
            None => (1, now, 0),
        };

        let (new_times_blocked, blocked_until, permanent) = if failure_count >= max_attempts {
            let new_times_blocked = times_blocked + 1;
            if permanent_after_repeats > 0 && new_times_blocked >= permanent_after_repeats {
                (new_times_blocked, None, true)
            } else {
                (
                    new_times_blocked,
                    Some(now + chrono::Duration::seconds(cooldown_secs)),
                    false,
                )
            }
        } else {
            (times_blocked, None, false)
        };

        sqlx::query(
            r#"
            INSERT INTO login_rate_limits
                (identifier, failure_count, window_started_at, last_failure_at, blocked_until, times_blocked, permanent, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(identifier) DO UPDATE SET
                failure_count = excluded.failure_count,
                window_started_at = excluded.window_started_at,
                last_failure_at = excluded.last_failure_at,
                blocked_until = excluded.blocked_until,
                times_blocked = excluded.times_blocked,
                permanent = excluded.permanent,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(identifier)
        .bind(failure_count)
        .bind(window_started_at)
        .bind(now)
        .bind(blocked_until)
        .bind(new_times_blocked)
        .bind(permanent)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        if permanent {
            Ok(Some(LoginBlockStatus::Permanent))
        } else {
            Ok(
                blocked_until.map(|blocked_until| LoginBlockStatus::Cooldown {
                    seconds_remaining: (blocked_until - now).num_seconds().max(1),
                }),
            )
        }
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

    /// Manually lifts a block (admin action) and resets the repeat-offender
    /// count -- a full clean slate. Returns whether a row existed.
    pub async fn unblock(&self, identifier: &str) -> Result<bool, sqlx::Error> {
        let res = sqlx::query("DELETE FROM login_rate_limits WHERE identifier = ?")
            .bind(identifier)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Lists identifiers currently blocked (cooldown or permanent), most
    /// recent failure first, for the admin UI.
    pub async fn list_blocked(&self) -> Result<Vec<LoginRateLimitEntry>, sqlx::Error> {
        sqlx::query_as::<_, LoginRateLimitEntry>(
            r#"
            SELECT identifier, failure_count, times_blocked, permanent, blocked_until, last_failure_at
            FROM login_rate_limits
            WHERE permanent = 1 OR (blocked_until IS NOT NULL AND blocked_until > ?)
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
            let status = service.record_failure(id, 5, 300, 900, 0).await.unwrap();
            assert!(status.is_none(), "should not block before max_attempts");
        }

        assert!(service.check_blocked(id).await.unwrap().is_none());

        let status = service.record_failure(id, 5, 300, 900, 0).await.unwrap();
        assert!(matches!(
            status,
            Some(LoginBlockStatus::Cooldown { seconds_remaining }) if seconds_remaining > 0
        ));

        assert!(matches!(
            service.check_blocked(id).await.unwrap(),
            Some(LoginBlockStatus::Cooldown { .. })
        ));
    }

    #[tokio::test]
    async fn success_clears_the_counter() {
        let service = setup_service().await;
        let id = "1.2.3.4";

        for _ in 0..4 {
            service.record_failure(id, 5, 300, 900, 0).await.unwrap();
        }

        service.record_success(id).await.unwrap();

        // A fresh run of failures afterward should need the full count again.
        for _ in 0..4 {
            let status = service.record_failure(id, 5, 300, 900, 0).await.unwrap();
            assert!(status.is_none());
        }
    }

    #[tokio::test]
    async fn manual_unblock_lifts_the_cooldown() {
        let service = setup_service().await;
        let id = "1.2.3.4";

        for _ in 0..5 {
            service.record_failure(id, 5, 300, 900, 0).await.unwrap();
        }
        assert!(service.check_blocked(id).await.unwrap().is_some());

        let unblocked = service.unblock(id).await.unwrap();
        assert!(unblocked);
        assert!(service.check_blocked(id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn different_identifiers_are_tracked_independently() {
        let service = setup_service().await;

        for _ in 0..5 {
            service
                .record_failure("1.1.1.1", 5, 300, 900, 0)
                .await
                .unwrap();
        }

        assert!(service.check_blocked("1.1.1.1").await.unwrap().is_some());
        assert!(service.check_blocked("2.2.2.2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_blocked_only_returns_currently_active_blocks() {
        let service = setup_service().await;

        for _ in 0..5 {
            service
                .record_failure("3.3.3.3", 5, 300, 900, 0)
                .await
                .unwrap();
        }
        for _ in 0..2 {
            service
                .record_failure("4.4.4.4", 5, 300, 900, 0)
                .await
                .unwrap();
        }

        let blocked = service.list_blocked().await.unwrap();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].identifier, "3.3.3.3");
    }

    #[tokio::test]
    async fn third_cooldown_cycle_escalates_to_permanent() {
        let service = setup_service().await;
        let id = "5.5.5.5";
        // permanent_after_repeats=3: the first two full block cycles are
        // ordinary cooldowns; the third escalates to permanent.
        let permanent_after = 3;

        for cycle in 1..=2 {
            let mut status = None;
            for _ in 0..3 {
                status = service
                    .record_failure(id, 3, 300, 1, permanent_after)
                    .await
                    .unwrap();
            }
            assert!(
                matches!(status, Some(LoginBlockStatus::Cooldown { .. })),
                "cycle {cycle} should be an ordinary cooldown, got {status:?}"
            );
            // Simulate the cooldown elapsing and the window resetting by
            // manually expiring it, then move on to the next cycle's fresh
            // set of failures.
            sqlx::query("UPDATE login_rate_limits SET window_started_at = ?, blocked_until = ? WHERE identifier = ?")
                .bind(chrono::Utc::now() - chrono::Duration::seconds(3600))
                .bind(chrono::Utc::now() - chrono::Duration::seconds(1))
                .bind(id)
                .execute(&service.pool)
                .await
                .unwrap();
        }

        // Third cycle: same failures again, should now escalate to permanent.
        let mut last_status = None;
        for _ in 0..3 {
            last_status = service
                .record_failure(id, 3, 300, 1, permanent_after)
                .await
                .unwrap();
        }
        assert_eq!(last_status, Some(LoginBlockStatus::Permanent));

        assert_eq!(
            service.check_blocked(id).await.unwrap(),
            Some(LoginBlockStatus::Permanent)
        );

        let blocked = service.list_blocked().await.unwrap();
        assert_eq!(blocked.len(), 1);
        assert!(blocked[0].permanent);
        assert_eq!(blocked[0].times_blocked, 3);
    }

    #[tokio::test]
    async fn unblock_resets_the_repeat_offender_count() {
        let service = setup_service().await;
        let id = "6.6.6.6";

        for _ in 0..5 {
            service.record_failure(id, 5, 300, 900, 3).await.unwrap();
        }
        assert!(service.check_blocked(id).await.unwrap().is_some());

        service.unblock(id).await.unwrap();

        // A brand new block cycle after a manual unblock should be treated
        // as the first offense again, not already escalated.
        let mut last_status = None;
        for _ in 0..5 {
            last_status = service.record_failure(id, 5, 300, 900, 3).await.unwrap();
        }
        assert!(matches!(
            last_status,
            Some(LoginBlockStatus::Cooldown { .. })
        ));
    }
}
