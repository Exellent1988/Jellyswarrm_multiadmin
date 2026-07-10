-- Fail2ban-style protection for the login endpoint: tracks failed
-- authentication attempts per client identifier (best-effort client IP, see
-- client_ip::extract_client_ip) in a rolling window, and imposes a cooldown
-- once a configurable threshold is exceeded. Instance-wide (not scoped to a
-- server or its owning admin), since it protects the login endpoint itself.
CREATE TABLE IF NOT EXISTS login_rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL UNIQUE,
    failure_count INTEGER NOT NULL DEFAULT 0,
    window_started_at TIMESTAMP NOT NULL,
    last_failure_at TIMESTAMP NOT NULL,
    blocked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_login_rate_limits_blocked_until
    ON login_rate_limits(blocked_until);
