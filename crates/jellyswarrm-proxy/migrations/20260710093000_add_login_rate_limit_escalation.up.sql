-- Repeat-offender escalation for the login rate limiter: tracks how many
-- times a given identifier has been through a full cooldown cycle, so that
-- after a configurable number of them it can be blocked permanently instead
-- of just cooling down again (classic fail2ban "recidive" pattern).
ALTER TABLE login_rate_limits ADD COLUMN times_blocked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE login_rate_limits ADD COLUMN permanent BOOLEAN NOT NULL DEFAULT 0;
