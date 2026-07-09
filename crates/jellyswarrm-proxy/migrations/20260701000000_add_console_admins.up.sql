-- Multi-admin support: multiple independent proxy console operators, each
-- owning a subset of servers. End-user-facing library/federation stays
-- global and is unaffected by ownership (see servers.owner_admin_id below).
--
-- Named "console_admins" (not "admins") to avoid confusion with the
-- pre-existing `server_admins` table, which stores per-server *upstream
-- Jellyfin* admin credentials used for federation sync -- an unrelated
-- concept.
CREATE TABLE IF NOT EXISTS console_admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_superadmin BOOLEAN NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_console_admins_username ON console_admins(username);

-- Nullable, and ON DELETE SET NULL (not CASCADE): deleting a console admin
-- must never delete or hide their servers, since the shared library must
-- keep showing them to end users regardless of who owns them.
ALTER TABLE servers ADD COLUMN owner_admin_id INTEGER REFERENCES console_admins(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_servers_owner_admin_id ON servers(owner_admin_id);

-- Backward-compatible bootstrap: create a sentinel "legacy" admin (empty
-- password_hash) representing the single JELLYSWARRM_USERNAME/PASSWORD pair
-- this instance used before this migration, then assign every pre-existing
-- server to it. Migrations can't read env vars, so the real password hash is
-- filled in by an application-startup step (console_admin_service::ensure_bootstrap_admin)
-- the first time it finds this sentinel row -- see that function for the
-- guard which keeps it from ever overwriting a real admin's password later.
INSERT INTO console_admins (username, password_hash, is_superadmin, created_at, updated_at)
SELECT 'admin', '', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
WHERE NOT EXISTS (SELECT 1 FROM console_admins);

UPDATE servers
SET owner_admin_id = (SELECT id FROM console_admins ORDER BY id ASC LIMIT 1)
WHERE owner_admin_id IS NULL;
