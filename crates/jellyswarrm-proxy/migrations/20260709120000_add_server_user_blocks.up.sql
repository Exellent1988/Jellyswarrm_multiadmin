-- Per-server user blocks: lets the admin who owns a server "kick" a user
-- from it (deleting their real upstream Jellyfin account, see
-- federated_users::delete_user_from_server) and have that decision stick --
-- i.e. prevent the new auto-create-on-login flow from silently recreating
-- the account there on the user's next login.
--
-- Keyed by username (not user_id): a block must survive even if the local
-- proxy user row is later deleted and a new one gets created for the same
-- username, since the whole point is "never recreate this person here".
CREATE TABLE IF NOT EXISTS server_user_blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    blocked_by_admin_id INTEGER REFERENCES console_admins(id) ON DELETE SET NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_server_user_blocks_server_username
    ON server_user_blocks(server_id, username);
