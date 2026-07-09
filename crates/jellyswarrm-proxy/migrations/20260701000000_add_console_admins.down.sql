DROP INDEX IF EXISTS idx_servers_owner_admin_id;
ALTER TABLE servers DROP COLUMN owner_admin_id;
DROP INDEX IF EXISTS idx_console_admins_username;
DROP TABLE IF EXISTS console_admins;
