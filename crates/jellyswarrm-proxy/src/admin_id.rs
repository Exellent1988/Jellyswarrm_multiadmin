use serde::{Deserialize, Serialize};

/// Identifies a console admin (a proxy operator account, distinct from the
/// per-server upstream Jellyfin admin credentials tracked in `server_admins`).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdminId(i64);

impl AdminId {
    pub fn new(value: i64) -> Self {
        Self(value)
    }

    pub fn as_i64(self) -> i64 {
        self.0
    }
}

impl std::fmt::Display for AdminId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
