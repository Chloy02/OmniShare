//! Role management for UKEY2 protocol
//!
//! Defines whether we are acting as a Client (initiating connection)
//! or Server (receiving connection) to ensure proper key assignment.

/// Represents the role in a UKEY2 connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Server role - receiving incoming connection (Android → Linux)
    Server,
    /// Client role - initiating outbound connection (Linux → Android)
    Client,
}

impl Role {
    /// Returns true if this is the server role
    pub fn is_server(&self) -> bool {
        matches!(self, Role::Server)
    }

    /// Returns true if this is the client role
    pub fn is_client(&self) -> bool {
        matches!(self, Role::Client)
    }
}
