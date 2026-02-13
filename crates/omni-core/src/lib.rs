//! OmniShare Core Library
//! 
//! This crate provides the core protocol implementation for Quick Share,
//! enabling file transfer between Linux and Android devices.

pub mod discovery;
pub mod connection_manager;
pub mod security;
pub mod proto;
pub mod transfer;

// Re-export main types for convenience
pub use connection_manager::ConnectionManager;

/// Configuration for the OmniShare service
#[derive(Debug, Clone)]
pub struct Config {
    /// Directory where received files are saved
    pub download_dir: std::path::PathBuf,
    /// Device name shown to other devices
    pub device_name: String,
    /// TCP port for Quick Share connections
    pub port: u16,
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            download_dir: std::path::PathBuf::from(format!("{}/Downloads", home)),
            device_name: "OmniShare".to_string(),
            port: 5200,
        }
    }
}

/// Information about an incoming file transfer request
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Unique identifier for this transfer
    pub id: i64,
    /// Name of the sending device
    pub sender_name: String,
    /// Files being transferred
    pub files: Vec<FileInfo>,
}

/// Information about a single file in a transfer
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Filename
    pub name: String,
    /// File size in bytes
    pub size: u64,
    /// MIME type
    pub mime_type: String,
    /// Internal payload ID (for protocol tracking)
    pub payload_id: i64,
}

use async_trait::async_trait;

/// Delegate trait for handling user interaction during file transfer negotiation
#[async_trait]
pub trait TransferDelegate: Send + Sync {
    /// Called when an incoming file transfer request is received (Introduction Level).
    /// Returns `true` to accept the transfer, `false` to reject it.
    async fn on_transfer_request(&self, request: TransferRequest) -> bool;

    /// Called periodically during file transfer to report progress.
    /// `payload_id` matches the ID from the FileInfo in TransferRequest.
    async fn on_transfer_progress(&self, payload_id: i64, current_bytes: u64, total_bytes: u64);
}

/// Generate a random endpoint ID for device identification
pub fn generate_endpoint_id() -> String {
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(4)
        .map(char::from)
        .collect()
}
