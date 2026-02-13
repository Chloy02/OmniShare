// Tauri commands - API for frontend to interact with omni-core
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;
use omni_core::{discovery, connection_manager::ConnectionManager, generate_endpoint_id, TransferDelegate};
use std::path::PathBuf;
use std::collections::HashMap;
use tauri::{Emitter, AppHandle};
use async_trait::async_trait;

/// Transfer request notification for frontend
#[derive(Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub id: String,
    pub sender_name: String,
    pub files: Vec<FileInfo>,
    pub total_size: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub mime_type: String,
}

/// Transfer progress update
#[derive(Clone, Serialize, Deserialize)]
pub struct TransferProgress {
    pub id: String,
    pub progress: f32,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub speed_bps: u64,
}

/// Transfer record for history
#[derive(Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub id: String,
    pub sender_name: String,
    pub file_name: String,
    pub file_size: u64,
    pub status: String, // "success", "failed", "cancelled"
    pub timestamp: String,
}

/// Application settings
#[derive(Clone, Serialize, Deserialize)]
pub struct Settings {
    pub save_location: String,
    pub device_name: String,
    pub auto_accept: bool,
    pub visible: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            save_location: dirs::download_dir()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            device_name: "OmniShare".to_string(),
            auto_accept: false,
            visible: true,
        }
    }
}

// App state managed by Tauri
pub struct AppState {
    pub is_running: bool,
    pub settings: Settings,
    pub pending_transfers: Vec<TransferRequest>,
    pub transfer_history: Vec<TransferRecord>,
    pub service_abort_handle: Option<tokio::task::AbortHandle>,
    pub transfer_confirmations: HashMap<i64, tokio::sync::oneshot::Sender<bool>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            is_running: false,
            settings: Settings::default(),
            pending_transfers: Vec::new(),
            transfer_history: Vec::new(),
            service_abort_handle: None,
            transfer_confirmations: HashMap::new(),
        }
    }
}

pub type SharedState = Arc<Mutex<AppState>>;

// ============ TAURI COMMANDS ============

/// Start the receiver (BLE advertising + TCP listener)
#[tauri::command]
pub async fn start_receiver(app: AppHandle, state: State<'_, SharedState>) -> Result<String, String> {
    let mut app_state = state.lock().await;
    if app_state.is_running {
        return Ok("Already running".to_string());
    }

    // Get configuration
    let download_dir = PathBuf::from(&app_state.settings.save_location);
    if !download_dir.exists() {
        std::fs::create_dir_all(&download_dir).map_err(|e| e.to_string())?;
    }
    
    let device_name = app_state.settings.device_name.clone();

    // Spawn the service task
    let app_handle = app.clone();
    let state_clone = state.inner().clone();
    let handle = tokio::spawn(async move {
        println!("GUI: Starting OmniShare Services...");
        
        let endpoint_id = generate_endpoint_id();
        println!("GUI: Generated Endpoint ID: {}", endpoint_id);

        // Start mDNS
        // Note: keeping _mdns alive is crucial
        let _mdns = match discovery::mdns_native::MdnsService::start(&device_name, 5200, &endpoint_id) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("GUI: Failed to start mDNS: {}", e);
                return;
            }
        };

        println!("GUI: Starting BLE and TCP...");
        let endpoint_id_clone = endpoint_id.clone();
        
        // Create delegate
        let delegate = Arc::new(TauriTransferDelegate {
            app: app_handle,
            state: state_clone,
        });

        // Run BLE and TCP concurrently
        let _ = tokio::join!(
            discovery::ble_native::run_forever(endpoint_id_clone),
            ConnectionManager::start_server(download_dir, Some(delegate))
        );
    });

    app_state.is_running = true;
    app_state.service_abort_handle = Some(handle.abort_handle());
    
    Ok("Receiver started".to_string())
}

/// Stop the receiver
#[tauri::command]
pub async fn stop_receiver(state: State<'_, SharedState>) -> Result<String, String> {
    let mut app_state = state.lock().await;
    
    if let Some(handle) = app_state.service_abort_handle.take() {
        handle.abort();
        println!("GUI: Receiver service aborted.");
    }
    
    app_state.is_running = false;
    Ok("Receiver stopped".to_string())
}

/// Check if receiver is running
#[tauri::command]
pub async fn is_receiver_running(state: State<'_, SharedState>) -> Result<bool, String> {
    let app_state = state.lock().await;
    Ok(app_state.is_running)
}

/// Accept a pending transfer
#[tauri::command]
pub async fn accept_transfer(
    transfer_id: String,
    state: State<'_, SharedState>,
) -> Result<String, String> {
    let mut app_state = state.lock().await;
    
    // Convert string ID back to i64
    if let Ok(id) = transfer_id.parse::<i64>() {
        if let Some(sender) = app_state.transfer_confirmations.remove(&id) {
            let _ = sender.send(true);
            return Ok(format!("Transfer {} accepted", transfer_id));
        }
    }
    
    Err("Transfer request not found or invalid ID".to_string())
}

/// Reject a pending transfer
#[tauri::command]
pub async fn reject_transfer(
    transfer_id: String,
    state: State<'_, SharedState>,
) -> Result<String, String> {
    let mut app_state = state.lock().await;
    
    // Convert string ID back to i64
    if let Ok(id) = transfer_id.parse::<i64>() {
        if let Some(sender) = app_state.transfer_confirmations.remove(&id) {
            let _ = sender.send(false);
            return Ok(format!("Transfer {} rejected", transfer_id));
        }
    }
    
    Err("Transfer request not found or invalid ID".to_string())
}

struct TauriTransferDelegate {
    app: AppHandle,
    state: SharedState,
}

#[async_trait]
impl TransferDelegate for TauriTransferDelegate {
    async fn on_transfer_request(&self, request: omni_core::TransferRequest) -> bool {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let request_id = request.id; // request.id is already i64
        
        // 1. Store the channel sender
        {
            let mut state = self.state.lock().await;
            state.transfer_confirmations.insert(request_id, tx);
        }
        
        // 2. Emit event to frontend
        // Convert to GUI-friendly struct
        let gui_files: Vec<FileInfo> = request.files.iter().map(|f| FileInfo {
            name: f.name.clone(),
            size: f.size,
            mime_type: f.mime_type.clone(),
        }).collect();
        
        let gui_req = TransferRequest {
            id: request.id.to_string(), // Convert i64 to String for JS
            sender_name: request.sender_name,
            files: gui_files,
            total_size: request.files.iter().map(|f| f.size).sum(),
        };
        
        println!("GUI: Emitting 'transfer-request' event for ID: {}", request_id);
        if let Err(e) = self.app.emit("transfer-request", &gui_req) {
            eprintln!("GUI: Failed to emit event: {}", e);
        }
        
        // 3. Wait for response
        match rx.await {
            Ok(accepted) => {
                println!("GUI: User decision for {}: {}", request_id, if accepted { "ACCEPTED" } else { "REJECTED" });
                accepted
            },
            Err(_) => {
                println!("GUI: Response channel closed (timeout or error). Rejecting.");
                false
            }
        }
    }

    async fn on_transfer_progress(&self, payload_id: i64, current_bytes: u64, total_bytes: u64) {
        let percentage = if total_bytes > 0 {
            (current_bytes as f32 / total_bytes as f32) * 100.0
        } else {
            0.0
        };

        let progress = TransferProgress {
            id: payload_id.to_string(),
            progress: percentage,
            bytes_transferred: current_bytes,
            total_bytes,
            speed_bps: 0, 
        };

        println!("GUI: Emitting progress {}% for ID {} (Transferred: {}/{})", 
            percentage, payload_id, current_bytes, total_bytes);

        if let Err(e) = self.app.emit("transfer-progress", &progress) {
            eprintln!("GUI: Failed to emit progress event: {}", e);
        }
    }
}

/// Get pending transfer requests
#[tauri::command]
pub async fn get_pending_transfers(
    state: State<'_, SharedState>,
) -> Result<Vec<TransferRequest>, String> {
    let app_state = state.lock().await;
    Ok(app_state.pending_transfers.clone())
}

/// Get transfer history
#[tauri::command]
pub async fn get_transfer_history(
    state: State<'_, SharedState>,
) -> Result<Vec<TransferRecord>, String> {
    let app_state = state.lock().await;
    Ok(app_state.transfer_history.clone())
}

/// Get current settings
#[tauri::command]
pub async fn get_settings(state: State<'_, SharedState>) -> Result<Settings, String> {
    let app_state = state.lock().await;
    Ok(app_state.settings.clone())
}

/// Update save location
#[tauri::command]
pub async fn set_save_location(
    path: String,
    state: State<'_, SharedState>,
) -> Result<String, String> {
    let mut app_state = state.lock().await;
    app_state.settings.save_location = path.clone();
    Ok(format!("Save location set to: {}", path))
}

/// Update device name
#[tauri::command]
pub async fn set_device_name(
    name: String,
    state: State<'_, SharedState>,
) -> Result<String, String> {
    let mut app_state = state.lock().await;
    app_state.settings.device_name = name.clone();
    Ok(format!("Device name set to: {}", name))
}

/// Toggle visibility (BLE advertising)
#[tauri::command]
pub async fn set_visibility(
    visible: bool,
    state: State<'_, SharedState>,
) -> Result<String, String> {
    let mut app_state = state.lock().await;
    app_state.settings.visible = visible;
    // TODO: Start/stop BLE advertising
    Ok(format!("Visibility set to: {}", visible))
}
