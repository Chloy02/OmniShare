//! OmniShare CLI Application
//!
//! Command-line interface for the OmniShare file transfer service.

use clap::{Parser, Subcommand};
use omni_core::{discovery, connection_manager::ConnectionManager, generate_endpoint_id, Config, TransferDelegate, TransferRequest};
use async_trait::async_trait;
use std::sync::Arc;
use std::path::PathBuf;
use std::time::Duration;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::sync::Mutex;
use std::collections::HashMap;

#[derive(Parser)]
#[command(name = "omnishare")]
#[command(about = "OmniShare - Zero-Install Linux Client for Quick Share", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Quick Share Discovery Service (BLE Advertisement)
    Run {
        /// Directory to save received files (default: ~/Downloads)
        #[arg(long, short = 'd')]
        download_dir: Option<PathBuf>,
    },
    /// Send files to nearby devices
    Send {
        /// Files to send
        #[arg(long, short = 'f', required = true)]
        file: Vec<PathBuf>,
    },
    /// Manually trigger a connection (Debug)
    Connect {
        /// Target IP address
        #[arg(long)]
        ip: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { download_dir } => {
            println!("Starting OmniShare Native Service...");
            
            // Use provided download dir or default from Config
            let config = Config::default();
            let download_path = download_dir.clone().unwrap_or(config.download_dir);
            
            // Ensure download directory exists
            if !download_path.exists() {
                std::fs::create_dir_all(&download_path)?;
                println!("Created download directory: {}", download_path.display());
            }
            
            // Generate shared Endpoint ID for both BLE and mDNS
            // The phone validates that these match to prevent spoofing
            let endpoint_id = generate_endpoint_id();
            println!("Generated Shared Endpoint ID: {}", endpoint_id);
            
            // Start mDNS Service
            let _mdns = discovery::mdns_native::MdnsService::start("OmniShare", 5200, &endpoint_id)?;

            println!("Starting BLE and TCP Services concurrently...");
            let endpoint_id_clone = endpoint_id.clone();
            let _ = tokio::join!(
                // BLE Advertisement
                discovery::ble_native::run_forever(endpoint_id_clone),
                
                // TCP Server with custom download directory
                ConnectionManager::start_server(download_path, Some(Arc::new(ConsoleDelegate::new())))
            );
        },
        Commands::Send { file } => {
            println!("📤 OmniShare File Sender");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━");
            
            // Validate files exist
            for f in file {
                if !f.exists() {
                    println!("❌ File not found: {}", f.display());
                    return Ok(());
                }
                println!("   📁 {}", f.display());
            }
            
            // Discover nearby devices
            println!();
            let devices = discovery::scanner::discover_devices(Duration::from_secs(5)).await?;
            
            if devices.is_empty() {
                println!("❌ No Quick Share devices found nearby.");
                println!("   Make sure the Android device has Quick Share enabled and is nearby.");
                return Ok(());
            }
            
            // Display device list
            println!();
            println!("📱 Nearby Devices:");
            for (i, device) in devices.iter().enumerate() {
                println!("   [{}] {} ({})", i + 1, device.name, device.ip);
            }
            
            // For now, auto-select first device (TODO: interactive selection)
            let target = &devices[0];
            println!();
            println!("🎯 Connecting to: {}", target.name);
            
            // Send files
            omni_core::transfer::outbound::send_files(
                target.clone(),
                file.clone(),
                "OmniShare",
            ).await?;
        },
        Commands::Connect { ip } => {
            println!("Connecting to {}...", ip);
            // TODO: Implement manual outbound connection
        }
    }
    Ok(())
}

struct ConsoleDelegate {
    multi: MultiProgress,
    bars: Mutex<HashMap<i64, ProgressBar>>,
}

impl ConsoleDelegate {
    fn new() -> Self {
        Self {
            multi: MultiProgress::new(),
            bars: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl TransferDelegate for ConsoleDelegate {
    async fn on_transfer_request(&self, request: TransferRequest) -> bool {
        println!("\n╔════════════════════════════════════════════════════╗");
        println!("║       📥 INCOMING FILE TRANSFER REQUEST            ║");
        println!("╠════════════════════════════════════════════════════╣");
        println!("║ From: {:<44} ║", request.sender_name);
        for file in &request.files {
           println!("║ 📁 {:<46} ║", file.name);
           println!("║    {:<46} ║", format!("{} bytes", file.size));
        }
        println!("╚════════════════════════════════════════════════════╝");
        println!("✅ Auto-accepting (CLI mode)");
        true
    }

    async fn on_transfer_progress(&self, payload_id: i64, current_bytes: u64, total_bytes: u64) {
        let mut bars = self.bars.lock().expect("Failed to lock progress bars");
        
        let bar = bars.entry(payload_id).or_insert_with(|| {
            let pb = self.multi.add(ProgressBar::new(total_bytes));
            pb.set_style(ProgressStyle::default_bar()

                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap()
                .progress_chars("#>-"));
            pb.set_message(format!("File {}", payload_id));
            pb
        });

        bar.set_position(current_bytes);

        if current_bytes >= total_bytes && total_bytes > 0 {
            bar.finish_with_message("Done");
            // Remove from map to clean up? For now, we leave it to show "Done".
            // If we remove it, we can't update it to "Done" effectively if called again.
        }
    }
}
