//! OmniShare CLI Application
//!
//! Command-line interface for the OmniShare file transfer service.

use clap::{Parser, Subcommand};
use omni_core::{discovery, connection_manager::ConnectionManager, generate_endpoint_id};

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
    Run,
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
        Commands::Run => {
            println!("Starting OmniShare Native Service...");
            
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
                
                // TCP Server
                ConnectionManager::start_server()
            );
        },
        Commands::Connect { ip } => {
            println!("Connecting to {}...", ip);
            // TODO: Implement outbound connection
        }
    }
    Ok(())
}
