mod discovery;
mod connection_manager;
pub mod proto;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "omni")]
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
            
            // Phase 2 (mDNS Native) - Start Background Daemon
            // Port 5200 is standard for Quick Share (though it can be dynamic)
            let _mdns = discovery::mdns_native::MdnsService::start("OmniShare", 5200)?;

            println!("Starting BLE and TCP Services concurrently...");
            let _ = tokio::join!(
                // Phase 1 (BLE Native) - The "Shout"
                discovery::ble_native::run_forever(),
                
                // Phase 2 (TCP Server) - The "Ear"
                connection_manager::ConnectionManager::start_server()
            );
        },
        Commands::Connect { ip } => {
            println!("Connecting to {}...", ip);
            // TODO: Implement Phase 3 (UKEY2 Handshake)
        }
    }
    Ok(())
}
