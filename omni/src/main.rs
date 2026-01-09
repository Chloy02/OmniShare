mod wifi_direct;
use clap::{Parser, Subcommand};
use wifi_direct::WpaClient;
use std::thread;
use std::time::Duration;
use anyhow::Context;

#[derive(Parser)]
#[command(name = "omni")]
#[command(about = "OmniShare - Cross-Platform Resource Sharing", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for nearby devices
    Scan {
        /// Network interface to use (auto-detects if not specified)
        #[arg(short, long)]
        interface: Option<String>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { interface } => {
            let iface_name = match interface {
                Some(i) => i.clone(),
                None => WpaClient::auto_detect_interface()
                    .unwrap_or_else(|| "wlan0".to_string()),
            };

            println!("🔗 OmniShare - Scanning on {}...", iface_name);
            let client = WpaClient::new(&iface_name).context("Failed to initialize DBus client")?;
            
            // Start scan
            client.p2p_find()?;
            
            println!("Scanning for 5 seconds (DBus)...");
            thread::sleep(Duration::from_secs(5));

            let peers = client.p2p_peers()?;
            if peers.is_empty() {
                println!("No peers found yet. (Ensure Android 'Nearby Share' or 'WiFi Direct' is visible)");
            } else {
                println!("📡 Found {} peers:", peers.len());
                for peer in peers {
                    println!("  - {}", peer);
                }
            }
        }
    }
    Ok(())
}
