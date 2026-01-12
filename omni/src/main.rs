mod wifi_direct;
mod discovery;
mod protocol;


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
    /// Scan for nearby devices (WiFi Direct)
    Scan {
        /// Network interface to use (auto-detects if not specified)
        #[arg(short, long)]
        interface: Option<String>,
    },
    /// Scan for Quick Share devices (BLE)
    ScanBle,
    /// Test UKEY2 Crypto Handshake (Debug)
    TestHandshake,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan { interface } => {
            let iface_name = match interface {
                Some(i) => i.clone(),
                None => WpaClient::auto_detect_interface()
                    .unwrap_or_else(|| "wlan0".to_string()),
            };

            println!("OmniShare - Scanning on {}...", iface_name);
            let client = WpaClient::new(&iface_name).context("Failed to initialize DBus client")?;
            
            // Start scan
            client.p2p_find()?;
            
            println!("Scanning for 5 seconds (DBus)...");
            thread::sleep(Duration::from_secs(5));

            let peers = client.p2p_peers()?;
            if peers.is_empty() {
                println!("No peers found yet. (Ensure Android 'Nearby Share' or 'WiFi Direct' is visible)");
            } else {
                println!("Found {} peers:", peers.len());
                for peer in peers {
                    println!("  - {}", peer);
                }
            }
        },
        Commands::ScanBle => {
            println!("Starting Quick Share BLE Discovery (Service: 0xFEF3)...");
            discovery::ble::scan_for_quick_share().await?;
        },
        Commands::TestHandshake => {
            println!("Initializing UKEY2 Secure Session...");
            use protocol::ukey2_engine::Ukey2Session;
            
            let session = Ukey2Session::new()?;
            println!("Curve25519 Key Pair Generated.");
            
            let client_init = session.generate_client_init();
            println!("Generated ClientInit Message:");
            println!("   - Version: {:?}", client_init.version);
            println!("   - Random (Nonce): {} bytes", client_init.random.as_ref().map(|r| r.len()).unwrap_or(0));
            println!("   - Next Protocol: {:?}", client_init.next_protocol);
            println!("   - Cipher Commitments: {:?}", client_init.cipher_commitments);
            
            println!("Crypto Engine is Ready!");
        }
    }
    Ok(())
}
