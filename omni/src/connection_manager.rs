use crate::wifi_direct::WpaClient;
use crate::protocol::ukey2_engine::Ukey2Session;
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

pub struct ConnectionManager;

impl ConnectionManager {
    /// The main entry point to "Connect" to a Quick Share device.
    /// 1. Scans for BLE (to get Endpoint ID)
    /// 2. Initiates WiFi Direct Connection
    /// 3. Performs UKEY2 Handshake
    pub async fn initiate_connection(interface: &str) -> Result<()> {
        println!("Initiating Quick Share Connection on {}...", interface);

        // Step 1: Find the Target (Simulated for now, normally we'd pick one from BLE)
        // In a real scenario, scan_for_quick_share would return the Endpoint ID.
        // For this phase, we assume the user finds it visually or we automate the selection.
        println!("Scanning for target...");
        // scan_for_quick_share().await?; 

        // Step 2: Connect via WiFi Direct
        let client = WpaClient::new(interface)?;
        println!("Requesting WiFi Direct Connection...");
        client.p2p_find()?;
        
        // Wait for discovery (WiFi Direct scanning takes time)
        println!("Waiting 10 seconds for peers to appear...");
        sleep(Duration::from_secs(10)).await;
        
        let peers = client.p2p_peers()?;
        if let Some(first_peer) = peers.first() {
             // Extract MAC address from our formatted string "AA:BB:CC... (Name)"
             let peer_addr = first_peer.split_whitespace().next().unwrap_or("");
             println!("Connecting to Peer: {}", peer_addr);
             
             client.p2p_connect(peer_addr)?; 
        } else {
            println!("No peers found to connect to.");
            return Ok(());
        }

        // Step 3: UKEY2 Handshake (Simulation)
        // If we had a TCP Stream here, we would write the ClientInit message
        let session = Ukey2Session::new()?;
        let _client_init = session.generate_client_init();
        println!("Prepared UKEY2 ClientInit (Ready to send).");

        Ok(())
    }
}
