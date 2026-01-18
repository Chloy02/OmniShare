use anyhow::Result;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;

pub struct ConnectionManager;

impl ConnectionManager {
    /// Starts the TCP Listener on Port 5200 (Standard Quick Share Port)
    pub async fn start_server() -> Result<()> {
        let addr = "0.0.0.0:5200";
        let listener = TcpListener::bind(addr).await?;
        println!("TCP Server: Listening for Quick Share connections on {}", addr);

        loop {
            // Accept new connection
            let (mut socket, peer_addr) = listener.accept().await?;
            println!("TCP Server: Incoming connection from {}", peer_addr);

            // Spawn a task to handle this connection so we don't block the listener
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(&mut socket).await {
                    eprintln!("TCP Server: Connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }

    /// Handles the connection lifecycle:
    /// 1. Read 4-byte length prefix.
    /// 2. Read Protobuf payload.
    /// 3. Decode ConnectionRequest.
    /// Handles the connection lifecycle:
    /// 1. Loop to read Frames.
    /// 2. Decode ConnectionRequest.
    /// 3. Decode UKEY2 Client Init.
    async fn handle_connection(socket: &mut tokio::net::TcpStream) -> Result<()> {
        println!("TCP Handler: Handler started.");

        loop {
            // --- Step 1: Read Transmission Length (4 Bytes Big Endian) ---
            let mut length_buf = [0u8; 4];
            
            // Wait for bytes (or EOF)
            match socket.read_exact(&mut length_buf).await {
                Ok(_) => {},
                Err(e) => {
                    // This is normal when client closes connection
                    println!("TCP Handler: Connection closed by client: {}", e);
                    return Ok(());
                }
            }

            let msg_len = u32::from_be_bytes(length_buf) as usize;
            println!("TCP Handler: 📦 Received Frame. Length: {} bytes", msg_len);

            // --- Step 2: Read The Payload ---
            let mut payload_buf = vec![0u8; msg_len];
            socket.read_exact(&mut payload_buf).await?;
            
            // --- Step 3: Decode Protobuf (Try OfflineFrame, then Ukey2Message) ---
            use prost::Message;
            use crate::proto::{quick_share::OfflineFrame, ukey2::Ukey2Message};

            // Attempt 1: OfflineFrame (e.g., ConnectionRequest)
            let mut decoded_something = false;
            
            if let Ok(frame) = OfflineFrame::decode(&payload_buf[..]) {
                if let Some(v1) = frame.v1 {
                    decoded_something = true;
                    println!("TCP Handler: ✅ Decoded OfflineFrame (Type: {:?})", v1.r#type);
                    
                    if let Some(req) = v1.connection_request {
                        println!("TCP Handler: 📱 CONNECTION REQUEST DETECTED");
                        // Clean up device name (sometimes has proto artifacts)
                        let raw_name = req.endpoint_name.unwrap_or_default();
                        println!("    -> Name: \"{}\" (Raw: {:?})", raw_name, raw_name.as_bytes());
                        println!("    -> ID: {:?}", req.endpoint_id);
                    }
                }
            }

            // Attempt 2: UKEY2 Message (e.g., ClientInit)
            if !decoded_something {
                if let Ok(ukey_msg) = Ukey2Message::decode(&payload_buf[..]) {
                    // Check if message_type is present and valid
                    if let Some(msg_type) = ukey_msg.message_type {
                         decoded_something = true;
                         println!("TCP Handler: 🔐 UKEY2 MESSAGE DETECTED (Type: {:?})", msg_type);
                         println!("    -> Data: {} bytes", ukey_msg.message_data.as_ref().map_or(0, |d| d.len()));
                         
                         // If this is CLIENT_INIT (2), we need to extract the "Commitment" inside
                         if msg_type == crate::proto::ukey2::ukey2_message::Type::ClientInit.into() {
                             println!("TCP Handler: 🚀 This is the Key Exchange Init! We need to reply!");
                         }
                    }
                }
            }

            if !decoded_something {
                println!("TCP Handler: ❌ Unknown Packet Format. Raw Hex: {}", hex::encode(&payload_buf));
            }
        }
    }
}
