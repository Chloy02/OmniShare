use anyhow::Result;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use std::sync::Arc;
use crate::{TransferDelegate, TransferRequest, FileInfo};


pub struct ConnectionManager;

impl ConnectionManager {
    /// Connects TO a discovered phone (reverse connection)
    #[allow(dead_code)] // Suppress unused warning
    pub async fn connect_to_phone(target: &str) -> Result<()> {
        use tokio::net::TcpStream;
        
        println!("REVERSE: Connecting to phone at {}...", target);
        
        match TcpStream::connect(target).await {
            Ok(mut socket) => {
                println!("REVERSE: Connection established! Starting handshake...");
                // Use default Downloads directory for reverse connections
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                let download_dir = std::path::PathBuf::from(format!("{}/Downloads", home));
                if let Err(e) = Self::handle_connection(&mut socket, download_dir, None).await {
                    eprintln!("REVERSE: Handshake failed: {}", e);
                }
                Ok(())
            },
            Err(e) => {
                eprintln!("REVERSE: TCP connection failed: {}", e);
                Err(e.into())
            }
        }
    }

    /// Starts the TCP Listener on Port 5200 (Standard Quick Share Port)
    pub async fn start_server(download_dir: std::path::PathBuf, delegate: Option<Arc<dyn TransferDelegate>>) -> Result<()> {
        let addr = "0.0.0.0:5200";
        let listener = TcpListener::bind(addr).await?;
        println!("TCP Server: Listening for Quick Share connections on {}", addr);
        println!("TCP Server: Download directory: {}", download_dir.display());

        loop {
            // Accept new connection
            let (mut socket, peer_addr) = listener.accept().await?;
            println!("TCP Server: Incoming connection from {}", peer_addr);

            // Spawn a task to handle this connection so we don't block the listener
            let download_dir_clone = download_dir.clone();
            let delegate_clone = delegate.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(&mut socket, download_dir_clone, delegate_clone).await {
                    eprintln!("TCP Server: Connection error from {}: {}", peer_addr, e);
                }
            });
        }
    }

    /// Handles the connection lifecycle:
    /// 1. Loop to read Frames.
    /// 2. Decode ConnectionRequest.
    /// 3. Decode UKEY2 Client Init.
    /// 2. Decode ConnectionRequest.
    /// 3. Decode UKEY2 Client Init.
    async fn handle_connection(socket: &mut tokio::net::TcpStream, download_dir: std::path::PathBuf, delegate: Option<Arc<dyn TransferDelegate>>) -> Result<()> {
        println!("TCP Handler: Handler started.");
        let mut _remote_handshake_data: Option<Vec<u8>> = None;
        let mut remote_device_name = String::new();

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
                    println!("TCP Handler: Decoded OfflineFrame (Type: {:?})", v1.r#type);
                    
                    if let Some(req) = v1.connection_request {
                        println!("TCP Handler: 📱 CONNECTION REQUEST DETECTED");
                        // Clean up device name (sometimes has proto artifacts)
                        let raw_name = req.endpoint_name.clone().unwrap_or_default();
                        remote_device_name = raw_name.clone();
                        println!("    -> Name: \"{}\" (Raw: {:?})", raw_name, raw_name.as_bytes());
                        println!("    -> ID: {:?}", req.endpoint_id);
                        
                        if let Some(hd) = req.handshake_data {
                            println!("TCP Handler: 📱 Handshake Data Captured! ({} bytes)", hd.len());
                            _remote_handshake_data = Some(hd);
                        } else {
                            println!("TCP Handler: ⚠️ No Handshake Data in Request.");
                        }
                    }
                }
            }

            // Attempt 2: UKEY2 Message (e.g., ClientInit)
            if !decoded_something {
                if let Ok(ukey_msg) = Ukey2Message::decode(&payload_buf[..]) {
                    if let Some(msg_type) = ukey_msg.message_type {
                         decoded_something = true;
                         println!("TCP Handler: UKEY2 MESSAGE DETECTED (Type: {:?})", msg_type);
                         
                         let msg_type_enum = crate::proto::ukey2::ukey2_message::Type::try_from(msg_type).ok();

                         // --- HANDSHAKE STATE MACHINE ---
                         if msg_type_enum == Some(crate::proto::ukey2::ukey2_message::Type::ClientInit) {
                             println!("TCP Handler: Processing CLIENT_INIT...");
                             
                             // 1. Initialize Server (in real app, do this once)
                             use crate::security::ukey2::Ukey2Server;
                             use tokio::io::AsyncWriteExt;
                             
                             let server = Ukey2Server::new().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                             
                             // Pass FULL Ukey2Message bytes for Transcript context
                             match server.handle_client_init(&payload_buf) {
                                  Ok((reply_bytes, pending)) => {
                                         // Send Reply
                                         let len_prefix = (reply_bytes.len() as u32).to_be_bytes();
                                         socket.write_all(&len_prefix).await?;
                                         socket.write_all(&reply_bytes).await?;
                                         println!("TCP Handler: Sent UKEY2 Server Init!");
                                         println!("TCP Handler: Waiting for CLIENT_FINISHED...");
                                         
                                         // --- NESTED READ FOR PACKET 3 ---
                                          let mut length_buf = [0u8; 4];
                                          socket.read_exact(&mut length_buf).await?;
                                          let msg_len = u32::from_be_bytes(length_buf) as usize;
                                          let mut payload_buf_3 = vec![0u8; msg_len];
                                          socket.read_exact(&mut payload_buf_3).await?;
                                          
                                          println!("TCP Handler: Packet 3 (Raw): {}", hex::encode(&payload_buf_3));

                                          let msg3 = Ukey2Message::decode(&payload_buf_3[..])?;
                                          if msg3.message_type == Some(crate::proto::ukey2::ukey2_message::Type::ClientFinished.into()) {
                                              println!("TCP Handler: RECEIVED CLIENT_FINISHED!");
                                              if let Some(fin_data) = &msg3.message_data {
                                                  let keys = pending.handle_client_finished(fin_data)
                                                      .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                                                  
                                                  println!("TCP Handler: Handshake Complete! Keys Derived.");
                                                  println!("    -> Auth String: {}", hex::encode(&keys.auth_string));
                                                  println!("    -> D2D Client Key: {}", hex::encode(&keys.d2d_client_key));
                                                  println!("    -> D2D Server Key: {}", hex::encode(&keys.d2d_server_key));
                                                  
                                                  // Handshake Done.
                                                  // --- Step 4: Send Connection Response (Plaintext) ---
                                                  println!("TCP Handler: Sending ConnectionResponse (ACCEPT)...");
                                                  
                                                  let response = crate::proto::quick_share::ConnectionResponse {
                                                      response: Some(crate::proto::quick_share::connection_response::ResponseStatus::Accept.into()),
                                                      os_info: Some(crate::proto::quick_share::OsInfo {
                                                          r#type: Some(crate::proto::quick_share::os_info::OsType::Linux.into()),
                                                      }),
                                                      multiplex_socket_bitmask: Some(0),
                                                      safe_to_disconnect_version: Some(1),
                                                      ..Default::default()
                                                  };

                                                  let frame_v1 = crate::proto::quick_share::V1Frame {
                                                      r#type: Some(crate::proto::quick_share::v1_frame::FrameType::ConnectionResponse.into()),
                                                      connection_response: Some(response),
                                                      ..Default::default()
                                                  };
                                                  let offline_frame = crate::proto::quick_share::OfflineFrame {
                                                      version: Some(1),
                                                      v1: Some(frame_v1),
                                                  };
                                                  
                                                  let mut resp_buf = Vec::new();
                                                  offline_frame.encode(&mut resp_buf)?;
                                                  
                                                  let len_prefix = (resp_buf.len() as u32).to_be_bytes();
                                                  socket.write_all(&len_prefix).await?;
                                                  socket.write_all(&resp_buf).await?;
                                                  println!("TCP Handler: Sent ConnectionResponse! Switching to Encrypted Mode.");

                                                  let engine = crate::security::engine::SecurityEngine::new(
                                                      &keys.decrypt_key,
                                                      &keys.encrypt_key,
                                                      &keys.receive_hmac_key,
                                                      &keys.send_hmac_key,
                                                  );
                                                  
                                                  // --- Step 4.5: Receive Client's Connection Response (Plaintext) ---
                                                  println!("TCP Handler: Waiting for Client's Plaintext ConnectionResponse...");
                                                  let mut cr_len_buf = [0u8; 4];
                                                  socket.read_exact(&mut cr_len_buf).await?;
                                                  let cr_len = u32::from_be_bytes(cr_len_buf) as usize;
                                                  let mut cr_buf = vec![0u8; cr_len];
                                                  socket.read_exact(&mut cr_buf).await?;
                                                  
                                                  // Decode just to verify (optional but good for debugging)
                                                  match crate::proto::quick_share::OfflineFrame::decode(&cr_buf[..]) {
                                                      Ok(frame) => {
                                                           if let Some(v1) = &frame.v1 {
                                                               println!("TCP Handler: Received Client Frame (Pre-Secure). Type: {:?}", v1.r#type);
                                                               if let Some(resp) = &v1.connection_response {
                                                                   println!("TCP Handler: 📱 Client ConnectionResponse: {:?}", resp.response);
                                                                    if let Some(data) = &resp.handshake_data {
                                                                        println!("TCP Handler: 📱 Client sent handshake_data: {} bytes", data.len());
                                                                    }
                                                                   // Check ResponseStatus::Accept (1)
                                                                   if resp.response != Some(1) { 
                                                                       println!("TCP Handler: ⚠️ WARNING: Client did not ACCEPT! Response: {:?}", resp.response);
                                                                   }
                                                               }
                                                           }
                                                      },
                                                      Err(e) => println!("TCP Handler: Failed to decode pre-secure frame: {:?}", e),
                                                  }
                                                  
                                                  println!("TCP Handler: Client Response received. Entering Secure Mode.");
                                                  
                                                  // --- Step 4.6: Send PairedKeyEncryption (Direct V1Packet) ---
                                                  println!("TCP Handler: Sending PairedKeyEncryption...");
                                                  
                                                  // Per PROTOCOL.md line 206: "I set secretIDHash to 6 random bytes and signedData to 72 random bytes"
                                                  use rand::Rng;
                                                  let mut secret_id_hash = vec![0u8; 6];
                                                  rand::thread_rng().fill(&mut secret_id_hash[..]);
                                                  let mut signed_data = vec![0u8; 72];
                                                  rand::thread_rng().fill(&mut signed_data[..]);
                                                  
                                                  // Use wire_format (Sharing Frame) for the Encrypted Layer
                                                  let pke = crate::proto::wire_format::PairedKeyEncryptionFrame {
                                                      signed_data: Some(signed_data),
                                                      secret_id_hash: Some(secret_id_hash),
                                                      optional_signed_data: None,
                                                      qr_code_handshake_data: None,
                                                  };

                                                  let pke_frame_v1 = crate::proto::wire_format::V1Frame {
                                                      r#type: Some(crate::proto::wire_format::v1_frame::FrameType::PairedKeyEncryption.into()),
                                                      paired_key_encryption: Some(pke),
                                                      ..Default::default()
                                                  };
                                                  
                                                  let pke_sharing_frame = crate::proto::wire_format::Frame {
                                                      version: Some(crate::proto::wire_format::frame::Version::V1.into()),
                                                      v1: Some(pke_frame_v1),
                                                  };
                                                  
                                                  // Serialize the Sharing Frame
                                                  let mut pke_buf = Vec::new();
                                                  pke_sharing_frame.encode(&mut pke_buf)?;
                                                  let pke_buf_len = pke_buf.len() as i64;
                                                  
                                                  // Initialize server sequence number
                                                  let mut server_seq_num = 1;

                                                  // Generate a random payload ID for this transfer
                                                  let payload_id: i64 = rand::random();
                                                  
                                                  // Wrap in PayloadTransfer (OfflineFrame Type 3) per PROTOCOL.md line 202
                                                  let payload_header = crate::proto::quick_share::payload_transfer::PayloadHeader {
                                                      id: Some(payload_id),
                                                      r#type: Some(crate::proto::quick_share::payload_transfer::payload_header::PayloadType::Bytes.into()),
                                                      total_size: Some(pke_buf_len),
                                                      is_sensitive: Some(false),
                                                      ..Default::default()
                                                  };
                                                  
                                                  let payload_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                      flags: Some(0), // Not the last chunk yet
                                                      offset: Some(0),
                                                      body: Some(pke_buf),
                                                  };
                                                  
                                                  let payload_transfer = crate::proto::quick_share::PayloadTransfer {
                                                      packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                      payload_header: Some(payload_header.clone()),
                                                      payload_chunk: Some(payload_chunk),
                                                      control_message: None,
                                                  };
                                                  
                                                  let offline_frame = crate::proto::quick_share::OfflineFrame {
                                                      version: Some(1),
                                                      v1: Some(crate::proto::quick_share::V1Frame {
                                                          r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                          payload_transfer: Some(payload_transfer),
                                                          ..Default::default()
                                                      }),
                                                  };
                                                  
                                                  let mut offline_buf = Vec::new();
                                                  offline_frame.encode(&mut offline_buf)?;
                                                  
                                                  // Wrap in DeviceToDeviceMessage
                                                  let d2d_msg = crate::proto::ukey2::DeviceToDeviceMessage {
                                                      sequence_number: Some(server_seq_num), 
                                                      message: Some(offline_buf),
                                                  };
                                                  server_seq_num += 1;
                                                  let mut d2d_buf = Vec::new();
                                                  d2d_msg.encode(&mut d2d_buf)?;
                                                  
                                                  // Create GcmMetadata for the SecureMessage Header
                                                  let gcm_meta = crate::proto::ukey2::GcmMetadata {
                                                      r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(), // Type 13
                                                      version: Some(1),
                                                  };
                                                  let mut meta_bytes = Vec::new();
                                                  gcm_meta.encode(&mut meta_bytes)?;
                                                  
                                                  // Encrypt and send the DATA frame
                                                  let encrypted_pke = engine.encrypt_and_sign(&d2d_buf, Some(&meta_bytes))?;
                                                  println!("TCP Handler: Encrypted PKE PayloadTransfer Frame size: {}", encrypted_pke.len());
                                                  
                                                  let pke_len_prefix = (encrypted_pke.len() as u32).to_be_bytes();
                                                  socket.write_all(&pke_len_prefix).await?;
                                                  socket.write_all(&encrypted_pke).await?;
                                                  println!("TCP Handler: Sent PKE in PayloadTransfer (data frame)!");
                                                  
                                                  // Send the END marker (second frame with LAST_CHUNK flag, no body)
                                                  let end_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                      flags: Some(1), // LAST_CHUNK
                                                      offset: Some(pke_buf_len),
                                                      body: None,
                                                  };
                                                  
                                                  let end_payload_transfer = crate::proto::quick_share::PayloadTransfer {
                                                      packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                      payload_header: Some(payload_header),
                                                      payload_chunk: Some(end_chunk),
                                                      control_message: None,
                                                  };
                                                  
                                                  let end_offline_frame = crate::proto::quick_share::OfflineFrame {
                                                      version: Some(1),
                                                      v1: Some(crate::proto::quick_share::V1Frame {
                                                          r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                          payload_transfer: Some(end_payload_transfer),
                                                          ..Default::default()
                                                      }),
                                                  };
                                                  
                                                  let mut end_buf = Vec::new();
                                                  end_offline_frame.encode(&mut end_buf)?;
                                                  
                                                  let d2d_end = crate::proto::ukey2::DeviceToDeviceMessage {
                                                      sequence_number: Some(server_seq_num), 
                                                      message: Some(end_buf),
                                                  };
                                                  server_seq_num += 1;
                                                  let mut d2d_end_buf = Vec::new();
                                                  d2d_end.encode(&mut d2d_end_buf)?;
                                                  
                                                  let encrypted_end = engine.encrypt_and_sign(&d2d_end_buf, Some(&meta_bytes))?;
                                                  let end_len_prefix = (encrypted_end.len() as u32).to_be_bytes();
                                                  socket.write_all(&end_len_prefix).await?;
                                                  socket.write_all(&encrypted_end).await?;
                                                  println!("TCP Handler: Sent PKE END marker!");

                                                  // Now we listen for the Client's encrypted reply
                                                  println!("TCP Handler: Listening for Client's Encrypted Frames...");
                                                  // Read loop for secure messages
                                                  
                                                  // File transfer state tracking
                                                  use std::collections::HashMap;
                                                  
                                                  // Maps payload_id -> (filename, expected_size)
                                                  let mut file_metadata_map: HashMap<i64, (String, i64)> = HashMap::new();
                                                  // Maps payload_id -> accumulated bytes
                                                  let mut file_buffers: HashMap<i64, Vec<u8>> = HashMap::new();
                                                  
                                                  loop {
                                                      let mut length_buf = [0u8; 4];
                                                      if let Err(_) = socket.read_exact(&mut length_buf).await {
                                                           println!("TCP Handler: Connection closed/EOF in Secure Loop.");
                                                           break;
                                                      }
                                                      let msg_len = u32::from_be_bytes(length_buf) as usize;
                                                      if msg_len == 0 { continue; }
                                                      
                                                      let mut enc_buf = vec![0u8; msg_len];
                                                      socket.read_exact(&mut enc_buf).await?;
                                                      println!("TCP Handler: 🔒 Received Encrypted Frame. Length: {}", msg_len);
                                                      
                                                      match engine.verify_and_decrypt(&enc_buf) {
                                                          Ok(decrypted_payload) => {
                                                              println!("TCP Handler: 🔓 Decrypted successfully! {} bytes.", decrypted_payload.len());
                                                              let d2d_msg = match crate::proto::ukey2::DeviceToDeviceMessage::decode(&decrypted_payload[..]) {
                                                                  Ok(m) => m,
                                                                  Err(e) => {
                                                                      println!("TCP Handler: Failed to decode DeviceToDeviceMessage: {:?}", e);
                                                                      continue;
                                                                  }
                                                              };
                                                              
                                                              if let Some(inner_msg) = d2d_msg.message {
                                                                  println!("TCP Handler: Decoded D2D Message (Seq: {:?}). Processing inner Sharing Frame...", d2d_msg.sequence_number);
                                                                  
                                                                  // TRY DECODING AS WIRE_FORMAT FRAME (Sharing Frame)
                                                                  let mut decoded_sharing_frame: Option<crate::proto::wire_format::Frame> = None;

                                                                  // Strategy 1: Direct Decoding
                                                                  match crate::proto::wire_format::Frame::decode(&inner_msg[..]) {
                                                                      Ok(frame) => {
                                                                           println!("TCP Handler: Strategy 1 (Direct) Success.");
                                                                           decoded_sharing_frame = Some(frame);
                                                                      },
                                                                      Err(_e) => {
                                                                           // Log failure but don't spam if it's actually wrapped
                                                                           println!("TCP Handler: Strategy 1 Failed: {}", _e);
                                                                      }
                                                                  }
                                                                  
                                                                  if decoded_sharing_frame.is_none() {
                                                                      // Strategy 2: Unwrap from OfflineFrame (PayloadTransfer)
                                                                      println!("TCP Handler: RAW HEX (Decrypted D2D Msg): {}", hex::encode(&inner_msg));
                                                                      match crate::proto::quick_share::OfflineFrame::decode(&inner_msg[..]) {
                                                                          Ok(offline_frame) => {
                                                                              println!("TCP Handler: Strategy 2: Decoded OfflineFrame.");
                                                                              if let Some(v1_offline) = offline_frame.v1 {
                                                                                   // Check for PAYLOAD_TRANSFER (Type 3)
                                                                                   println!("TCP Handler: OfflineFrame Type: {:?}", v1_offline.r#type);
                                                                                   if v1_offline.r#type == Some(3) { // FrameType::PayloadTransfer
                                                                                       if let Some(pt) = v1_offline.payload_transfer {
                                                                                           // Log Header Details
                                                                                           if let Some(header) = &pt.payload_header {
                                                                                               println!("TCP Handler: PayloadHeader -> Type: {:?}, ID: {:?}, Size: {:?}, Sensitive: {:?}", 
                                                                                                    header.r#type, header.id, header.total_size, header.is_sensitive);
                                                                                           } else {
                                                                                               println!("TCP Handler: PayloadHeader is None");
                                                                                           }
                                                                                           
                                                                                           // Log Chunk Details
                                                                                           if let Some(chunk) = pt.payload_chunk {
                                                                                               println!("TCP Handler: PayloadChunk -> Flags: {:?}, Offset: {:?}, Body Len: {:?}", 
                                                                                                    chunk.flags, chunk.offset, chunk.body.as_ref().map(|b| b.len()));

                                                                                               if let Some(body) = chunk.body {
                                                                                                   println!("TCP Handler: Found Payload Body ({} bytes). Attempting unwrap...", body.len());
                                                                                                   // Recursively attempt to decode the body as a Sharing Frame
                                                                                                   match crate::proto::wire_format::Frame::decode(&body[..]) {
                                                                                                        Ok(inner_sharing) => {
                                                                                                            println!("TCP Handler: 📦 Unwrapped SharingFrame from PayloadTransfer!");
                                                                                                            decoded_sharing_frame = Some(inner_sharing);
                                                                                                        },
                                                                                                        Err(_decode_err) => {
                                                                                                            // This is actual file data, not a sharing frame!
                                                                                                            // Buffer it by payload_id
                                                                                                            if let Some(ref header) = pt.payload_header {
                                                                                                                if let Some(payload_id) = header.id {
                                                                                                                    // Only buffer if it's a FILE type (2)
                                                                                                                    let is_file_type = header.r#type == Some(2);
                                                                                                                    
                                                                                                                    if is_file_type {
                                                                                                                        // Add to buffer
                                                                                                                        let buffer = file_buffers.entry(payload_id).or_insert_with(Vec::new);
                                                                                                                        buffer.extend_from_slice(&body);
                                                                                                                        println!("TCP Handler: 📥 Buffered {} bytes for payload_id: {} (Total: {} bytes)", 
                                                                                                                            body.len(), payload_id, buffer.len());
                                                                                                                        
                                                                                                                        // Check if this is the last chunk (flags = 1)
                                                                                                                        let is_last_chunk = chunk.flags == Some(1);
                                                                                                                        
                                                                                                                        if is_last_chunk {
                                                                                                                            println!("TCP Handler: 🏁 LAST_CHUNK received for payload_id: {}", payload_id);
                                                                                                                            
                                                                                                                            // Look up filename from metadata
                                                                                                                            let final_buffer = file_buffers.remove(&payload_id);
                                                                                                                            
                                                                                                                            if let Some(file_data) = final_buffer {
                                                                                                                                let filename = file_metadata_map
                                                                                                                                    .get(&payload_id)
                                                                                                                                    .map(|(name, _)| name.clone())
                                                                                                                                    .unwrap_or_else(|| format!("received_file_{}", payload_id));
                                                                                                                                
                                                                                                                                // Save to configured download folder
                                                                                                                                let download_path = download_dir.join(&filename);
                                                                                                                                
                                                                                                                                match std::fs::write(&download_path, &file_data) {
                                                                                                                                    Ok(()) => {
                                                                                                                                        println!("TCP Handler: ✅ FILE SAVED! {} ({} bytes) -> {}", 
                                                                                                                                            filename, file_data.len(), download_path.display());
                                                                                                                                    },
                                                                                                                                    Err(e) => {
                                                                                                                                        println!("TCP Handler: ❌ Failed to save file: {}", e);
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    } else {
                                                                                                                        println!("TCP Handler: 📥 Non-file PayloadTransfer chunk ({} bytes)", body.len());
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                               } else {
                                                                                                   // Body is None - but check if this is a LAST_CHUNK end marker!
                                                                                                   let is_last_chunk = chunk.flags == Some(1);
                                                                                                   if is_last_chunk {
                                                                                                       println!("TCP Handler: 🏁 LAST_CHUNK END MARKER received (no body)");
                                                                                                       if let Some(ref header) = pt.payload_header {
                                                                                                           if let Some(payload_id) = header.id {
                                                                                                               let final_buffer = file_buffers.remove(&payload_id);
                                                                                                               
                                                                                                               if let Some(file_data) = final_buffer {
                                                                                                                   let filename = file_metadata_map
                                                                                                                       .get(&payload_id)
                                                                                                                       .map(|(name, _)| name.clone())
                                                                                                                       .unwrap_or_else(|| format!("received_file_{}", payload_id));
                                                                                                                   
                                                                                                                    // Save to configured download folder
                                                                                                                   let download_path = download_dir.join(&filename);
                                                                                                                   
                                                                                                                   match std::fs::write(&download_path, &file_data) {
                                                                                                                       Ok(()) => {
                                                                                                                           println!("TCP Handler: ✅ FILE SAVED! {} ({} bytes) -> {}", 
                                                                                                                               filename, file_data.len(), download_path.display());
                                                                                                                       },
                                                                                                                       Err(e) => {
                                                                                                                           println!("TCP Handler: ❌ Failed to save file: {}", e);
                                                                                                                       }
                                                                                                                   }
                                                                                                               } else {
                                                                                                                   println!("TCP Handler: ⚠️ No buffered data for payload_id: {}", payload_id);
                                                                                                               }
                                                                                                           }
                                                                                                       }
                                                                                                   } else {
                                                                                                       println!("TCP Handler: PayloadChunk body is None");
                                                                                                   }
                                                                                               }
                                                                                           } else {
                                                                                               println!("TCP Handler: PayloadChunk is None");
                                                                                           }
                                                                                       } else {
                                                                                           println!("TCP Handler: PayloadTransfer field is None");
                                                                                       }
                                                                                   } else {
                                                                                       println!("TCP Handler: Inner OfflineFrame Type NOT PayloadTransfer (3). Is: {:?}", v1_offline.r#type);
                                                                                   }
                                                                              } else {
                                                                                  println!("TCP Handler: OfflineFrame.v1 is None");
                                                                              }
                                                                          },
                                                                          Err(e) => {
                                                                              println!("TCP Handler: Strategy 2 (OfflineFrame) Failed: {}", e);
                                                                              println!("TCP Handler: ⚠️ Failed to decode 41-byte frame. Type unknown.");
                                                                              println!("TCP Handler: RAW HEX (Inner D2D): {}", hex::encode(&inner_msg));
                                                                          }
                                                                      }
                                                                  }

                                                                  if let Some(frame) = decoded_sharing_frame {
                                                                      let v1 = frame.v1.unwrap_or_default();
                                                                      let frame_type = v1.r#type.unwrap_or(0);
                                                                      
                                                                      println!("TCP Handler: ✨ SHARING FRAME TYPE: {:?}", frame_type);

                                                                      if frame_type == 3 { // PAIRED_KEY_ENCRYPTION
                                                                           println!("TCP Handler: 🔑 Client's PAIRED_KEY_ENCRYPTION received!");
                                                                           // Send PairedKeyResult (Status: UNABLE)
                                                                           println!("TCP Handler: Sending PairedKeyResult (UNABLE)...");
                                                                           let pkr = crate::proto::wire_format::PairedKeyResultFrame {
                                                                               status: Some(crate::proto::wire_format::paired_key_result_frame::Status::Unable.into()),
                                                                               ..Default::default()
                                                                           };
                                                                           let pkr_frame_v1 = crate::proto::wire_format::V1Frame {
                                                                               r#type: Some(crate::proto::wire_format::v1_frame::FrameType::PairedKeyResult.into()),
                                                                               paired_key_result: Some(pkr),
                                                                               ..Default::default()
                                                                           };
                                                                           let pkr_sharing_frame = crate::proto::wire_format::Frame {
                                                                               version: Some(crate::proto::wire_format::frame::Version::V1.into()),
                                                                               v1: Some(pkr_frame_v1),
                                                                           };
                                                                           
                                                                           let mut pkr_buf = Vec::new();
                                                                           pkr_sharing_frame.encode(&mut pkr_buf)?;
                                                                           let pkr_buf_len = pkr_buf.len() as i64;
                                                                           
                                                                           // Generate a random payload ID for this transfer
                                                                           let pkr_payload_id: i64 = rand::random();
                                                                           
                                                                           // Wrap in PayloadTransfer (OfflineFrame Type 3)
                                                                           let pkr_header = crate::proto::quick_share::payload_transfer::PayloadHeader {
                                                                               id: Some(pkr_payload_id),
                                                                               r#type: Some(crate::proto::quick_share::payload_transfer::payload_header::PayloadType::Bytes.into()),
                                                                               total_size: Some(pkr_buf_len),
                                                                               is_sensitive: Some(false),
                                                                               ..Default::default()
                                                                           };
                                                                           
                                                                           let pkr_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                                               flags: Some(0),
                                                                               offset: Some(0),
                                                                               body: Some(pkr_buf),
                                                                           };
                                                                           
                                                                           let pkr_pt = crate::proto::quick_share::PayloadTransfer {
                                                                               packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                                               payload_header: Some(pkr_header.clone()),
                                                                               payload_chunk: Some(pkr_chunk),
                                                                               control_message: None,
                                                                           };
                                                                           
                                                                           let pkr_offline = crate::proto::quick_share::OfflineFrame {
                                                                               version: Some(1),
                                                                               v1: Some(crate::proto::quick_share::V1Frame {
                                                                                   r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                                                   payload_transfer: Some(pkr_pt),
                                                                                   ..Default::default()
                                                                               }),
                                                                           };
                                                                           
                                                                           let mut pkr_offline_buf = Vec::new();
                                                                           pkr_offline.encode(&mut pkr_offline_buf)?;
                                                                           
                                                                           let d2d_pkr = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                               sequence_number: Some(server_seq_num), 
                                                                               message: Some(pkr_offline_buf),
                                                                           };
                                                                           server_seq_num += 1;
                                                                           let mut d2d_pkr_buf = Vec::new();
                                                                           d2d_pkr.encode(&mut d2d_pkr_buf)?;
                                                                           
                                                                           let gcm_meta = crate::proto::ukey2::GcmMetadata {
                                                                               r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(),
                                                                               version: Some(1),
                                                                           };
                                                                           let mut meta_bytes = Vec::new();
                                                                           gcm_meta.encode(&mut meta_bytes)?;
                                                                           
                                                                           let encrypted_pkr = engine.encrypt_and_sign(&d2d_pkr_buf, Some(&meta_bytes))?;
                                                                           let len_prefix = (encrypted_pkr.len() as u32).to_be_bytes();
                                                                           socket.write_all(&len_prefix).await?;
                                                                           socket.write_all(&encrypted_pkr).await?;
                                                                           println!("TCP Handler: Sent PKR in PayloadTransfer (data frame)!");
                                                                           
                                                                           // Send END marker
                                                                           let pkr_end_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                                               flags: Some(1), // LAST_CHUNK
                                                                               offset: Some(pkr_buf_len),
                                                                               body: None,
                                                                           };
                                                                           
                                                                           let pkr_end_pt = crate::proto::quick_share::PayloadTransfer {
                                                                               packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                                               payload_header: Some(pkr_header),
                                                                               payload_chunk: Some(pkr_end_chunk),
                                                                               control_message: None,
                                                                           };
                                                                           
                                                                           let pkr_end_offline = crate::proto::quick_share::OfflineFrame {
                                                                               version: Some(1),
                                                                               v1: Some(crate::proto::quick_share::V1Frame {
                                                                                   r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                                                   payload_transfer: Some(pkr_end_pt),
                                                                                   ..Default::default()
                                                                               }),
                                                                           };
                                                                           
                                                                           let mut pkr_end_buf = Vec::new();
                                                                           pkr_end_offline.encode(&mut pkr_end_buf)?;
                                                                           
                                                                           let d2d_pkr_end = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                               sequence_number: Some(server_seq_num), 
                                                                               message: Some(pkr_end_buf),
                                                                           };
                                                                           server_seq_num += 1;
                                                                           let mut d2d_pkr_end_buf = Vec::new();
                                                                           d2d_pkr_end.encode(&mut d2d_pkr_end_buf)?;
                                                                           
                                                                           let encrypted_pkr_end = engine.encrypt_and_sign(&d2d_pkr_end_buf, Some(&meta_bytes))?;
                                                                           let end_len_prefix = (encrypted_pkr_end.len() as u32).to_be_bytes();
                                                                           socket.write_all(&end_len_prefix).await?;
                                                                           socket.write_all(&encrypted_pkr_end).await?;
                                                                           println!("TCP Handler: Sent PKR END marker!");

                                                                      } else if frame_type == 4 { // PAIRED_KEY_RESULT
                                                                           println!("TCP Handler: 🔑 Client's PAIRED_KEY_RESULT received!");
                                                                           if let Some(pkr) = v1.paired_key_result {
                                                                               println!("    -> Status: {:?}", pkr.status);
                                                                           }
                                                                      } else if frame_type == 1 { // INTRODUCTION
                                                                           if let Some(intro) = v1.introduction {
                                                                               println!("TCP Handler: 📜 INTRODUCTION received! File count: {}", intro.file_metadata.len());
                                                                               
                                                                               // Display file metadata
                                                                               for (i, file) in intro.file_metadata.iter().enumerate() {
                                                                                   let name = file.name.as_deref().unwrap_or("Unknown");
                                                                                   let size = file.size.unwrap_or(0);
                                                                                   let mime = file.mime_type.as_deref().unwrap_or("application/octet-stream");
                                                                                   let file_type = file.r#type.unwrap_or(0);
                                                                                   let type_str = match file_type {
                                                                                       1 => "IMAGE",
                                                                                       2 => "VIDEO",
                                                                                       3 => "ANDROID_APP",
                                                                                       4 => "AUDIO",
                                                                                       5 => "DOCUMENT",
                                                                                       6 => "CONTACT_CARD",
                                                                                       _ => "UNKNOWN",
                                                                                   };
                                                                                    println!("    📁 File {}: {} ({}) - {} bytes [{}]", i + 1, name, type_str, size, mime);
                                                                                    
                                                                                    // Store metadata for payload reassembly
                                                                                    if let Some(payload_id) = file.payload_id {
                                                                                        file_metadata_map.insert(payload_id, (name.to_string(), size));
                                                                                        println!("    📦 Registered payload_id: {} for file: {}", payload_id, name);
                                                                                    }
                                                                                }
                                                                                
                                                                                // CLI Prompt: Ask user to Accept or Reject
                                                                                println!();
                                                                                println!("╔════════════════════════════════════════════════════╗");
                                                                                println!("║       📥 INCOMING FILE TRANSFER REQUEST            ║");
                                                                                println!("╠════════════════════════════════════════════════════╣");
                                                                                for file in intro.file_metadata.iter() {
                                                                                    let name = file.name.as_deref().unwrap_or("Unknown");
                                                                                    let size = file.size.unwrap_or(0);
                                                                                    let size_str = if size < 1024 {
                                                                                        format!("{} B", size)
                                                                                    } else if size < 1024 * 1024 {
                                                                                        format!("{:.1} KB", size as f64 / 1024.0)
                                                                                    } else {
                                                                                        format!("{:.1} MB", size as f64 / (1024.0 * 1024.0))
                                                                                    };
                                                                                    println!("║ 📁 {} ({})", name, size_str);
                                                                                }
                                                                                println!("╚════════════════════════════════════════════════════╝");
                                                                                println!();
                                                                                
                                                // Ask delegate for permission
                                                let user_accepted = if let Some(delegate) = &delegate {
                                                    println!("TCP Handler: Requesting user confirmation via delegate...");
                                                    
                                                    let files: Vec<FileInfo> = intro.file_metadata.iter().map(|f| FileInfo {
                                                        name: f.name.clone().unwrap_or_default(),
                                                        size: f.size.unwrap_or(0) as u64,
                                                        mime_type: f.mime_type.clone().unwrap_or_default(),
                                                        payload_id: f.payload_id.unwrap_or(0),
                                                    }).collect();
                                                    
                                                    let req = TransferRequest {
                                                        id: rand::random(),
                                                        sender_name: remote_device_name.clone(),
                                                        files,
                                                    };
                                                    
                                                    delegate.on_transfer_request(req).await
                                                } else {
                                                    println!("✅ No delegate attached. Auto-accepting transfer.");
                                                    true
                                                };
                                                                                
                                                                                if !user_accepted {
                                                                                    println!("TCP Handler: ❌ User REJECTED transfer.");
                                                                                    
                                                                                    // Create RESPONSE frame with REJECT
                                                                                    let response = crate::proto::wire_format::ConnectionResponseFrame {
                                                                                        status: Some(crate::proto::wire_format::connection_response_frame::Status::Reject.into()),
                                                                                    };
                                                                                    let response_v1 = crate::proto::wire_format::V1Frame {
                                                                                        r#type: Some(crate::proto::wire_format::v1_frame::FrameType::Response.into()),
                                                                                        connection_response: Some(response),
                                                                                        ..Default::default()
                                                                                    };
                                                                                    let response_frame = crate::proto::wire_format::Frame {
                                                                                        version: Some(crate::proto::wire_format::frame::Version::V1.into()),
                                                                                        v1: Some(response_v1),
                                                                                    };
                                                                                    
                                                                                    let mut resp_buf = Vec::new();
                                                                                    response_frame.encode(&mut resp_buf)?;
                                                                                    let resp_buf_len = resp_buf.len() as i64;
                                                                                    
                                                                                    // Wrap in PayloadTransfer and send
                                                                                    let resp_payload_id: i64 = rand::random();
                                                                                    let resp_header = crate::proto::quick_share::payload_transfer::PayloadHeader {
                                                                                        id: Some(resp_payload_id),
                                                                                        r#type: Some(crate::proto::quick_share::payload_transfer::payload_header::PayloadType::Bytes.into()),
                                                                                        total_size: Some(resp_buf_len),
                                                                                        is_sensitive: Some(false),
                                                                                        ..Default::default()
                                                                                    };
                                                                                    
                                                                                    let resp_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                                                        flags: Some(0),
                                                                                        offset: Some(0),
                                                                                        body: Some(resp_buf),
                                                                                    };
                                                                                    
                                                                                    let resp_pt = crate::proto::quick_share::PayloadTransfer {
                                                                                        packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                                                        payload_header: Some(resp_header.clone()),
                                                                                        payload_chunk: Some(resp_chunk),
                                                                                        control_message: None,
                                                                                    };
                                                                                    
                                                                                    let resp_offline = crate::proto::quick_share::OfflineFrame {
                                                                                        version: Some(1),
                                                                                        v1: Some(crate::proto::quick_share::V1Frame {
                                                                                            r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                                                            payload_transfer: Some(resp_pt),
                                                                                            ..Default::default()
                                                                                        }),
                                                                                    };
                                                                                    
                                                                                    let mut resp_offline_buf = Vec::new();
                                                                                    resp_offline.encode(&mut resp_offline_buf)?;
                                                                                    
                                                                                    let d2d_resp = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                                        sequence_number: Some(server_seq_num), 
                                                                                        message: Some(resp_offline_buf),
                                                                                    };
                                                                                    server_seq_num += 1;
                                                                                    let mut d2d_resp_buf = Vec::new();
                                                                                    d2d_resp.encode(&mut d2d_resp_buf)?;
                                                                                    
                                                                                    let gcm_meta = crate::proto::ukey2::GcmMetadata {
                                                                                        r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(),
                                                                                        version: Some(1),
                                                                                    };
                                                                                    let mut meta_bytes = Vec::new();
                                                                                    gcm_meta.encode(&mut meta_bytes)?;
                                                                                    
                                                                                    let encrypted_resp = engine.encrypt_and_sign(&d2d_resp_buf, Some(&meta_bytes))?;
                                                                                    let len_prefix = (encrypted_resp.len() as u32).to_be_bytes();
                                                                                    socket.write_all(&len_prefix).await?;
                                                                                    socket.write_all(&encrypted_resp).await?;
                                                                                    println!("TCP Handler: Sent RESPONSE (REJECT)!");
                                                                                    
                                                                                    // Send END marker
                                                                                    let resp_end_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                                                        flags: Some(1),
                                                                                        offset: Some(resp_buf_len),
                                                                                        body: None,
                                                                                    };
                                                                                    
                                                                                    let resp_end_pt = crate::proto::quick_share::PayloadTransfer {
                                                                                        packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                                                        payload_header: Some(resp_header),
                                                                                        payload_chunk: Some(resp_end_chunk),
                                                                                        control_message: None,
                                                                                    };
                                                                                    
                                                                                    let resp_end_offline = crate::proto::quick_share::OfflineFrame {
                                                                                        version: Some(1),
                                                                                        v1: Some(crate::proto::quick_share::V1Frame {
                                                                                            r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                                                            payload_transfer: Some(resp_end_pt),
                                                                                            ..Default::default()
                                                                                        }),
                                                                                    };
                                                                                    
                                                                                    let mut resp_end_buf = Vec::new();
                                                                                    resp_end_offline.encode(&mut resp_end_buf)?;
                                                                                    
                                                                                    let d2d_resp_end = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                                        sequence_number: Some(server_seq_num), 
                                                                                        message: Some(resp_end_buf),
                                                                                    };
                                                                                    // server_seq_num += 1; // Unused as we break immediately
                                                                                    let mut d2d_resp_end_buf = Vec::new();
                                                                                    d2d_resp_end.encode(&mut d2d_resp_end_buf)?;
                                                                                    
                                                                                    let encrypted_resp_end = engine.encrypt_and_sign(&d2d_resp_end_buf, Some(&meta_bytes))?;
                                                                                    let end_len_prefix = (encrypted_resp_end.len() as u32).to_be_bytes();
                                                                                    socket.write_all(&end_len_prefix).await?;
                                                                                    socket.write_all(&encrypted_resp_end).await?;
                                                                                    println!("TCP Handler: Sent REJECT END marker!");
                                                                                    
                                                                                    // Exit the loop - transfer rejected
                                                                                    break;
                                                                                }
                                                                                
                                                                                println!("TCP Handler: ✅ User ACCEPTED transfer!");
                                                                               
                                                                               // Create RESPONSE frame with ACCEPT
                                                                               let response = crate::proto::wire_format::ConnectionResponseFrame {
                                                                                   status: Some(crate::proto::wire_format::connection_response_frame::Status::Accept.into()),
                                                                               };
                                                                               let response_v1 = crate::proto::wire_format::V1Frame {
                                                                                   r#type: Some(crate::proto::wire_format::v1_frame::FrameType::Response.into()),
                                                                                   connection_response: Some(response),
                                                                                   ..Default::default()
                                                                               };
                                                                               let response_frame = crate::proto::wire_format::Frame {
                                                                                   version: Some(crate::proto::wire_format::frame::Version::V1.into()),
                                                                                   v1: Some(response_v1),
                                                                               };
                                                                               
                                                                               let mut resp_buf = Vec::new();
                                                                               response_frame.encode(&mut resp_buf)?;
                                                                               let resp_buf_len = resp_buf.len() as i64;
                                                                               
                                                                               // Wrap in PayloadTransfer
                                                                               let resp_payload_id: i64 = rand::random();
                                                                               let resp_header = crate::proto::quick_share::payload_transfer::PayloadHeader {
                                                                                   id: Some(resp_payload_id),
                                                                                   r#type: Some(crate::proto::quick_share::payload_transfer::payload_header::PayloadType::Bytes.into()),
                                                                                   total_size: Some(resp_buf_len),
                                                                                   is_sensitive: Some(false),
                                                                                   ..Default::default()
                                                                               };
                                                                               
                                                                               let resp_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                                                   flags: Some(0),
                                                                                   offset: Some(0),
                                                                                   body: Some(resp_buf),
                                                                               };
                                                                               
                                                                               let resp_pt = crate::proto::quick_share::PayloadTransfer {
                                                                                   packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                                                   payload_header: Some(resp_header.clone()),
                                                                                   payload_chunk: Some(resp_chunk),
                                                                                   control_message: None,
                                                                               };
                                                                               
                                                                               let resp_offline = crate::proto::quick_share::OfflineFrame {
                                                                                   version: Some(1),
                                                                                   v1: Some(crate::proto::quick_share::V1Frame {
                                                                                       r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                                                       payload_transfer: Some(resp_pt),
                                                                                       ..Default::default()
                                                                                   }),
                                                                               };
                                                                               
                                                                               let mut resp_offline_buf = Vec::new();
                                                                               resp_offline.encode(&mut resp_offline_buf)?;
                                                                               
                                                                               let d2d_resp = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                                   sequence_number: Some(server_seq_num), 
                                                                                   message: Some(resp_offline_buf),
                                                                               };
                                                                               server_seq_num += 1;
                                                                               let mut d2d_resp_buf = Vec::new();
                                                                               d2d_resp.encode(&mut d2d_resp_buf)?;
                                                                               
                                                                               let gcm_meta = crate::proto::ukey2::GcmMetadata {
                                                                                   r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(),
                                                                                   version: Some(1),
                                                                               };
                                                                               let mut meta_bytes = Vec::new();
                                                                               gcm_meta.encode(&mut meta_bytes)?;
                                                                               
                                                                               let encrypted_resp = engine.encrypt_and_sign(&d2d_resp_buf, Some(&meta_bytes))?;
                                                                               let len_prefix = (encrypted_resp.len() as u32).to_be_bytes();
                                                                               socket.write_all(&len_prefix).await?;
                                                                               socket.write_all(&encrypted_resp).await?;
                                                                               println!("TCP Handler: Sent RESPONSE (ACCEPT) in PayloadTransfer!");
                                                                               
                                                                               // Send END marker
                                                                               let resp_end_chunk = crate::proto::quick_share::payload_transfer::PayloadChunk {
                                                                                   flags: Some(1), // LAST_CHUNK
                                                                                   offset: Some(resp_buf_len),
                                                                                   body: None,
                                                                               };
                                                                               
                                                                               let resp_end_pt = crate::proto::quick_share::PayloadTransfer {
                                                                                   packet_type: Some(crate::proto::quick_share::payload_transfer::PacketType::Data.into()),
                                                                                   payload_header: Some(resp_header),
                                                                                   payload_chunk: Some(resp_end_chunk),
                                                                                   control_message: None,
                                                                               };
                                                                               
                                                                               let resp_end_offline = crate::proto::quick_share::OfflineFrame {
                                                                                   version: Some(1),
                                                                                   v1: Some(crate::proto::quick_share::V1Frame {
                                                                                       r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                                                                                       payload_transfer: Some(resp_end_pt),
                                                                                       ..Default::default()
                                                                                   }),
                                                                               };
                                                                               
                                                                               let mut resp_end_buf = Vec::new();
                                                                               resp_end_offline.encode(&mut resp_end_buf)?;
                                                                               
                                                                               let d2d_resp_end = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                                   sequence_number: Some(server_seq_num), 
                                                                                   message: Some(resp_end_buf),
                                                                               };
                                                                               server_seq_num += 1;
                                                                               let mut d2d_resp_end_buf = Vec::new();
                                                                               d2d_resp_end.encode(&mut d2d_resp_end_buf)?;
                                                                               
                                                                               let encrypted_resp_end = engine.encrypt_and_sign(&d2d_resp_end_buf, Some(&meta_bytes))?;
                                                                               let end_len_prefix = (encrypted_resp_end.len() as u32).to_be_bytes();
                                                                               socket.write_all(&end_len_prefix).await?;
                                                                               socket.write_all(&encrypted_resp_end).await?;
                                                                               println!("TCP Handler: Sent RESPONSE END marker!");
                                                                           }
                                                                      } else if frame_type == 12 { // KEEP_ALIVE
                                                                           println!("TCP Handler: 💓 Received KEEP_ALIVE, responding with ack...");
                                                                           // Need to send a KeepAlive ack?
                                                                            let ka = crate::proto::wire_format::KeepAliveFrame { ack: Some(true) };
                                                                            let ka_v1 = crate::proto::wire_format::V1Frame {
                                                                                r#type: Some(crate::proto::wire_format::v1_frame::FrameType::KeepAlive.into()),
                                                                                keep_alive: Some(ka),
                                                                                ..Default::default()
                                                                            };
                                                                            let ka_frame = crate::proto::wire_format::Frame {
                                                                                version: Some(crate::proto::wire_format::frame::Version::V1.into()),
                                                                                v1: Some(ka_v1),
                                                                            };
                                                                            let mut ka_buf = Vec::new();
                                                                            ka_frame.encode(&mut ka_buf)?;
                                                                            
                                                                            let d2d_ka = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                                sequence_number: Some(server_seq_num), 
                                                                                message: Some(ka_buf),
                                                                            };
                                                                            server_seq_num += 1;
                                                                            let mut ka_enc_buf = Vec::new();
                                                                            d2d_ka.encode(&mut ka_enc_buf)?;
                                                                            
                                                                            let gcm_meta = crate::proto::ukey2::GcmMetadata {
                                                                                r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(),
                                                                                 version: Some(1),
                                                                             };
                                                                             let mut meta_bytes = Vec::new();
                                                                             gcm_meta.encode(&mut meta_bytes)?;

                                                                             let encrypted_ka = engine.encrypt_and_sign(&ka_enc_buf, Some(&meta_bytes))?;
                                                                             let len_prefix = (encrypted_ka.len() as u32).to_be_bytes();
                                                                             socket.write_all(&len_prefix).await?;
                                                                             socket.write_all(&encrypted_ka).await?;
                                                                             println!("TCP Handler: Sent KEEP_ALIVE Ack.");
                                                                      } else if frame_type == 2 { // RESPONSE (ConnectionResponseFrame)
                                                                           println!("TCP Handler: 📬 Client's RESPONSE received!");
                                                                           if let Some(conn_resp) = &v1.connection_response {
                                                                               let status = conn_resp.status.unwrap_or(0);
                                                                               let status_str = match status {
                                                                                   1 => "ACCEPT",
                                                                                   2 => "REJECT",
                                                                                   3 => "NOT_ENOUGH_SPACE",
                                                                                   4 => "UNSUPPORTED_ATTACHMENT_TYPE",
                                                                                   5 => "TIMED_OUT",
                                                                                   _ => "UNKNOWN",
                                                                               };
                                                                               println!("    -> Status: {} ({})", status, status_str);
                                                                               if status == 1 {
                                                                                   println!("TCP Handler: ✅ Phone confirmed ACCEPT - file transfer should begin!");
                                                                               }
                                                                           }
                                                                      } else if frame_type == 6 { // CANCEL
                                                                           println!("TCP Handler: ❌ Received CANCEL from client.");
                                                                      } else {
                                                                           println!("TCP Handler: ⚠️ Unhandled Sharing Frame Type: {}", frame_type);
                                                                      }
                                                                  } else {
                                                                      // Fallback or explicit failure log
                                                                      // Already logged errors above
                                                                  }
                                                              }
                                                          },
                                                          Err(e) => {
                                                              println!("TCP Handler: ⛔ Decryption Failed: {:?}", e);
                                                              println!("TCP Handler: RAW HEX: {}", hex::encode(&enc_buf));
                                                              
                                                              // Check for plaintext
                                                              match crate::proto::quick_share::OfflineFrame::decode(&enc_buf[..]) {
                                                                  Ok(f) => {
                                                                       println!("TCP Handler: ⚠️  IT IS PLAINTEXT! Type: {:?}", f.v1.as_ref().and_then(|v| v.r#type));
                                                                  },
                                                                  Err(_) => {},
                                                              }
                                                          }
                                                      }
                                                  }
                                              }
                                         }
                                    },
                                     Err(e) => println!("TCP Handler: Handshake Error: {}", e),
                                 }
                         }
                    }
                }
            }

            if !decoded_something {
                println!("TCP Handler: Unknown Packet Format. Raw Hex: {}", hex::encode(&payload_buf));
            }
        }
    }
}
