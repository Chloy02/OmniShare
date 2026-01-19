use anyhow::Result;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use sha2::Digest;

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
                    println!("TCP Handler: Decoded OfflineFrame (Type: {:?})", v1.r#type);
                    
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
                             
                             if let Some(inner_data) = &ukey_msg.message_data {
                                 match server.handle_client_init(inner_data) {
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
                                                      status: Some(crate::proto::quick_share::connection_response::Status::Accept.into()),
                                                      handshake_data: None,
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
                                                      &keys.d2d_client_key,
                                                      &keys.d2d_server_key,
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
                                                           println!("TCP Handler: Received Client Frame (Pre-Secure). Type: {:?}", frame.v1.as_ref().and_then(|v| v.r#type));
                                                      },
                                                      Err(e) => println!("TCP Handler: Failed to decode pre-secure frame: {:?}", e),
                                                  }
                                                  
                                                  println!("TCP Handler: Client Response received. Entering Secure Mode.");
                                                  
                                                  // --- Step 4.6: Send PairedKeyEncryption (Encrypted) ---
                                                  println!("TCP Handler: Sending PairedKeyEncryption...");
                                                  
                                                  // Calculate Secret ID Hash = SHA256(auth_string)
                                                  let secret_id_hash = sha2::Sha256::digest(&keys.auth_string).to_vec();
                                                  println!("TCP Handler: Secret ID Hash: {}", hex::encode(&secret_id_hash));
                                                  
                                                  // For Signed Data: We are unauthorized/guest, so we send None.
                                                  let pke = crate::proto::quick_share::PairedKeyEncryption {
                                                      signed_data: None,
                                                      secret_id_hash: Some(secret_id_hash),
                                                  };
                                                  let pke_frame_v1 = crate::proto::quick_share::V1Frame {
                                                      r#type: Some(crate::proto::quick_share::v1_frame::FrameType::PairedKeyEncryption.into()),
                                                      paired_key_encryption: Some(pke),
                                                      ..Default::default()
                                                  };
                                                  let pke_offline_frame = crate::proto::quick_share::OfflineFrame {
                                                      version: Some(1),
                                                      v1: Some(pke_frame_v1),
                                                  };
                                                  
                                                  let mut pke_buf = Vec::new();
                                                  pke_offline_frame.encode(&mut pke_buf)?;
                                                  // Wrap in DeviceToDeviceMessage
                                                  let d2d_msg = crate::proto::ukey2::DeviceToDeviceMessage {
                                                      sequence_number: Some(1), 
                                                      message: Some(pke_buf),
                                                  };
                                                  let mut d2d_buf = Vec::new();
                                                  d2d_msg.encode(&mut d2d_buf)?;
                                                  
                                                  // Create GcmMetadata for the SecureMessage Header
                                                  let gcm_meta = crate::proto::ukey2::GcmMetadata {
                                                      r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(), // Type 13
                                                      version: Some(1),
                                                  };
                                                  let mut meta_bytes = Vec::new();
                                                  gcm_meta.encode(&mut meta_bytes)?;

                                                  // Encrypt this payload with the GcmMetadata in the header
                                                  let encrypted_pke = engine.encrypt_and_sign(&d2d_buf, Some(&meta_bytes))?;
                                                  println!("TCP Handler: Encrypted PKE Frame size: {}", encrypted_pke.len());
                                                  
                                                  let pke_len_prefix = (encrypted_pke.len() as u32).to_be_bytes();
                                                  socket.write_all(&pke_len_prefix).await?;
                                                  socket.write_all(&encrypted_pke).await?;
                                                  println!("TCP Handler: Sent Encrypted PairedKeyEncryption!");

                                                  // Now we listen for the Client's encrypted reply
                                                  println!("TCP Handler: Listening for Client's Encrypted Frames...");
                                                  // Read loop for secure messages
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
                                                              // Check if it is a SecureMessage (DeviceToDeviceMessage)
                                                              // The payload of SecureMessage is usually a DeviceToDeviceMessage proto.
                                                              // Let's decode it.
                                                              let d2d_msg = match crate::proto::ukey2::DeviceToDeviceMessage::decode(&decrypted_payload[..]) {
                                                                  Ok(m) => m,
                                                                  Err(e) => {
                                                                      println!("TCP Handler: Failed to decode DeviceToDeviceMessage: {:?}", e);
                                                                      continue;
                                                                  }
                                                              };
                                                              
                                                              if let Some(inner_msg) = d2d_msg.message {
                                                                  println!("TCP Handler: Decoded D2D Message (Seq: {:?}). Processing inner OfflineFrame...", d2d_msg.sequence_number);
                                                                  // Inner message is an OfflineFrame
                                                                  let frame = crate::proto::quick_share::OfflineFrame::decode(&inner_msg[..])?;
                                                                  if let Some(v1) = frame.v1 {
                                                                      println!("TCP Handler: Inner Frame Type: {:?}", v1.r#type);
                                                                      if let Some(pke) = v1.paired_key_encryption {
                                                                           println!("TCP Handler: 🔑 PAIRED_KEY_ENCRYPTION received! (Chunk size: {:?})", pke.signed_data.as_ref().map(|d| d.len()));
                                                                           // We effectively ignore the validation for now as per "works fine" advice
                                                                           // But we MUST send a reply? 
                                                                           // According to doc: "After that, the client and the server send each other a 'paired key result' frame."
                                                                           // TODO: Send PairedKeyResult
                                                                      }
                                                                  }
                                                              }
                                                          },
                                                          Err(e) => {
                                                              println!("TCP Handler: ⛔ Decryption Failed: {:?}", e);
                                                              println!("TCP Handler: RAW HEX: {}", hex::encode(&enc_buf));
                                                              
                                                              // Debug: Is it plaintext?
                                                              match crate::proto::quick_share::OfflineFrame::decode(&enc_buf[..]) {
                                                                  Ok(f) => {
                                                                       println!("TCP Handler: ⚠️  IT IS PLAINTEXT! Type: {:?}", f.v1.as_ref().and_then(|v| v.r#type));
                                                                       // If it's KeepAlive (5), maybe we just ignore it or handle it?
                                                                  },
                                                                  Err(_) => println!("TCP Handler: Not plaintext either."),
                                                              }
                                                          }
                                                      }
                                                  }
                                              }
                                          } else {
                                              println!("TCP Handler: Expected ClientFinished, got {:?}", msg3.message_type);
                                          }
                                     },
                                     Err(e) => println!("TCP Handler: Handshake Error: {}", e),
                                 }
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
