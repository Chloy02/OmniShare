use anyhow::Result;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;


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
                if let Err(e) = Self::handle_connection(&mut socket).await {
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
    /// 1. Loop to read Frames.
    /// 2. Decode ConnectionRequest.
    /// 3. Decode UKEY2 Client Init.
    async fn handle_connection(socket: &mut tokio::net::TcpStream) -> Result<()> {
        println!("TCP Handler: Handler started.");
        let mut _remote_handshake_data: Option<Vec<u8>> = None;

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
                                                  
                                                  // Serialize the Sharing Frame (Directly, NO PayloadTransfer wrapping for PKE)
                                                  // Reference: NearDrop's sendTransferSetupFrame just sends the Frame
                                                  let mut pke_buf = Vec::new();
                                                  pke_sharing_frame.encode(&mut pke_buf)?;
                                                  
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
                                                  
                                                  // Encrypt this payload
                                                  let encrypted_pke = engine.encrypt_and_sign(&d2d_buf, Some(&meta_bytes))?;
                                                  println!("TCP Handler: Encrypted PKE Frame size: {}", encrypted_pke.len());
                                                  
                                                  let pke_len_prefix = (encrypted_pke.len() as u32).to_be_bytes();
                                                  socket.write_all(&pke_len_prefix).await?;
                                                  socket.write_all(&encrypted_pke).await?;
                                                  println!("TCP Handler: Sent Encrypted PairedKeyEncryption (sharing.nearby.Frame)!");

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
                                                                  match crate::proto::wire_format::Frame::decode(&inner_msg[..]) {
                                                                      Ok(frame) => {
                                                                          if let Some(v1) = frame.v1 {
                                                                               println!("TCP Handler: Inner Sharing Frame Type: {:?}", v1.r#type);
                                                                               
                                                                               if let Some(_pke) = v1.paired_key_encryption {
                                                                                   println!("TCP Handler: 🔑 Client's PAIRED_KEY_ENCRYPTION received!");
                                                                                   
                                                                                   // Send PairedKeyResult (Status: UNABLE) because we don't support true pairing yet
                                                                                   println!("TCP Handler: Sending PairedKeyResult (UNABLE)...");
                                                                                   
                                                                                   let pkr = crate::proto::wire_format::PairedKeyResultFrame {
                                                                                       status: Some(crate::proto::wire_format::paired_key_result_frame::Status::Unable.into()),
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
                                                                                   
                                                                                   let d2d_pkr = crate::proto::ukey2::DeviceToDeviceMessage {
                                                                                       sequence_number: Some(2), 
                                                                                       message: Some(pkr_buf),
                                                                                   };
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
                                                                                   
                                                                                   println!("TCP Handler: Sent Encrypted PairedKeyResult (UNABLE)!");
                                                                               }
                                                                               else if let Some(pkr) = v1.paired_key_result {
                                                                                    println!("TCP Handler: 🔑 Client's PAIRED_KEY_RESULT received: {:?}", pkr.status);
                                                                               }
                                                                               else if let Some(intro) = v1.introduction {
                                                                                    println!("TCP Handler: 📜 INTRODUCTION received! File count: {}", intro.file_metadata.len());
                                                                               }
                                                                               // Removed 'cancel' check as it is not defined in wire_format.proto definition yet
                                                                               else {
                                                                                    // Check for other types if needed, or just log generic
                                                                                    println!("TCP Handler: ⚠️ Unknown or Unhandled Sharing Frame Type: {:?}", v1.r#type);
                                                                               }
                                                                          }
                                                                      },
                                                                      Err(_) => {
                                                                          println!("TCP Handler: Failed to decode as Sharing Frame. Trying OfflineFrame (fallback)...");
                                                                           if let Ok(frame) = crate::proto::quick_share::OfflineFrame::decode(&inner_msg[..]) {
                                                                              if let Some(v1) = frame.v1 {
                                                                                  println!("TCP Handler: Inner OfflineFrame Type: {:?}", v1.r#type);
                                                                                  if let Some(payload) = v1.payload_transfer {
                                                                                      println!("TCP Handler: 📥 PAYLOAD_TRANSFER received (OfflineFrame)!");
                                                                                      if let Some(header) = payload.payload_header {
                                                                                          println!("TCP Handler: File: {:?}, Size: {:?} bytes", 
                                                                                              header.file_name, header.total_size);
                                                                                      }
                                                                                  }
                                                                              }
                                                                          }
                                                                      }
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
