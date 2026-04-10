//! Outbound Transfer Handler
//!
//! Handles sending files from Linux to Android devices.

use anyhow::{anyhow, Result};
use prost::Message;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::proto::securemessage::{SecureMessage, HeaderAndBody};
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
type Aes256CbcDec = Decryptor<aes::Aes256>;

use crate::discovery::scanner::DiscoveredDevice;
use crate::security::ukey2::{Ukey2Client, Ukey2SessionKeys};
use crate::security::engine::SecurityEngine;
use crate::proto::quick_share;  // location.nearby.connections
use crate::proto::wire_format;  // sharing.nearby

/// Sequence counter for encrypted messages
struct SequenceCounter {
    value: i32,
}

impl SequenceCounter {
    fn new() -> Self {
        Self { value: 0 }
    }
    
    fn next(&mut self) -> i32 {
        let v = self.value;
        self.value += 1;
        v
    }

    fn peek(&self) -> i32 {
        self.value
    }
}

/// Send files to a discovered device
pub async fn send_files(
    device: DiscoveredDevice,
    files: Vec<PathBuf>,
    device_name: &str,
) -> Result<()> {
    println!("📤 Starting transfer to {} ({}:{})", device.name, device.ip, device.port);
    println!("   Files to send: {:?}", files);

    // 1. Connect to device
    let target = format!("{}:{}", device.ip, device.port);
    let mut socket = TcpStream::connect(&target).await?;
    println!("✅ Connected to {}", target);

    // 2. Send CONNECTION_REQUEST
    send_connection_request(&mut socket, &device.endpoint_id, device_name).await?;
    
    // 3. UKEY2 Handshake (as client) — keys only, no ConnectionResponse yet
    let session_keys = perform_ukey2_handshake(&mut socket).await?;
    println!("✅ UKEY2 Handshake complete");
    
    // 4. Wait for Android's ConnectionResponse FIRST (Server sends first per protocol)
    let response = read_frame(&mut socket).await?;
    println!("DEBUG: Received frame after UKEY2: {} bytes, first 32: {}", 
             response.len(), 
             hex::encode(&response[..std::cmp::min(32, response.len())]));
    let offline_frame = quick_share::OfflineFrame::decode(response.as_slice())?;
    println!("DEBUG: Decoded OfflineFrame v1.type: {:?}", offline_frame.v1.as_ref().map(|v| v.r#type()));
    if let Some(v1) = &offline_frame.v1 {
        if let Some(conn_resp) = &v1.connection_response {
            let status = conn_resp.response.unwrap_or(0);
            if status != 1 { // 1 = ACCEPT
                return Err(anyhow!("Connection rejected by device (status: {})", status));
            }
            println!("✅ Connection accepted by {}", device.name);
        }
    }
    
    // 5. Send OUR ConnectionResponse (Client sends second)
    let conn_response = build_connection_response()?;
    send_frame(&mut socket, &conn_response).await?;
    println!("📤 Sent ConnectionResponse (ACCEPT)");

    // Create security engine with derived keys (Client role for outbound)
    let engine = SecurityEngine::new_with_role(
        crate::security::Role::Client,
        &session_keys,
    );
    println!("✅ SecurityEngine initialized with ROLE::CLIENT");
    
    let mut seq = SequenceCounter::new();

    // 5. Wait for SERVER's PairedKeyEncryption FIRST (Server always sends first per protocol)
    println!("⏳ Waiting for device's PairedKeyEncryption...");
    let _ = read_and_validate_next_frame(&mut socket, &engine, wire_format::v1_frame::FrameType::PairedKeyEncryption).await?;
    println!("📥 Received PairedKeyEncryption");
    
    // 6. Send our PairedKeyEncryption (with random data)
    send_paired_key_encryption(&mut socket, &engine, &mut seq).await?;
    
    // 7. Wait for SERVER's PairedKeyResult FIRST
    println!("⏳ Waiting for device's PairedKeyResult...");
    let _ = read_and_validate_next_frame(&mut socket, &engine, wire_format::v1_frame::FrameType::PairedKeyResult).await?;
    println!("📥 Received PairedKeyResult");
    
    // 8. Send our PairedKeyResult (UNABLE - we don't have saved keys)
    send_paired_key_result(&mut socket, &engine, &mut seq).await?;

    // 9. Send INTRODUCTION with file metadata
    let file_metadata = build_file_metadata(&files)?;
    // Retain a copy so we have the payload_ids for streaming
    let streaming_metadata = file_metadata.clone();
    send_introduction(&mut socket, &engine, &mut seq, file_metadata).await?;

    // 10. Wait for user to accept on Android
    // The Response comes wrapped in a PayloadTransfer containing a wire_format::Frame { Response }
    println!("⏳ Waiting for user to accept on {}...", device.name);

    let frame = read_and_validate_next_frame(&mut socket, &engine, wire_format::v1_frame::FrameType::Response).await?;
    if let Some(v1) = frame.v1 {
        if let Some(resp) = v1.connection_response {
            let status = resp.status.unwrap_or(0);
            if status != 1 {
                // 1 = ACCEPT in wire_format::ConnectionResponseFrame
                println!("❌ User rejected the transfer (status: {})", status);
                return Ok(());
            }
        }
    }
    println!("✅ User ACCEPTED the transfer!");

    // 11. Stream file data
    stream_files(&mut socket, &engine, &mut seq, &files, &streaming_metadata).await?;

    println!("✅ Transfer complete!");
    Ok(())
}

/// Send CONNECTION_REQUEST frame
async fn send_connection_request(
    socket: &mut TcpStream,
    endpoint_id: &str,
    device_name: &str,
) -> Result<()> {
    // Build endpoint_info (same format as mDNS) — raw bytes, NOT lossy UTF-8
    let mut endpoint_info = Vec::new();
    endpoint_info.push(0x06u8); // Laptop device type
    endpoint_info.extend_from_slice(&rand::random::<[u8; 16]>()); // Random salt
    endpoint_info.push(device_name.len() as u8);
    endpoint_info.extend_from_slice(device_name.as_bytes());
    
    // Convert bytes to Latin-1 string (each byte maps to its Unicode codepoint)
    // This preserves all byte values unlike String::from_utf8_lossy which corrupts bytes ≥0x80
    let endpoint_info_str: String = endpoint_info.iter().map(|&b| b as char).collect();

    let frame = quick_share::OfflineFrame {
        version: Some(1),
        v1: Some(quick_share::V1Frame {
            r#type: Some(quick_share::v1_frame::FrameType::ConnectionRequest.into()),
            connection_request: Some(quick_share::ConnectionRequest {
                endpoint_id: Some(endpoint_id.to_string()),
                endpoint_name: Some(device_name.to_string()),
                endpoint_info: Some(endpoint_info_str),
                nonce: Some(rand::random::<i32>().abs()),
                mediums: vec![4], // 4 = WIFI_LAN (required for transport negotiation)
                ..Default::default()
            }),
            ..Default::default()
        }),
    };

    let data = frame.encode_to_vec();
    send_frame(socket, &data).await?;
    println!("📤 Sent CONNECTION_REQUEST");
    Ok(())
}

/// Perform UKEY2 handshake as client
async fn perform_ukey2_handshake(socket: &mut TcpStream) -> Result<Ukey2SessionKeys> {
    // 1. Generate and send ClientInit
    let (client_init, ukey_client) = Ukey2Client::new()?;
    send_frame(socket, &client_init).await?;
    println!("📤 Sent UKEY2 ClientInit");

    // 2. Receive ServerInit
    let server_init = read_frame(socket).await?;
    println!("📥 Received UKEY2 ServerInit ({} bytes)", server_init.len());

    // 3. Process ServerInit and get ClientFinished
    let (client_finished, ukey_pending) = ukey_client.handle_server_init(&server_init)?;
    send_frame(socket, &client_finished).await?;
    println!("📤 Sent UKEY2 ClientFinished");

    // 4. Derive keys (ConnectionResponse exchange happens in send_files after this)
    let session_keys = ukey_pending.finalize(&server_init)?;

    Ok(session_keys)
}

/// Build ConnectionResponse frame
fn build_connection_response() -> Result<Vec<u8>> {
    let response = quick_share::ConnectionResponse {
        response: Some(quick_share::connection_response::ResponseStatus::Accept.into()),
        os_info: Some(quick_share::OsInfo {
            r#type: Some(quick_share::os_info::OsType::Linux.into()),
        }),
        multiplex_socket_bitmask: Some(0),
        safe_to_disconnect_version: Some(1),
        ..Default::default()
    };

    let frame = quick_share::OfflineFrame {
        version: Some(1),
        v1: Some(quick_share::V1Frame {
            r#type: Some(quick_share::v1_frame::FrameType::ConnectionResponse.into()),
            connection_response: Some(response),
            ..Default::default()
        }),
    };

    Ok(frame.encode_to_vec())
}

/// Send PairedKeyEncryption frame
/// Note: send_encrypted_payload() handles PayloadTransfer wrapping + LAST_CHUNK automatically
async fn send_paired_key_encryption(
    socket: &mut TcpStream,
    engine: &SecurityEngine,
    seq: &mut SequenceCounter,
) -> Result<()> {
    use rand::RngCore;
    let mut signed_data = vec![0u8; 72];
    rand::thread_rng().fill_bytes(&mut signed_data);
    
    let pke_frame = wire_format::Frame {
        version: Some(wire_format::frame::Version::V1.into()),
        v1: Some(wire_format::V1Frame {
            r#type: Some(wire_format::v1_frame::FrameType::PairedKeyEncryption.into()),
            paired_key_encryption: Some(wire_format::PairedKeyEncryptionFrame {
                secret_id_hash: Some(rand::random::<[u8; 6]>().to_vec()),
                signed_data: Some(signed_data),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    
    let pke_data = pke_frame.encode_to_vec();
    send_encrypted_payload(socket, engine, seq, &pke_data).await?;
    println!("📤 Sent PairedKeyEncryption");
    Ok(())
}

/// Send PairedKeyResult frame (UNABLE) — sent as Direct OfflineFrame (NOT wrapped in PayloadTransfer)
/// Per HANDOVER doc: PKR uses "Direct OfflineFrame" unlike PKE which is wrapped.
async fn send_paired_key_result(
    socket: &mut TcpStream,
    engine: &SecurityEngine,
    seq: &mut SequenceCounter,
) -> Result<()> {
    let pkr_frame = wire_format::Frame {
        version: Some(wire_format::frame::Version::V1.into()),
        v1: Some(wire_format::V1Frame {
            r#type: Some(wire_format::v1_frame::FrameType::PairedKeyResult.into()),
            paired_key_result: Some(wire_format::PairedKeyResultFrame {
                status: Some(wire_format::paired_key_result_frame::Status::Unable.into()),
            }),
            ..Default::default()
        }),
    };
    
    let pkr_data = pkr_frame.encode_to_vec();
    
    // PKR is a "Direct OfflineFrame" — wrap in D2D + encrypt, but NO PayloadTransfer
    let d2d_msg = crate::proto::ukey2::DeviceToDeviceMessage {
        sequence_number: Some(seq.next()),
        message: Some(pkr_data),
    };
    let d2d_buf = d2d_msg.encode_to_vec();
    
    let gcm_meta = crate::proto::ukey2::GcmMetadata {
        r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(),
        version: Some(1),
    };
    let meta_bytes = gcm_meta.encode_to_vec();
    
    let encrypted = engine.encrypt_and_sign(&d2d_buf, Some(&meta_bytes))?;
    send_frame(socket, &encrypted).await?;
    println!("📤 Sent PairedKeyResult (UNABLE) — direct OfflineFrame");
    Ok(())
}

/// Read encrypted frames, skipping KeepAlives, until a frame matching `expected_type` is found.
///
/// Handles two frame layouts Android uses:
///   - Wrapped:  D2D → OfflineFrame → PayloadTransfer → body → wire_format::Frame  (PKE, Response)
///   - Direct:   D2D → wire_format::Frame directly                                  (PKR, KeepAlive)
async fn read_and_validate_next_frame(
    socket: &mut TcpStream,
    engine: &SecurityEngine,
    expected_type: wire_format::v1_frame::FrameType,
) -> Result<wire_format::Frame> {
    loop {
        let data = read_frame(socket).await?;
        println!("📥 Encrypted frame ({} bytes)", data.len());

        // Decrypt
        let decrypted = match engine.verify_and_decrypt(&data) {
            Ok(dec) => dec,
            Err(e) => {
                println!("❌ HMAC verification failed: {}", e);
                // Try force-decrypt (wrong key) to see if Android sent DISCONNECTION
                if let Ok(secure_msg) = SecureMessage::decode(data.as_slice()) {
                    if let Ok(hb) = HeaderAndBody::decode(&secure_msg.header_and_body[..]) {
                        if let Some(iv) = hb.header.iv {
                            let mut buf = hb.body.clone();
                            if let Ok(plaintext) = Aes256CbcDec::new(
                                &(*engine.get_decrypt_key()).into(),
                                iv.as_slice().into(),
                            )
                            .decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buf)
                            {
                                if let Ok(d2d) = crate::proto::ukey2::DeviceToDeviceMessage::decode(plaintext) {
                                    if let Some(msg) = d2d.message {
                                        if let Ok(offline) = quick_share::OfflineFrame::decode(msg.as_slice()) {
                                            if let Some(v1) = &offline.v1 {
                                                if v1.r#type == Some(quick_share::v1_frame::FrameType::Disconnection.into()) {
                                                    println!("⚠️ Android sent DISCONNECTION — key mismatch?");
                                                    return Err(anyhow::anyhow!("Android disconnected (crypto key mismatch)"));
                                                }
                                                println!("🔍 Force-decrypted frame type: {:?}", v1.r#type);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                return Err(e);
            }
        };

        let d2d_msg = crate::proto::ukey2::DeviceToDeviceMessage::decode(decrypted.as_slice())?;
        let msg_bytes = match d2d_msg.message {
            Some(b) => b,
            None => { println!("⚠️ D2D message has no inner payload"); continue; }
        };

        // --- Strategy 1: OfflineFrame → PayloadTransfer body → wire_format::Frame ---
        // Used for: PKE, Response
        if let Ok(offline) = quick_share::OfflineFrame::decode(msg_bytes.as_slice()) {
            if let Some(v1) = offline.v1 {
                if v1.r#type == Some(quick_share::v1_frame::FrameType::PayloadTransfer.into()) {
                    if let Some(pt) = v1.payload_transfer {
                        if let Some(chunk) = pt.payload_chunk {
                            if let Some(body) = chunk.body {
                                if !body.is_empty() {
                                    if let Ok(inner) = wire_format::Frame::decode(body.as_slice()) {
                                        if let Some(inner_v1) = &inner.v1 {
                                            if inner_v1.r#type == Some(expected_type.into()) {
                                                println!("📥 Received {:?} (wrapped)", expected_type);
                                                return Ok(inner);
                                            }
                                            println!("⚠️ Wrapped frame type {:?} ≠ expected {:?}", inner_v1.r#type, expected_type);
                                        }
                                        continue; // Not what we want, keep reading
                                    }
                                }
                            }
                        }
                    }
                } else if v1.r#type == Some(quick_share::v1_frame::FrameType::Disconnection.into()) {
                    println!("❌ Received DISCONNECTION from Android");
                    return Err(anyhow::anyhow!("Android sent DISCONNECTION"));
                }
            }
        }

        // --- Strategy 2: Direct wire_format::Frame ---
        // Used for: PKR (PairedKeyResult), KeepAlive
        if let Ok(direct) = wire_format::Frame::decode(msg_bytes.as_slice()) {
            if let Some(inner_v1) = &direct.v1 {
                if inner_v1.r#type == Some(wire_format::v1_frame::FrameType::KeepAlive.into()) {
                    println!("💤 Received KeepAlive — skipping");
                    continue;
                }
                if inner_v1.r#type == Some(expected_type.into()) {
                    println!("📥 Received {:?} (direct)", expected_type);
                    return Ok(direct);
                }
                println!("⚠️ Direct frame type {:?} ≠ expected {:?}", inner_v1.r#type, expected_type);
            }
        }

        println!("⚠️ Frame did not match {:?} — retrying", expected_type);
    }
}


/// Build file metadata for INTRODUCTION
fn build_file_metadata(files: &[PathBuf]) -> Result<Vec<wire_format::FileMetadata>> {
    let mut metadata = Vec::new();
    
    for path in files {
        if !path.is_file() {
            println!("⚠️ Skipping non-file: {}", path.display());
            continue;
        }
        
        let file_meta = std::fs::metadata(path)?;
        let file_name = path.file_name()
            .ok_or_else(|| anyhow!("Invalid filename"))?
            .to_string_lossy()
            .to_string();
        
        // Determine file type from extension
        let ext = path.extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        
        let (file_type, mime_type) = match ext.as_str() {
            "jpg" | "jpeg" => (1, "image/jpeg"),
            "png" => (1, "image/png"),
            "gif" => (1, "image/gif"),
            "webp" => (1, "image/webp"),
            "mp4" => (2, "video/mp4"),
            "mkv" => (2, "video/x-matroska"),
            "mp3" => (4, "audio/mpeg"),
            "pdf" => (5, "application/pdf"),
            "txt" => (5, "text/plain"),
            "apk" => (3, "application/vnd.android.package-archive"),
            _ => (5, "application/octet-stream"),
        };
        
        // Generate unique payload ID for each file
        let payload_id = rand::random::<i64>().abs();
        
        metadata.push(wire_format::FileMetadata {
            name: Some(file_name),
            r#type: Some(file_type),
            size: Some(file_meta.len() as i64),
            mime_type: Some(mime_type.to_string()),
            payload_id: Some(payload_id),
            ..Default::default()
        });
    }
    
    Ok(metadata)
}

/// Send INTRODUCTION frame with file metadata
async fn send_introduction(
    socket: &mut TcpStream,
    engine: &SecurityEngine,
    seq: &mut SequenceCounter,
    file_metadata: Vec<wire_format::FileMetadata>,
) -> Result<()> {
    let intro = wire_format::Frame {
        version: Some(wire_format::frame::Version::V1.into()),
        v1: Some(wire_format::V1Frame {
            r#type: Some(wire_format::v1_frame::FrameType::Introduction.into()),
            introduction: Some(wire_format::IntroductionFrame {
                file_metadata,
                ..Default::default()
            }),
            ..Default::default()
        }),
    };

    let intro_data = intro.encode_to_vec();
    send_encrypted_payload(socket, engine, seq, &intro_data).await?;
    println!("📤 Sent INTRODUCTION");
    Ok(())
}

/// Send an encrypted payload wrapped in PayloadTransfer
    // Send encrypted payload wrapped in PayloadTransfer
async fn send_encrypted_payload(
    socket: &mut TcpStream,
    engine: &SecurityEngine,
    seq: &mut SequenceCounter,
    payload: &[u8],
) -> Result<()> {
    let payload_id = rand::random::<i64>().abs();
    let payload_len = payload.len() as i64;
    
    // Create PayloadHeader
    let payload_header = quick_share::payload_transfer::PayloadHeader {
        id: Some(payload_id),
        r#type: Some(quick_share::payload_transfer::payload_header::PayloadType::Bytes.into()),
        total_size: Some(payload_len),
        is_sensitive: Some(false),
        ..Default::default()
    };
    
    // 1. Send Data Chunk (flags = 0)
    let payload_chunk = quick_share::payload_transfer::PayloadChunk {
        flags: Some(0), // Not last chunk
        offset: Some(0),
        body: Some(payload.to_vec()),
    };
    
    let payload_transfer = quick_share::PayloadTransfer {
        packet_type: Some(quick_share::payload_transfer::PacketType::Data.into()),
        payload_header: Some(payload_header.clone()),
        payload_chunk: Some(payload_chunk),
        control_message: None,
    };
    
    let offline_frame = quick_share::OfflineFrame {
        version: Some(1),
        v1: Some(quick_share::V1Frame {
            r#type: Some(quick_share::v1_frame::FrameType::PayloadTransfer.into()),
            payload_transfer: Some(payload_transfer),
            ..Default::default()
        }),
    };
    
    let offline_buf = offline_frame.encode_to_vec();
    println!("📦 Sending Encrypted Payload (Part 1/2). Inner Size: {} bytes. Seq: {}", payload.len(), seq.peek() + 1);

    let d2d_msg = crate::proto::ukey2::DeviceToDeviceMessage {
        sequence_number: Some(seq.next()),
        message: Some(offline_buf),
    };
    let d2d_buf = d2d_msg.encode_to_vec();
    
    let gcm_meta = crate::proto::ukey2::GcmMetadata {
        r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(),
        version: Some(1),
    };
    let meta_bytes = gcm_meta.encode_to_vec();
    
    let encrypted = engine.encrypt_and_sign(&d2d_buf, Some(&meta_bytes))?;
    send_frame(socket, &encrypted).await?;
    
    // 2. Send Empty Last Chunk (flags = 1)
    let end_chunk = quick_share::payload_transfer::PayloadChunk {
        flags: Some(1), // LAST_CHUNK
        offset: Some(payload_len),
        body: Some(vec![]),
    };
    
    let end_transfer = quick_share::PayloadTransfer {
        packet_type: Some(quick_share::payload_transfer::PacketType::Data.into()),
        payload_header: Some(payload_header),
        payload_chunk: Some(end_chunk),
        control_message: None,
    };
    
    let end_offline = quick_share::OfflineFrame {
        version: Some(1),
        v1: Some(quick_share::V1Frame {
            r#type: Some(quick_share::v1_frame::FrameType::PayloadTransfer.into()),
            payload_transfer: Some(end_transfer),
            ..Default::default()
        }),
    };
    
    let end_buf = end_offline.encode_to_vec();
    println!("📦 Sending Encrypted Payload (Part 2/2). Empty End Chunk. Seq: {}", seq.peek() + 1);
    
    let end_d2d = crate::proto::ukey2::DeviceToDeviceMessage {
        sequence_number: Some(seq.next()),
        message: Some(end_buf),
    };
    let end_d2d_buf = end_d2d.encode_to_vec();
    
    let end_encrypted = engine.encrypt_and_sign(&end_d2d_buf, Some(&meta_bytes))?;
    send_frame(socket, &end_encrypted).await?;
    
    Ok(())
}

/// Stream actual file bytes to Android after it has accepted the transfer.
///
/// Each file is sent as a series of `PayloadTransfer` (type=FILE) chunks encrypted inside D2D
/// messages. The `payload_id` in each chunk must match the one sent in the INTRODUCTION frame.
async fn stream_files(
    socket: &mut TcpStream,
    engine: &SecurityEngine,
    seq: &mut SequenceCounter,
    files: &[std::path::PathBuf],
    metadata: &[wire_format::FileMetadata],
) -> Result<()> {
    use tokio::io::AsyncReadExt as _;
    // 512 KB per chunk — large enough for throughput, small enough to avoid memory pressure.
    const CHUNK_SIZE: usize = 512 * 1024;

    let gcm_meta = crate::proto::ukey2::GcmMetadata {
        r#type: crate::proto::ukey2::Type::DeviceToDeviceMessage.into(),
        version: Some(1),
    };
    let meta_bytes = gcm_meta.encode_to_vec();

    for (path, meta) in files.iter().zip(metadata.iter()) {
        let payload_id = meta.payload_id.unwrap_or_else(|| rand::random::<i64>().abs());
        let total_size = std::fs::metadata(path)?.len();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| format!("file_{}", payload_id));

        println!("📤 Streaming '{}' ({} bytes, payload_id: {})", file_name, total_size, payload_id);

        let mut file = tokio::fs::File::open(path).await?;
        let mut chunk_buf = vec![0u8; CHUNK_SIZE];
        let mut offset: u64 = 0;
        let mut bytes_sent: u64 = 0;

        loop {
            let bytes_read = file.read(&mut chunk_buf).await?;
            if bytes_read == 0 {
                // EOF — all bytes have been sent
                break;
            }

            bytes_sent += bytes_read as u64;
            let is_last = bytes_sent >= total_size;
            let flags: i32 = if is_last { 1 } else { 0 }; // 1 = LAST_CHUNK

            let payload_transfer = quick_share::PayloadTransfer {
                packet_type: Some(quick_share::payload_transfer::PacketType::Data.into()),
                payload_header: Some(quick_share::payload_transfer::PayloadHeader {
                    id: Some(payload_id),
                    r#type: Some(2), // 2 = FILE type
                    total_size: Some(total_size as i64),
                    is_sensitive: Some(false),
                    ..Default::default()
                }),
                payload_chunk: Some(quick_share::payload_transfer::PayloadChunk {
                    flags: Some(flags),
                    offset: Some(offset as i64),
                    body: Some(chunk_buf[..bytes_read].to_vec()),
                }),
                control_message: None,
            };

            let offline_frame = quick_share::OfflineFrame {
                version: Some(1),
                v1: Some(quick_share::V1Frame {
                    r#type: Some(quick_share::v1_frame::FrameType::PayloadTransfer.into()),
                    payload_transfer: Some(payload_transfer),
                    ..Default::default()
                }),
            };

            let d2d_msg = crate::proto::ukey2::DeviceToDeviceMessage {
                sequence_number: Some(seq.next()),
                message: Some(offline_frame.encode_to_vec()),
            };

            let encrypted = engine.encrypt_and_sign(&d2d_msg.encode_to_vec(), Some(&meta_bytes))?;
            send_frame(socket, &encrypted).await?;

            offset += bytes_read as u64;

            let pct = (bytes_sent as f64 / total_size as f64 * 100.0) as u32;
            println!("📤 {}% ({}/{} bytes)", pct, bytes_sent, total_size);

            if is_last {
                println!("✅ Finished streaming '{}'", file_name);
                break;
            }
        }
    }

    println!("✅ All files streamed.");
    Ok(())
}

/// Send a frame with 4-byte big-endian length prefix
async fn send_frame(socket: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    socket.write_all(&len.to_be_bytes()).await?;
    socket.write_all(data).await?;
    socket.flush().await?;
    Ok(())
}

/// Read a frame with 4-byte big-endian length prefix
async fn read_frame(socket: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    
    if len > 5 * 1024 * 1024 {
        return Err(anyhow!("Frame too large: {} bytes", len));
    }
    
    let mut data = vec![0u8; len];
    socket.read_exact(&mut data).await?;
    Ok(data)
}
