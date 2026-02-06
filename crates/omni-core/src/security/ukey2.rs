use anyhow::{anyhow, Result};
use ring::{agreement, rand};
use hkdf::Hkdf;
use sha2::Sha256;
use prost::Message;
use crate::proto::ukey2::{Ukey2Message, ukey2_message::Type as Ukey2Type, Ukey2ClientInit, Ukey2ServerInit, Ukey2ClientFinished, GenericPublicKey, EcP256PublicKey};

/// HKDF-Extract-Expand helper function matching rquickshare's implementation
fn hkdf_extract_expand(salt: &[u8], ikm: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(okm)
}

/// The UKEY2 Protocol Version we support (v1).
const UKEY2_VERSION: i32 = 1;

/// Initial State: We have generated our keys and are ready to process ClientInit.
pub struct Ukey2Server {
    my_private_key: agreement::EphemeralPrivateKey,
    pub my_public_key_bytes: Vec<u8>,
}

/// State after sending ServerInit: We are waiting for ClientFinished.
pub struct Ukey2ServerPending {
    my_private_key: agreement::EphemeralPrivateKey,
    _client_init_bytes: Vec<u8>, // Stored for v2 context
    _server_init_bytes: Vec<u8>, // Stored for v2 context
}

pub struct Ukey2SessionKeys {
    pub auth_string: Vec<u8>,
    pub d2d_client_key: Vec<u8>,
    pub d2d_server_key: Vec<u8>,
    pub decrypt_key: Vec<u8>,
    pub receive_hmac_key: Vec<u8>,
    pub encrypt_key: Vec<u8>,
    pub send_hmac_key: Vec<u8>,
}

#[allow(dead_code)]
pub struct HandshakeResult {
    pub auth_string: Vec<u8>,
    pub d2d_client_key: Vec<u8>,
    pub d2d_server_key: Vec<u8>,
}

impl Ukey2Server {
    pub fn new() -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| anyhow!("Failed to generate ECDH keypair"))?;
        
        // Compute Public Key
        let my_public_key_bytes = my_private_key.compute_public_key()
            .map_err(|_| anyhow!("Failed to compute public key"))?
            .as_ref()
            .to_vec();

        Ok(Self {
            my_private_key,
            my_public_key_bytes,
        })
    }

    /// Process ClientInit, Generate ServerInit, and transition to Pending state.
    // NOTE: client_init_outer_bytes must be the raw Ukey2Message (packet 2) from the wire.
    pub fn handle_client_init(self, client_init_outer_bytes: &[u8]) -> Result<(Vec<u8>, Ukey2ServerPending)> {
        // 1. Decode Outer Ukey2Message
        let ukey_msg = Ukey2Message::decode(client_init_outer_bytes)?;
        let client_init_data = ukey_msg.message_data.ok_or(anyhow!("Missing message_data in ClientInit"))?;
        
        // 2. Decode Inner ClientInit
        let client_init = Ukey2ClientInit::decode(client_init_data.as_slice())?;
        println!("UKEY2: Received ClientInit. Version: {:?}", client_init.version);
        for (i, commitment) in client_init.cipher_commitments.iter().enumerate() {
            println!("UKEY2: Commitment {}: Cipher={:?}", i, commitment.handshake_cipher);
        }
        if let Some(np) = &client_init.next_protocol {
            println!("UKEY2: Next Protocol: {:?} (String: {:?})", np, String::from_utf8_lossy(np));
        }

        // 3. Construct ServerInit with EcP256PublicKey
        // my_public_key_bytes is 65 bytes: [0x04, X (32 bytes), Y (32 bytes)]
        if self.my_public_key_bytes.len() != 65 {
            return Err(anyhow!("Invalid Public Key Length"));
        }
        let x_raw = &self.my_public_key_bytes[1..33];
        let y_raw = &self.my_public_key_bytes[33..65];

        let ec_key = EcP256PublicKey {
            x: Some(to_java_bigint(x_raw)),
            y: Some(to_java_bigint(y_raw)),
        };

        let my_generic_public_key = GenericPublicKey {
            r#type: Some(1), // 1 = EC_P256
            ec_p256_public_key: Some(ec_key),
        };

        // Fix for rand::generate: specify type array [u8; 32]
        let rng = rand::SystemRandom::new();
        let random_bytes: [u8; 32] = rand::generate(&rng)
            .map_err(|_| anyhow!("Random gen failed"))?
            .expose();

        let server_init = Ukey2ServerInit {
            version: Some(UKEY2_VERSION),
            random: Some(random_bytes.to_vec()),
            handshake_cipher: Some(100), // 100 = P256_SHA512
            public_key: Some(my_generic_public_key), 
        };

        let mut server_init_buf = Vec::new();
        server_init.encode(&mut server_init_buf)?;
        
        // Wrap in Ukey2Message
        let ukey2_reply = Ukey2Message {
            message_type: Some(Ukey2Type::ServerInit.into()),
            message_data: Some(server_init_buf.clone()),
        };

        let mut reply_buf = Vec::new();
        ukey2_reply.encode(&mut reply_buf)?;

        Ok((reply_buf.clone(), Ukey2ServerPending {
            my_private_key: self.my_private_key,
            _client_init_bytes: client_init_outer_bytes.to_vec(), // Store OUTER Bytes
            _server_init_bytes: reply_buf, // Store OUTER Bytes
        }))
    }
}

impl Ukey2ServerPending {
    /// Finish the handshake by processing ClientFinished and deriving keys.
    pub fn handle_client_finished(self, client_finished_msg_data: &[u8]) -> Result<Ukey2SessionKeys> {
         // 1. Decode ClientFinished
         let client_finished = Ukey2ClientFinished::decode(client_finished_msg_data)?;
         
         // 2. Extract Public Key
         let generic_pk = client_finished.public_key.ok_or(anyhow!("Missing Client Public Key"))?;
         
         // Extract X and Y from EcP256PublicKey
         let ec_key = generic_pk.ec_p256_public_key.ok_or(anyhow!("Missing EC Key in GenericPublicKey"))?;
         let x_pad = ec_key.x.ok_or(anyhow!("Missing X coordinate"))?;
         let y_pad = ec_key.y.ok_or(anyhow!("Missing Y coordinate"))?;
         
         let x = from_java_bigint(&x_pad);
         let y = from_java_bigint(&y_pad);

         // Reconstruct [0x04, X, Y]
         let mut peer_public_key_bytes = Vec::with_capacity(65);
         peer_public_key_bytes.push(0x04);
         peer_public_key_bytes.extend_from_slice(&x);
         peer_public_key_bytes.extend_from_slice(&y);

         // 3. Perform ECDH
         let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer_public_key_bytes);
         
         let shared_secret = agreement::agree_ephemeral(
            self.my_private_key,
            &peer_public_key,
            |key_material| key_material.to_vec(),
        ).map_err(|_| anyhow!("ECDH Agreement Failed"))?;

        // UKEY2 v1 requires SHA256 hash of the raw ECDH shared secret
        use sha2::{Digest, Sha256};
        let shared_secret = Sha256::digest(&shared_secret).to_vec();

        // 4. Derive UKEY2 Keys (Phase 1: Auth String and Next Protocol Secret)
        // Per Google UKEY2 spec: https://github.com/google/ukey2
        // PRK_AUTH = HKDF-Extract("UKEY2 v1 auth", DHS)
        // AUTH_STRING = HKDF-Expand(PRK_AUTH, M_1|M_2, L_auth)
        
        // Build transcript: M_1|M_2 (ClientInit | ServerInit)
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&self._client_init_bytes);
        transcript.extend_from_slice(&self._server_init_bytes);
        
        // Derive Auth String (using hkdf crate like rquickshare)
        let auth_string = hkdf_extract_expand(b"UKEY2 v1 auth", &shared_secret, &transcript, 32)?;

        // Derive Next Protocol Secret
        let next_protocol_secret = hkdf_extract_expand(b"UKEY2 v1 next", &shared_secret, &transcript, 32)?;

        // --- DERIVATION PHASE 2: D2D KEYS (From Next Protocol Secret) ---
        let d2d_salt = hex::decode("82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510").unwrap();
        let d2d_client_key = hkdf_extract_expand(&d2d_salt, &next_protocol_secret, b"client", 32)?;
        let d2d_server_key = hkdf_extract_expand(&d2d_salt, &next_protocol_secret, b"server", 32)?;

        // --- DERIVATION PHASE 3: SECURE MESSAGE KEYS (AES & HMAC) ---
        // "All four use the same value of salt, which is SHA256('SecureMessage')"
        // BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E
        let sm_salt = hex::decode("BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E").unwrap();
        
        // SERVER (That's US in inbound handler):
        // - We DECRYPT messages FROM the CLIENT (Android), so use D2D_CLIENT_KEY
        // - We ENCRYPT messages TO the CLIENT, so use D2D_SERVER_KEY

        // Decrypt Key (IKM = D2D Client Key - messages FROM client)
        let decrypt_key = hkdf_extract_expand(&sm_salt, &d2d_client_key, b"ENC:2", 32)?;
        // Receive HMAC Key (IKM = D2D Client Key - verify HMACs FROM client)
        let receive_hmac_key = hkdf_extract_expand(&sm_salt, &d2d_client_key, b"SIG:1", 32)?;
        // Encrypt Key (IKM = D2D Server Key - our messages TO client)
        let encrypt_key = hkdf_extract_expand(&sm_salt, &d2d_server_key, b"ENC:2", 32)?;
        // Send HMAC Key (IKM = D2D Server Key - sign our messages)
        let send_hmac_key = hkdf_extract_expand(&sm_salt, &d2d_server_key, b"SIG:1", 32)?;

        Ok(Ukey2SessionKeys {
            auth_string,
            d2d_client_key, // Keeping these for debug logging, but effectively unused now
            d2d_server_key, // Keeping these for debug logging
            decrypt_key,
            receive_hmac_key,
            encrypt_key,
            send_hmac_key,
        })
    }
}

/// Helper: Pad with 0x00 if the bytes would be interpreted as negative by Java BigInteger (MSB set).
fn to_java_bigint(bytes: &[u8]) -> Vec<u8> {
    if let Some(&first_byte) = bytes.first() {
        if first_byte >= 0x80 {
            let mut v = Vec::with_capacity(bytes.len() + 1);
            v.push(0x00);
            v.extend_from_slice(bytes);
            return v;
        }
    }
    bytes.to_vec()
}

/// Helper: Strip leading 0x00 padding if present (Java BigInteger artifact).
fn from_java_bigint(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() > 32 { // Assuming 32-byte expected length for P-256 coords
        // Take the last 32 bytes (safest assumption for fixed size keys)
        let split_idx = bytes.len().saturating_sub(32);
        bytes[split_idx..].to_vec()
    } else {
        bytes.to_vec()
    }
}

// ============================================================================
// UKEY2 CLIENT (For Outbound Connections - We are the initiator)
// ============================================================================

/// Initial State: We generate our keys and send ClientInit.
pub struct Ukey2Client {
    my_private_key: agreement::EphemeralPrivateKey,
    pub my_public_key_bytes: Vec<u8>,
    client_init_bytes: Vec<u8>,
    client_finished_bytes: Vec<u8>,
}

/// State after sending ClientInit: We are waiting for ServerInit.
pub struct Ukey2ClientPending {
    my_private_key: agreement::EphemeralPrivateKey,
    client_init_bytes: Vec<u8>,
    _client_finished_bytes: Vec<u8>,
    server_init_bytes: Vec<u8>,
}

impl Ukey2Client {
    /// Create a new UKEY2 client and generate ClientInit message.
    /// Returns (client_init_message, Ukey2Client)
    pub fn new() -> Result<(Vec<u8>, Self)> {
        let rng = rand::SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(|_| anyhow!("Failed to generate ECDH keypair"))?;
        
        // Compute Public Key
        let my_public_key_bytes = my_private_key.compute_public_key()
            .map_err(|_| anyhow!("Failed to compute public key"))?
            .as_ref()
            .to_vec();

        // Construct EcP256PublicKey for ClientFinished
        let x_raw = &my_public_key_bytes[1..33];
        let y_raw = &my_public_key_bytes[33..65];

        let ec_key = EcP256PublicKey {
            x: Some(to_java_bigint(x_raw)),
            y: Some(to_java_bigint(y_raw)),
        };

        let my_generic_public_key = GenericPublicKey {
            r#type: Some(1), // 1 = EC_P256
            ec_p256_public_key: Some(ec_key),
        };

        // Pre-construct ClientFinished (needed for commitment in ClientInit)
        let client_finished = Ukey2ClientFinished {
            public_key: Some(my_generic_public_key),
        };
        let mut client_finished_bytes = Vec::new();
        client_finished.encode(&mut client_finished_bytes)?;

        // Wrap in Ukey2Message for ClientFinished
        let client_finished_msg = Ukey2Message {
            message_type: Some(Ukey2Type::ClientFinished.into()),
            message_data: Some(client_finished_bytes.clone()),
        };
        let mut client_finished_outer = Vec::new();
        client_finished_msg.encode(&mut client_finished_outer)?;

        // Create SHA-512 commitment of ClientFinished
        use sha2::{Digest, Sha512};
        let commitment = Sha512::digest(&client_finished_outer).to_vec();

        // Generate random bytes
        let random_bytes: [u8; 32] = rand::generate(&rng)
            .map_err(|_| anyhow!("Random gen failed"))?
            .expose();

        // Construct ClientInit
        use crate::proto::ukey2::CipherCommitment;
        let client_init = Ukey2ClientInit {
            version: Some(UKEY2_VERSION),
            random: Some(random_bytes.to_vec()),
            cipher_commitments: vec![CipherCommitment {
                handshake_cipher: Some(100), // 100 = P256_SHA512
                commitment: Some(commitment),
            }],
            next_protocol: Some(b"AES_256_CBC-HMAC_SHA256".to_vec()),
        };

        let mut client_init_inner = Vec::new();
        client_init.encode(&mut client_init_inner)?;

        // Wrap in Ukey2Message
        let client_init_msg = Ukey2Message {
            message_type: Some(Ukey2Type::ClientInit.into()),
            message_data: Some(client_init_inner),
        };
        let mut client_init_bytes = Vec::new();
        client_init_msg.encode(&mut client_init_bytes)?;

        println!("UKEY2 Client: Generated ClientInit ({} bytes)", client_init_bytes.len());

        Ok((client_init_bytes.clone(), Self {
            my_private_key,
            my_public_key_bytes,
            client_init_bytes,
            client_finished_bytes: client_finished_outer,
        }))
    }

    /// Process ServerInit and transition to pending state.
    pub fn handle_server_init(self, server_init_outer_bytes: &[u8]) -> Result<(Vec<u8>, Ukey2ClientPending)> {
        // 1. Decode outer Ukey2Message
        let ukey_msg = Ukey2Message::decode(server_init_outer_bytes)?;
        let server_init_data = ukey_msg.message_data.ok_or(anyhow!("Missing message_data in ServerInit"))?;
        
        // 2. Decode ServerInit
        let server_init = Ukey2ServerInit::decode(server_init_data.as_slice())?;
        println!("UKEY2 Client: Received ServerInit. Version: {:?}, Cipher: {:?}", 
                 server_init.version, server_init.handshake_cipher);

        // Validate version and cipher
        if server_init.version != Some(1) {
            return Err(anyhow!("Unsupported UKEY2 version"));
        }
        if server_init.handshake_cipher != Some(100) {
            return Err(anyhow!("Unsupported handshake cipher"));
        }

        // 3. Return ClientFinished message
        println!("UKEY2 Client: Sending ClientFinished ({} bytes)", self.client_finished_bytes.len());

        Ok((self.client_finished_bytes.clone(), Ukey2ClientPending {
            my_private_key: self.my_private_key,
            client_init_bytes: self.client_init_bytes,
            _client_finished_bytes: self.client_finished_bytes,
            server_init_bytes: server_init_outer_bytes.to_vec(),
        }))
    }
}

impl Ukey2ClientPending {
    /// Finalize the handshake by deriving keys.
    /// Call this after receiving the peer's ConnectionResponse.
    pub fn finalize(self, server_init_outer_bytes: &[u8]) -> Result<Ukey2SessionKeys> {
        // 1. Extract server's public key from ServerInit
        let ukey_msg = Ukey2Message::decode(server_init_outer_bytes)?;
        let server_init_data = ukey_msg.message_data.ok_or(anyhow!("Missing message_data"))?;
        let server_init = Ukey2ServerInit::decode(server_init_data.as_slice())?;
        
        let generic_pk = server_init.public_key.ok_or(anyhow!("Missing Server Public Key"))?;
        let ec_key = generic_pk.ec_p256_public_key.ok_or(anyhow!("Missing EC Key"))?;
        let x_pad = ec_key.x.ok_or(anyhow!("Missing X coordinate"))?;
        let y_pad = ec_key.y.ok_or(anyhow!("Missing Y coordinate"))?;
        
        println!("DEBUG: Raw X len={}, Raw Y len={}", x_pad.len(), y_pad.len());
        
        let x = from_java_bigint(&x_pad);
        let y = from_java_bigint(&y_pad);

        println!("DEBUG: After from_java_bigint: X len={}, Y len={}", x.len(), y.len());

        // Reconstruct [0x04, X, Y]
        let mut peer_public_key_bytes = Vec::with_capacity(65);
        peer_public_key_bytes.push(0x04);
        // Ensure 32 bytes each, pad with leading zeros if needed
        let x_padded: Vec<u8> = std::iter::repeat(0u8).take(32_usize.saturating_sub(x.len())).chain(x.iter().cloned()).collect();
        let y_padded: Vec<u8> = std::iter::repeat(0u8).take(32_usize.saturating_sub(y.len())).chain(y.iter().cloned()).collect();
        peer_public_key_bytes.extend_from_slice(&x_padded);
        peer_public_key_bytes.extend_from_slice(&y_padded);
        
        println!("DEBUG: Final point: X_padded len={}, Y_padded len={}, Total len={}", 
                 x_padded.len(), y_padded.len(), peer_public_key_bytes.len());

        // 2. Perform ECDH
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer_public_key_bytes);
        
        let shared_secret = agreement::agree_ephemeral(
            self.my_private_key,
            &peer_public_key,
            |key_material| key_material.to_vec(),
        ).map_err(|_| anyhow!("ECDH Agreement Failed"))?;

        // SHA256 hash of raw ECDH secret
        // SHA256 hash of raw ECDH secret
        use sha2::{Digest, Sha256};
        let shared_secret = Sha256::digest(&shared_secret).to_vec();
        println!("DEBUG: Shared Secret Len: {}", shared_secret.len());
        println!("DEBUG: Peer Public Key (padded): X len={}, Y len={}", x_padded.len(), y_padded.len());

        // 3. Build transcript: M_1|M_2 (ClientInit | ServerInit)
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&self.client_init_bytes);
        transcript.extend_from_slice(&self.server_init_bytes);

        // 4. Derive Auth String (using hkdf crate like rquickshare)
        let auth_string = hkdf_extract_expand(b"UKEY2 v1 auth", &shared_secret, &transcript, 32)?;

        // 5. Derive Next Protocol Secret
        let next_protocol_secret = hkdf_extract_expand(b"UKEY2 v1 next", &shared_secret, &transcript, 32)?;

        // 6. Derive D2D Keys
        let d2d_salt = hex::decode("82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510").unwrap();
        let d2d_client_key = hkdf_extract_expand(&d2d_salt, &next_protocol_secret, b"client", 32)?;
        let d2d_server_key = hkdf_extract_expand(&d2d_salt, &next_protocol_secret, b"server", 32)?;

        // 7. Derive SecureMessage Keys
        // CRITICAL: As CLIENT, keys are SWAPPED compared to server:
        // - We ENCRYPT with Client Key (we are the client)
        // - We DECRYPT with Server Key (messages from server)
        let sm_salt = hex::decode("BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E").unwrap();

        // Encrypt Key (IKM = D2D Client Key - we are client)
        let encrypt_key = hkdf_extract_expand(&sm_salt, &d2d_client_key, b"ENC:2", 32)?;
        // Send HMAC Key (IKM = D2D Client Key)
        let send_hmac_key = hkdf_extract_expand(&sm_salt, &d2d_client_key, b"SIG:1", 32)?;

        // Decrypt Key (IKM = D2D Server Key - messages from server)
        let decrypt_key = hkdf_extract_expand(&sm_salt, &d2d_server_key, b"ENC:2", 32)?;
        // Receive HMAC Key (IKM = D2D Server Key)
        let receive_hmac_key = hkdf_extract_expand(&sm_salt, &d2d_server_key, b"SIG:1", 32)?;

        // ==== DEBUG: Print all derived keys (first 8 bytes hex) ====
        println!("=== UKEY2 Key Derivation Debug ===");
        println!("  Transcript Len: {} (ClientInit={}, ServerInit={})", 
                 transcript.len(), self.client_init_bytes.len(), self.server_init_bytes.len());
        println!("  Shared Secret (first 8): {}", hex::encode(&shared_secret[..8]));
        println!("  Next Protocol Secret (first 8): {}", hex::encode(&next_protocol_secret[..8]));
        println!("  D2D Client Key (first 8): {}", hex::encode(&d2d_client_key[..8]));
        println!("  D2D Server Key (first 8): {}", hex::encode(&d2d_server_key[..8]));
        println!("  --- SecureMessage Keys (CLIENT role) ---");
        println!("  Encrypt Key (first 8): {}", hex::encode(&encrypt_key[..8]));
        println!("  Send HMAC Key (first 8): {}", hex::encode(&send_hmac_key[..8]));
        println!("  Decrypt Key (first 8): {}", hex::encode(&decrypt_key[..8]));
        println!("  Recv HMAC Key (first 8): {}", hex::encode(&receive_hmac_key[..8]));
        println!("==================================");

        Ok(Ukey2SessionKeys {
            auth_string,
            d2d_client_key,
            d2d_server_key,
            decrypt_key,
            receive_hmac_key,
            encrypt_key,
            send_hmac_key,
        })
    }
}
