use anyhow::{anyhow, Result};
use ring::{agreement, rand, hkdf, hmac};
use prost::Message;
use crate::proto::ukey2::{Ukey2Message, ukey2_message::Type as Ukey2Type, Ukey2ClientInit, Ukey2ServerInit, Ukey2ClientFinished, GenericPublicKey, EcP256PublicKey};

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
    pub fn handle_client_init(self, client_init_msg_data: &[u8]) -> Result<(Vec<u8>, Ukey2ServerPending)> {
        // 1. Decode ClientInit just to validate it
        let _client_init = Ukey2ClientInit::decode(client_init_msg_data)?;
        
        // 2. Construct ServerInit with EcP256PublicKey
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

        // Fix for rand::generate: specify type array [u8; 16] - Wait, used u8;32 before?
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

        Ok((reply_buf, Ukey2ServerPending {
            my_private_key: self.my_private_key,
            _client_init_bytes: client_init_msg_data.to_vec(),
            _server_init_bytes: server_init_buf,
        }))
    }
}

impl Ukey2ServerPending {
    /// Finish the handshake by processing ClientFinished and deriving keys.
    pub fn handle_client_finished(self, client_finished_msg_data: &[u8]) -> Result<HandshakeResult> {
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

        // 4. Derive UKEY2 Keys
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]); 
        let prk = salt.extract(&shared_secret);

        let info_auth = [b"UKEY2 v1 auth".as_slice()];
        let okm_auth = prk.expand(&info_auth, hmac::HMAC_SHA256)
            .map_err(|_| anyhow!("HKDF Expand Auth Failed"))?;
        let mut auth_string = vec![0u8; 32];
        okm_auth.fill(&mut auth_string).map_err(|_| anyhow!("HKDF Fill Auth Failed"))?;

        let info_next = [b"UKEY2 v1 next".as_slice()];
        let okm_next = prk.expand(&info_next, hmac::HMAC_SHA256)
             .map_err(|_| anyhow!("HKDF Expand Next Failed"))?;
        let mut next_protocol_secret = vec![0u8; 32];
        okm_next.fill(&mut next_protocol_secret).map_err(|_| anyhow!("HKDF Fill Next Failed"))?;

        // 5. Derive D2D Keys
        let d2d_salt_bytes = hex::decode("82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510").unwrap();
        let d2d_salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &d2d_salt_bytes);
        let d2d_prk = d2d_salt.extract(&next_protocol_secret);

        // Client Key
        let info_client = [b"client".as_slice()];
        let okm_client = d2d_prk.expand(&info_client, hmac::HMAC_SHA256).map_err(|_| anyhow!("HKDF D2D Client"))?;
        let mut d2d_client_key = vec![0u8; 32];
        okm_client.fill(&mut d2d_client_key).map_err(|_| anyhow!("HKDF Fill D2D Client"))?;

        // Server Key
        let info_server = [b"server".as_slice()];
        let okm_server = d2d_prk.expand(&info_server, hmac::HMAC_SHA256).map_err(|_| anyhow!("HKDF D2D Server"))?;
        let mut d2d_server_key = vec![0u8; 32];
        okm_server.fill(&mut d2d_server_key).map_err(|_| anyhow!("HKDF Fill D2D Server"))?;

        Ok(HandshakeResult {
            auth_string,
            d2d_client_key,
            d2d_server_key,
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
