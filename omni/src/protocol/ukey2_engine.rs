use crate::protocol::securegcm::{Ukey2ClientInit, Ukey2HandshakeCipher};
use anyhow::Result;
use rand::RngCore;
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::SystemRandom;

#[allow(dead_code)]
pub struct Ukey2Session {
    my_private_key: Option<EphemeralPrivateKey>,
    my_public_key: Vec<u8>,
}

impl Ukey2Session {
    /// Initialize a new session and generate an ephemeral Key Pair (Curve25519)
    pub fn new() -> Result<Self> {
        let rng = SystemRandom::new();
        let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate ephemeral private key"))?;
        
        // Compute public key
        let my_public_key = my_private_key.compute_public_key()
            .map_err(|_| anyhow::anyhow!("Failed to compute public key"))?
            .as_ref().to_vec();

        Ok(Self {
            my_private_key: Some(my_private_key),
            my_public_key,
        })
    }

    /// Generates the raw bytes for the Client Init message (Step 1 of Handshake)
    pub fn generate_client_init(&self) -> Ukey2ClientInit {
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);

        Ukey2ClientInit {
            version: Some(1),
            random: Some(random_bytes.to_vec()),
            // We use the standard phrasing seen in Google's implementation
            next_protocol: Some("AES_256_CBC-HMAC_SHA256".to_string()),
            // We support Curve25519 (Fast, Modern) and P256 (Legacy)
            cipher_commitments: vec![
                Ukey2HandshakeCipher::Curve25519Sha512 as i32,
                Ukey2HandshakeCipher::P256Sha512 as i32,
            ],
        }
    }
}
