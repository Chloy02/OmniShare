use crate::proto::securemessage::{
    SecureMessage, HeaderAndBody, Header, SigScheme, EncScheme,
};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use prost::Message;
use anyhow::{Result, anyhow};
use rand::RngCore;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

pub struct SecurityEngine {
    decrypt_key: [u8; 32],
    encrypt_key: [u8; 32],
    receive_hmac_key: [u8; 32],
    send_hmac_key: [u8; 32],
}

impl SecurityEngine {
    /// Initialize with the 4 keys derived from UKEY2
    pub fn new(
        d2d_client_key: &[u8],
        d2d_server_key: &[u8],
        // Note: UKEY2 usually derives different keys for HMAC, but for now we might reuse 
        // or need to check if we derive specific HMAC-specific keys. 
        // Based on doc: "Derive... D2D client key... D2D server key".
        // Doc also says: "Derive the four keys... Receive HMAC key... Send HMAC key" using specific info strings.
        // We need to verify if we did that. If not, we need to update ukey2.rs to derive all 4.
        // For now, let's assume we pass them in.
        receive_hmac_key: &[u8],
        send_hmac_key: &[u8],
    ) -> Self {
        let mut dk = [0u8; 32]; dk.copy_from_slice(d2d_client_key);
        let mut ek = [0u8; 32]; ek.copy_from_slice(d2d_server_key);
        let mut rhk = [0u8; 32]; rhk.copy_from_slice(receive_hmac_key);
        let mut shk = [0u8; 32]; shk.copy_from_slice(send_hmac_key);

        Self {
            decrypt_key: dk,
            encrypt_key: ek,
            receive_hmac_key: rhk,
            send_hmac_key: shk,
        }
    }

    /// Wraps a raw payload (e.g. OfflineFrame bytes) into a SecureMessage
    pub fn encrypt_and_sign(&self, payload: &[u8], public_metadata: Option<&[u8]>) -> Result<Vec<u8>> {
        // 1. Generate IV (16 bytes)
        let mut iv = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);

        // 2. Encrypt Payload (AES-256-CBC with PKCS7)
        let mut buf = vec![0u8; payload.len() + 16]; // Sufficient capacity for padding
        buf[..payload.len()].copy_from_slice(payload);
        
        let ct_len = Aes256CbcEnc::new(&self.encrypt_key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, payload.len())
            .map_err(|e| anyhow!("Encryption Error: {:?}", e))?
            .len();
        
        let ciphertext = &buf[..ct_len];

        // 3. Create Header
        let header = Header {
            signature_scheme: SigScheme::HmacSha256.into(),
            encryption_scheme: EncScheme::Aes256Cbc.into(),
            iv: Some(iv.to_vec()),
            public_metadata: public_metadata.map(|v| v.to_vec()),
            ..Default::default()
        };

        // 4. Create HeaderAndBody
        let header_and_body = HeaderAndBody {
            header: header,
            body: ciphertext.to_vec(),
        };
        
        let mut hb_bytes = Vec::new();
        header_and_body.encode(&mut hb_bytes)?;

        // 5. Sign (HMAC-SHA256)
        let mut mac = HmacSha256::new_from_slice(&self.send_hmac_key)
            .map_err(|_| anyhow!("HMAC Key Error"))?;
        mac.update(&hb_bytes);
        let signature = mac.finalize().into_bytes().to_vec();

        // 6. Wrap in SecureMessage
        let secure_msg = SecureMessage {
            header_and_body: hb_bytes,
            signature: signature,
        };

        let mut final_bytes = Vec::new();
        secure_msg.encode(&mut final_bytes)?;

        Ok(final_bytes)
    }

    /// Unwraps a SecureMessage, verifies sig, decrypts, and returns raw payload
    pub fn verify_and_decrypt(&self, secure_msg_bytes: &[u8]) -> Result<Vec<u8>> {
        let secure_msg = SecureMessage::decode(secure_msg_bytes)?;

        // 1. Verify Signature
        let mut mac = HmacSha256::new_from_slice(&self.receive_hmac_key)
            .map_err(|_| anyhow!("HMAC Key Error"))?;
        mac.update(&secure_msg.header_and_body);
        mac.verify_slice(&secure_msg.signature)
            .map_err(|_| anyhow!("HMAC Verification Failed!"))?;

        // 2. Decode HeaderAndBody
        let hb = HeaderAndBody::decode(&secure_msg.header_and_body[..])?;

        // 3. Validate Header
        if hb.header.encryption_scheme != EncScheme::Aes256Cbc.into() {
            return Err(anyhow!("Unsupported Encryption Scheme"));
        }
        let iv = hb.header.iv.ok_or_else(|| anyhow!("Missing IV"))?;
        if iv.len() != 16 {
            return Err(anyhow!("Invalid IV length"));
        }

        // 4. Decrypt Body
        let ciphertext = hb.body;
        let mut buf = ciphertext.clone(); // In-place decryption requires mut buffer
        
        let pt_len = Aes256CbcDec::new(&self.decrypt_key.into(), iv.as_slice().into())
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|e| anyhow!("Decryption Error: {:?}", e))?
            .len();

        Ok(buf[..pt_len].to_vec())
    }
}
