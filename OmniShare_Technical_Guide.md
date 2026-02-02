# OmniShare: The Internals (Deep Dive)

**Version:** 3.0 (The File Transfer Edition)  
**Target Audience:** Systems Engineers, Security Researchers, Cryptographers, Protocol Developers.  
**Status:** ✅ Working - Successfully receiving files from Android devices

---

## 1. Introduction: The "Zero-Install" Philosophy & Methodology

OmniShare bridges the ecosystem gap between Linux and Android without requiring a companion app. It achieves this by emulating the proprietary **Quick Share** (formerly Nearby Share) protocol directly at the packet layer.

### 1.1 Methodology: The Art of Reverse Engineering

Our approach relies on "Black Box" analysis, as the official protocol documentation is non-existent.

1.  **Pattern Recognition**: By analyzing raw hex dumps of TCP streams, we identify recurring headers (e.g., `0xFC`, `0x12`) and structure (Length-Prefixed Protobufs).
2.  **Differential Analysis**: We compare our logs against open-source partial implementations (like `NearDrop` and `rquickshare`) to identify discrepancies in field IDs and wire types.
3.  **Hypothesis Testing**: When decoding fails, we formulate hypotheses (e.g., "Is this frame wrapped inside another frame?") and implement "Strategies" in code to validate them. Identifying the "Matryoshka Doll" structure of the frames was a direct result of this.

---

## 2. Part 1: The Physics of Discovery

How do two devices find each other in a room full of radio noise?

### 2.1 Bluetooth Low Energy (BLE) Legacy Advertising

Android phones rely on the Bluetooth Low Energy (BLE) radio (~15μA power draw) rather than WiFi (~200mA) for background scanning.

#### The "Legacy" Constraint
We typically use **Legacy Advertising** (31 bytes max) because Android's hardware offload filters—which wake the main CPU—often ignore the newer Extended Advertising extensions.

**The Packet Anatomy:**
*   **Service UUID:** `0xFE2C` (Google Fast Pair Service).
*   **Model ID:** `0xFC128E` ("Quick Share").
*   **Salt:** 10 Random Bytes. (Prevents tracking users by persistent BLE signatures).

### 2.2 Multicast DNS (mDNS) / RFC 6762

Once "woken up" by BLE, the phone uses mDNS over WiFi to resolve the identity (IP/Port).

*   **Service Type:** `_FC9F5ED42C8A._tcp` (The hash of "NearbySharing").
*   **TXT Record (`n`):** Contains the "Endpoint Info" (Base64 encoded):
    *   Version, Visibility (Contacts/All), Device Type (Phone/Tablet/Laptop), and Device Name.
*   **Instance Name:** `Base64([PCP][EndpointID][ServiceHash][Padding])`. Validation fails if this specific format isn't met.

---

## 3. Part 2: The Cryptographic Handshake (UKEY2)

Quick Share uses **UKEY2** (User exchange Key exchange protocol v2). While theoretically standard, Android's implementation has specific quirks.

### 3.1 The Mathematics of Key Exchange (ECDH)
We use **Elliptic Curve Diffie-Hellman** (ECDH) on the **P-256** curve (secp256r1).

**The Equation:**
$$ S = d_A \times Q_B $$
Where:
*   $d_A$ is our Private Key (random scalar).
*   $Q_B$ is the Phone's Public Key (point on curve).
*   $S$ is the Shared Secret point $(x, y)$.

**The Serialize Quirk (Java BigInteger):**
Android's Java Crypto implementation treats byte arrays as *Signed Two's Complement*.
*   **The Crash:** If our random public key coordinate starts with a bit `1` (e.g., `0x80...`), Java interprets it as a negative number. P-256 coordinates are strictly positive.
*   **The Fix:** We must prepend a `0x00` byte if the MSB is 1, sending 33 bytes instead of 32. This ensures the value is interpreted as positive.

### 3.2 Key Derivation (HKDF-SHA256)
Once we have the raw ECDH shared secret ($S$), we don't use it directly. We use **HKDF** (HMAC-based Extract-and-Expand Key Derivation Function) to derive session keys.

1.  **Extract:**
    $$ PRK = HMAC\_SHA256(salt="UKEY2 v1", IKM=S_x) $$

2.  **Expand:**
    We derive two 32-byte keys:
    *   **D2D Client Key:** Info = `"client"`. Used by the Client (Phone) to *Encrypt*.
    *   **D2D Server Key:** Info = `"server"`. Used by the Server (Us) to *Encrypt*.

**Crucial Role Swap:**
*   To **Decrypt** incoming messages, we must use the **Client Key** (because the Phone encrypted it).
*   To **Encrypt** outgoing messages, we must use the **Server Key**.

---

## 4. Part 3: The Secure Frame Layer (The "Matryoshka Doll")

Once encryption is established, the protocol creates a complex nesting of frames.

### 4.1 The Onion Structure
Every packet on the wire (after the handshake) follows this structure:

1.  **Layer 1: SecureMessage** (Google Internal Proto)
    *   Contains `signature` (HMAC-SHA256).
    *   Contains `header_and_body` (AES-256-CBC Encrypted Blob).
    *   *Crypto:* AES-CBC requires an IV (Initialization Vector). This is stored in the Header.

2.  **Layer 2: DeviceToDeviceMessage** (Inside the AES Decryption)
    *   Contains `sequence_number` (To prevent replay attacks).
    *   Contains `message` (The actual payload).

3.  **Layer 3: OfflineFrame** (The Quick Share Standard)
    *   This is where things get tricky.
    *   It can be a simple control frame (e.g., `KeepAlive`).
    *   OR, it can be a container for data (`PayloadTransfer`).

### 4.2 The "PayloadTransfer" Trap
For critical frames like `PairedKeyEncryption` or the File `Introduction`, Quick Share does **not** send them as simple Control Frames. It wraps them as if they were file chunks.

**The Wrapping Logic:**
```
OfflineFrame (Type: PAYLOAD_TRANSFER)
  ↳ PayloadHeader (Type: BYTES or FILE, ID, Total Size)
  ↳ PayloadChunk
      ↳ body (Raw Bytes)
          ↳ SharingFrame (The *real* message)
```

**PayloadHeader Types:**
| Type | Name | Purpose |
| :--- | :--- | :--- |
| 1 | `BYTES` | Control/Protocol messages (INTRODUCTION, PKE, PKR, etc.) |
| 2 | `FILE` | Actual file data chunks |

**Strategy 2 (Recursive Unwrapping):**
Our implementation implements a "Strategy 2" decoder:
1.  Try decoding `DeviceToDevice` payload directly as `SharingFrame`. (Fails for wrapped messages).
2.  Try decoding as `OfflineFrame`.
3.  If `OfflineFrame.type == PAYLOAD_TRANSFER`, extract the `body` bytes from `payload_chunk`.
4.  Recursively decode those bytes as `SharingFrame`.

**Why?** This unifies the code path for sending small control structures (like encryption proofs) and large files (photos/videos). The `Introduction` frame (file list) could be larger than a single TCP packet, so wrapping it in `PayloadTransfer` allows it to be chunked.

### 4.3 Frame Types Discovered

| Type | Name | Purpose | Behavior |
| :--- | :--- | :--- | :--- |
| 1 | `INTRODUCTION` | File Metadata | Wrapped in `PayloadTransfer`. Contains Filename, Size, MIME type, payload_id. |
| 2 | `RESPONSE` | User Acceptance | Sent by Receiver to Accept/Reject transfer. Phone also sends back to confirm. |
| 3 | `PAIRED_KEY_ENCRYPTION` | Auth Proof | Wrapped. Proves we own the session keys. |
| 4 | `PAIRED_KEY_RESULT` | Auth Status | Success/Fail/Unable status of verification. |
| 6 | `CANCEL` | Cancellation | Abort transfer. |
| 12 | `KEEP_ALIVE` | Heartbeat | Prevents timeout. Requires Ack response. |

---

## 5. Part 4: File Transfer Protocol

This section documents the complete file transfer flow, including critical bugs we encountered and fixes.

### 5.1 The Complete Transfer Handshake

```
┌─────────────┐                            ┌─────────────┐
│   Phone     │                            │  OmniShare  │
│  (Client)   │                            │  (Server)   │
└─────────────┘                            └─────────────┘
       │                                          │
       │  ─────── CONNECTION_REQUEST ──────────>  │  TCP Connect
       │  <────── CONNECTION_RESPONSE (ACCEPT) ── │
       │                                          │
       │  ─────── UKEY2 CLIENT_INIT ───────────>  │  Key Exchange
       │  <────── UKEY2 SERVER_INIT ───────────── │
       │  ─────── UKEY2 CLIENT_FINISHED ───────>  │
       │                                          │
       │  <────── CONNECTION_RESPONSE (ACCEPT) ── │  Plaintext
       │  ─────── CONNECTION_RESPONSE (ACCEPT) ─> │  Plaintext
       │                                          │
       │         ═══ ENCRYPTED MODE ═══          │
       │                                          │
       │  <────── PAIRED_KEY_ENCRYPTION ───────── │  Wrapped in PayloadTransfer
       │  ─────── PAIRED_KEY_ENCRYPTION ───────>  │  Wrapped in PayloadTransfer
       │                                          │
       │  <────── PAIRED_KEY_RESULT (UNABLE) ──── │  We don't have paired keys
       │  ─────── PAIRED_KEY_RESULT (UNABLE) ──>  │  Phone doesn't either
       │                                          │
       │  ─────── INTRODUCTION ────────────────>  │  File metadata (name, size, payload_id)
       │  <────── RESPONSE (ACCEPT) ───────────── │  We accept the transfer
       │  ─────── RESPONSE (ACCEPT) ───────────>  │  Phone confirms, ready to send
       │                                          │
       │  ─────── FILE_CHUNKS (Type=FILE) ─────>  │  Actual file data
       │  ─────── FILE_CHUNKS (Type=FILE) ─────>  │  ...multiple chunks...
       │  ─────── LAST_CHUNK (flags=1) ────────>  │  Transfer complete signal
       │                                          │
       │  ═══════ FILE SAVED TO DISK ════════════ │
```

### 5.2 Critical Bug #1: PayloadTransfer Wrapping for Outgoing Frames

**Symptom:** Phone receives our frames but doesn't respond, eventually times out.

**Root Cause:** We were sending raw `SharingFrame` messages, but the protocol requires ALL encrypted frames to be wrapped in `PayloadTransfer` + `OfflineFrame`.

**Fix Implementation:**
```rust
// WRONG: Sending raw SharingFrame
let frame = SharingFrame { ... };
socket.write(frame.encode())?;

// CORRECT: Wrap in PayloadTransfer + OfflineFrame
let sharing_frame = SharingFrame { ... };
let sharing_bytes = sharing_frame.encode_to_vec();

let payload_transfer = PayloadTransfer {
    payload_header: Some(PayloadHeader {
        id: Some(unique_payload_id),
        r#type: Some(1), // BYTES for control messages
        total_size: Some(sharing_bytes.len() as i64),
        is_sensitive: Some(false),
    }),
    payload_chunk: Some(PayloadChunk {
        offset: Some(0),
        flags: Some(0), // 0 = more chunks coming
        body: Some(sharing_bytes),
    }),
    ..Default::default()
};

let offline_frame = OfflineFrame {
    version: Some(1),
    v1: Some(V1Frame {
        r#type: Some(3), // PAYLOAD_TRANSFER
        payload_transfer: Some(payload_transfer),
        ..Default::default()
    }),
};

// Also must send END marker (flags=1, no body)
let end_marker = create_end_marker(payload_id);
```

### 5.3 Critical Bug #2: LAST_CHUNK with Empty Body

**Symptom:** File data is buffered correctly, but file never saves to disk.

**Root Cause:** The `LAST_CHUNK` signal (flags=1) arrives in a **separate packet with no body**. Our save logic was inside the "if body exists" branch.

**Debug Evidence:**
```
TCP Handler: PayloadChunk -> Flags: Some(1), Offset: Some(1880742), Body Len: None
TCP Handler: PayloadChunk body is None  // <-- Save never triggered!
```

**Fix:** Handle LAST_CHUNK even when body is None:
```rust
if let Some(body) = &chunk.body {
    // Buffer the chunk
    file_buffers.entry(payload_id).or_insert_with(Vec::new).extend_from_slice(&body);
    
    if chunk.flags == Some(1) {
        // LAST_CHUNK with data - save file
        save_file(payload_id, &file_buffers, &file_metadata_map);
    }
} else {
    // Body is None - but check if this is a LAST_CHUNK end marker!
    if chunk.flags == Some(1) {
        // LAST_CHUNK end marker (no body) - save file now!
        save_file(payload_id, &file_buffers, &file_metadata_map);
    }
}
```

### 5.4 Critical Bug #3: RESPONSE Frame Not Handled

**Symptom:** Phone says "Failed" immediately after we send ACCEPT.

**Root Cause:** After we send `RESPONSE (ACCEPT)`, the phone sends back its own `RESPONSE (ACCEPT)` to confirm. We weren't handling this frame (logged as "Unhandled Sharing Frame Type: 2").

**Debug Evidence:**
```
TCP Handler: ✨ SHARING FRAME TYPE: 2
TCP Handler: ⚠️ Unhandled Sharing Frame Type: 2
TCP Handler: Connection closed/EOF in Secure Loop.  // Phone disconnected!
```

**Key Insight:** The phone expects acknowledgment of its RESPONSE frame. Without it, the phone assumes failure and closes the connection before sending file data.

**Fix:** Add handler for Type 2 (RESPONSE):
```rust
} else if frame_type == 2 { // RESPONSE (ConnectionResponseFrame)
    println!("TCP Handler: 📬 Client's RESPONSE received!");
    if let Some(conn_resp) = &v1.connection_response {
        let status = conn_resp.status.unwrap_or(0);
        if status == 1 {
            println!("TCP Handler: ✅ Phone confirmed ACCEPT - file transfer should begin!");
        }
    }
}
```

### 5.5 File Saving Implementation

**State Tracking:**
```rust
// Maps to track incoming file transfers
let mut file_metadata_map: HashMap<i64, (String, i64)> = HashMap::new(); // payload_id -> (filename, size)
let mut file_buffers: HashMap<i64, Vec<u8>> = HashMap::new();           // payload_id -> accumulated bytes
```

**Populating Metadata (from INTRODUCTION frame):**
```rust
if let Some(intro) = &v1.introduction {
    for file in &intro.file_metadata {
        if let Some(payload_id) = file.payload_id {
            let filename = file.name.clone().unwrap_or_else(|| format!("received_file_{}", payload_id));
            let size = file.size.unwrap_or(0);
            file_metadata_map.insert(payload_id, (filename, size));
        }
    }
}
```

**Saving to Disk:**
```rust
// When LAST_CHUNK received (flags=1)
if let Some(file_data) = file_buffers.remove(&payload_id) {
    let filename = file_metadata_map
        .get(&payload_id)
        .map(|(name, _)| name.clone())
        .unwrap_or_else(|| format!("received_file_{}", payload_id));
    
    let download_path = format!("{}/Downloads/{}", env::var("HOME").unwrap(), filename);
    std::fs::write(&download_path, &file_data)?;
}
```

---

## 6. Debugging Techniques

### 6.1 Hex Dump Analysis
When protobuf decoding fails, we dump raw hex to analyze wire format:
```rust
println!("RAW HEX: {}", hex::encode(&decrypted_bytes));
```

### 6.2 Multi-Strategy Decoding
We implement multiple decode strategies and try them in order:
1. **Strategy 1 (Direct):** Decode as `SharingFrame` directly
2. **Strategy 2 (Unwrap):** Decode as `OfflineFrame`, extract `PayloadTransfer.body`, decode as `SharingFrame`

### 6.3 Payload ID Tracking
Every file transfer uses unique `payload_id` values (64-bit signed integers, often negative). These must be tracked correctly:
- INTRODUCTION provides `payload_id` for each file
- File chunks arrive with matching `payload_id` in PayloadHeader
- LAST_CHUNK uses same `payload_id` to signal completion

---

## 7. Current Architecture Summary

1.  **Discovery**: Hybrid BLE (Trigger) + mDNS (Identity).
2.  **Transport**: TCP Port 5200.
3.  **Security**: UKEY2 Handshake → AES-256-CBC + HMAC-SHA256.
4.  **Framing**: Length-Prefixed → SecureMessage → DeviceToDevice → OfflineFrame → [PayloadTransfer Wrapper] → SharingFrame.
5.  **File Reception**: Buffer chunks by `payload_id`, save on `LAST_CHUNK` (flags=1).

This architecture ensures privacy (randomized MACs/Salts), security (Forward Secrecy via ECDH), and reliability (Chunked Payload Transfer).

---

## 8. TODO / Future Work

- [ ] **CLI Accept/Reject Prompt**: Currently auto-accepts all transfers. Add user confirmation.
- [ ] **Progress Display**: Show transfer progress percentage during large file transfers.
- [ ] **Multiple Files**: Test and verify handling of multi-file transfers.
- [ ] **Sending Files**: Implement Linux → Android file transfer (outbound).
- [ ] **Error Recovery**: Handle interrupted transfers gracefully.
