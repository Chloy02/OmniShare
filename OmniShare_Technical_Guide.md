# OmniShare: The Internals (Deep Dive)

**Version:** 4.0 (The Robustness & GUI Edition)  
**Target Audience:** Systems Engineers, Security Researchers, Cryptographers, Protocol Developers.  
**Status:** ✅ Working - Reliable file reception with GUI & CLI support.

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

This section documents the complete file transfer flow, with a focus on recent stability fixes (v4.0).

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
       │  <────── PAIRED_KEY_ENCRYPTION ───────── │  Wrapped in PayloadTransfer (Seq: 1)
       │  ─────── PAIRED_KEY_ENCRYPTION ───────>  │  Wrapped (Seq: 1)
       │                                          │
       │  <────── PAIRED_KEY_RESULT (UNABLE) ──── │  We don't have paired keys
       │  ─────── PAIRED_KEY_RESULT (UNABLE) ──>  │  Phone doesn't either (Seq: 2)
       │                                          │
       │  ─────── INTRODUCTION ────────────────>  │  File metadata (name, size, payload_id)
       │  <────── KEEP_ALIVE (ACK) ─────────────  │  We ack heartbeats regularly (Seq: 3, 4...)
       │                                          │
       │  <────── RESPONSE (ACCEPT) ───────────── │  User Clicks Accept! (Seq: N)
       │  ─────── RESPONSE (ACCEPT) ───────────>  │  Phone confirms (Seq: N+1)
       │                                          │
       │  ─────── FILE_CHUNKS (Type=FILE) ─────>  │  Actual file data
       │  ─────── FILE_CHUNKS (Type=FILE) ─────>  │  ...multiple chunks...
       │  ─────── LAST_CHUNK (flags=1) ────────>  │  Transfer complete signal
       │                                          │
       │  ═══════ FILE SAVED TO DISK ════════════ │
```

### 5.2 Critical Fix: Dynamic Sequence Numbers (v4.0)

**The Issue:**
The connection would drop immediately after the user accepted the transfer, or randomly after `KeepAlive` frames. This was typically flagged as "Early EOF" or a sudden socket close by the client.

**The Root Cause:**
The Android client enforces strictly **monotonic sequence numbers** for `DeviceToDeviceMessage` frames.
*   We were hardcoding `sequence_number: Some(1)` or `Some(0)` in various places (PKE, PKR, Response, KeepAlive).
*   If we sent `Seq: 1` (PKE), then `Seq: 1` (PKR), the client would reject the second frame as a replay attack or protocol violation and drop the connection.

**The Fix:**
We introduced a persistent `server_seq_num` variable in the connection handler, initialized to `-1` (or 0) after the handshake. It is incremented for **every** encrypted frame sent:
*   PKE
*   PKR
*   KeepAlive Acks
*   Accept/Reject Responses

This ensures the sequence is always $N, N+1, N+2...$, satisfying the client's security checks.

### 5.3 Critical Fix: `LastChunk` Handling for `ACCEPT`

The `RESPONSE` (Accept) frame is wrapped in a `PayloadTransfer`. The protocol dictates that any `PayloadTransfer` must be terminated by a "Last Chunk" marker to signal the end of that specific message stream.

**Incorrect Behavior:**
We sent the `RESPONSE` frame wrapped in a `PayloadTransfer` but forgot the end marker. The client kept waiting for more "Response Data" and eventually timed out.

**Correct Behavior:**
Immediately after sending the `RESPONSE` payload, we send a second, empty `PayloadChunk` with `flags = 1` (LAST_CHUNK) for the *same* `payload_id`.

```rust
// 1. Send Response Data
let resp_chunk = PayloadChunk { flags: Some(0), body: Some(resp_buf), ... };
send(resp_chunk);

// 2. Send End Marker
let end_chunk = PayloadChunk { flags: Some(1), body: None, ... };
send(end_chunk);
```

---

## 6. Architecture Update: GUI Integration

### 6.1 The TransferDelegate Pattern

To support both CLI and GUI interfaces without code duplication, we introduced the `TransferDelegate` trait.

```rust
#[async_trait]
pub trait TransferDelegate: Send + Sync {
    async fn on_transfer_request(&self, request: TransferRequest) -> bool;
}
```

*   **CLI Mode:** Uses `ConsoleDelegate`. It prints ASCII art to stdout and auto-accepts (for now) or prompts for `y/n`.
*   **GUI Mode:** Uses `TauriDelegate` (via MPSC channels). It fires a Tauri event `transfer-request` to the frontend.

### 6.2 Frontend-Backend Loop

1.  **Core:** Receives `Introduction` frame. Parses metadata.
2.  **Delegate:** Calls `on_transfer_request`.
3.  **Tauri:** Emits event.
4.  **JavaScript:** Listens for event, shows `<dialog>` modal with "Accept" / "Reject".
5.  **User Action:** User clicks "Accept".
6.  **Tauri Command:** `accept_transfer` command is invoked.
7.  **Core:** Channel receiver gets the signal, `on_transfer_request` returns `true`.
8.  **Connection Manager:** Sends `RESPONSE (ACCEPT)` frame. Transfer begins.

---

## 7. Current Architecture Summary

1.  **Discovery**: Hybrid BLE (Trigger) + mDNS (Identity).
2.  **Transport**: TCP Port 5200.
3.  **Security**: UKEY2 Handshake → AES-256-CBC + HMAC-SHA256.
4.  **Framing**: Length-Prefixed → SecureMessage → DeviceToDevice → OfflineFrame → [PayloadTransfer Wrapper] → SharingFrame.
5.  **Reliability**: Dynamic Sequence Numbering + KeepAlive handling.
6.  **File Reception**: Buffer chunks by `payload_id`, save on `LAST_CHUNK` (flags=1).

This architecture ensures privacy (randomized MACs/Salts), security (Forward Secrecy via ECDH), and reliability (Chunked Payload Transfer).

---

## 8. TODO / Future Work

- [ ] **Phase 4: Progress Tracking**: Use the `TransferDelegate` to report byte progress to the GUI.
- [ ] **Phase 5: Transfer History**: Persist transfer logs to SQLite.
- [ ] **Phase 6: Settings**: Allow users to change the default download directory and device name.
- [ ] **Outbound Transfer**: Re-visit the encryption issues blocking Linux-to-Android transfers.

---

## 9. Running OmniShare

### CLI Mode (Headless)

#### ▶️ Use the default directory (`~/Downloads`)
```bash
cargo run -p omni-cli -- run
```

#### 📂 Use a custom download folder
```bash
cargo run -p omni-cli -- run --download-dir /path/to/custom/folder
# OR
cargo run -p omni-cli -- run -d /path/to/custom/folder
```

### GUI Mode (System Tray)

```bash
cargo tauri dev
```

