# OmniShare: The Internals (Deep Dive)

**Version:** 2.0 (The Connection Edition)
**Target Audience:** Systems Engineers, Security Researchers, Cryptographers, Protocol Developers.

---

## 1. Introduction: The "Zero-Install" Philosophy & Methodology

OmniShare bridges the ecosystem gap between Linux and Android without requiring a companion app. It achieves this by emulating the proprietary **Quick Share** (formerly Nearby Share) protocol directly at the packet layer.

### 1.1 Methodology: The Art of Reverse Engineering
Our approach relies on "Black Box" analysis, as the official protocol documentation is non-existent.

1.  **Pattern Recognition**: By analyzing raw hex dumps of TCP streams, we identify recurring headers (e.g., `0xFC`, `0x12`) and structure (Length-Prefixed Protobufs).
2.  **Differential Analysis**: We compare our logs against open-source partial implementations (like `NearDrop` and `rquickshare`) to identify discrepancies in field IDs and wire types.
3.  **Hypothesis Testing**: When decoding fails, we formulate hypotheses (e.g., "Is this frame wrapped inside another frame?") and implement "Strategies" in code to validate them. identifying the "Matryoshka Doll" structure of the frames was a direct result of this.

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

### 3.1 The Mathematics of key Exchange (ECDH)
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
    *(Note: We specifically hash the SHA256 of the shared secret before HKDF in some versions, but standard UKEY2 uses the raw x-coordinate).*

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
`OfflineFrame` (Type: PAYLOAD_TRANSFER)
  ↳ `PayloadChunk`
      ↳ `body` (Raw Bytes)
          ↳ **`SharingFrame`** (The *real* message)

**Strategy 2 (Recursive Unwrapping):**
Our implementation implements a "Strategy 2" decoder:
1.  Try decoding `DeviceToDevice` payload directly as `SharingFrame`. (Fails for wrapped messages).
2.  Try decoding as `OfflineFrame`.
3.  If `OfflineFrame.type == PAYLOAD_TRANSFER`, extract the `body` bytes from `payload_chunk`.
4.  Recursively decode those bytes as `SharingFrame`.

**Why?** This unifies the code path for sending small control structures (like encryption proofs) and large files (photos/videos). Theoretically, the `Introduction` frame (file list) could be larger than a single TCP packet, so wrapping it in `PayloadTransfer` allows it to be chunked.

### 4.3 Frame Types Discovered

| Type | Name | Purpose | Behavior |
| :--- | :--- | :--- | :--- |
| 1 | `INTRODUCTION` | File Metadata | Wrapped in `PayloadTransfer`. Contains Filename, Size. |
| 2 | `RESPONSE` | User Acceptance | Sent by Receiver to Accept/Reject transfer. |
| 3 | `PAIRED_KEY_ENCRYPTION` | Auth Proof | Wrapped. Proves we own the session keys. |
| 4 | `PAIRED_KEY_RESULT` | Auth Status | Success/Fail/Unable status of verification. |
| 6 | `CANCEL` | Cancellation | Abort transfer. |
| 12 | `KEEP_ALIVE` | Heartbeat | Prevents timeout. Requires Ack. |

---

## 5. Summary of Current Architecture

1.  **Discovery**: Hybrid BLE (Trigger) + mDNS (Identity).
2.  **Transport**: TCP Port 5200.
3.  **Security**: UKEY2 Handshake -> AES-256-CBC + HMAC-SHA256.
4.  **Framing**: Length-Prefixed -> SecureMessage -> DeviceToDevice -> OfflineFrame -> [PayloadTransfer Wrapper] -> SharingFrame.

This architecture ensures privacy (randomized MACs/Salts), security (Forward Secrecy via ECDH), and reliability (Chunked Payload Transfer).
