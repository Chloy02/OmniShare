# OmniShare: Comprehensive Handover Documentation

**Version:** 5.0 (The KeepAlive & Stability Edition)  
**Last Updated:** 2026-02-13  
**Purpose:** Enable new AI agents to understand the complete context and continue development

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture & Protocol](#2-architecture--protocol)
3. [Recent Major Fixes (v5.0)](#3-recent-major-fixes-v50)
4. [Codebase Structure](#4-codebase-structure)
5. [Development Workflow](#5-development-workflow)
6. [Testing & Verification](#6-testing--verification)
7. [Known Issues & Future Work](#7-known-issues--future-work)
8. [Critical References](#8-critical-references)

---

## 1. Project Overview

### 1.1 Mission Statement
OmniShare is a Linux implementation of Android's **Quick Share** (formerly Nearby Share) protocol that enables **zero-install** file transfers from Android devices to Linux machines without requiring any app installation on the Android side.

### 1.2 Current Status
- ✅ **Inbound Transfers**: Fully functional, stable for files up to 500MB+
- ✅ **GUI Interface**: Tauri-based system tray application with transfer notifications
- ✅ **CLI Interface**: Command-line tool with progress bars (`indicatif`)
- ⚠️ **Outbound Transfers**: Blocked by crypto implementation issues (deferred)

### 1.3 Technology Stack
- **Language**: Rust (2021 edition)
- **Crypto**: `p256`, `aes`, `cbc`, `hmac`, `sha2`
- **Protocol**: Protobuf (`prost`)
- **GUI Framework**: Tauri 2.x with vanilla HTML/CSS/JS frontend
- **BLE**: `bluer` (Linux BlueZ bindings)
- **mDNS**: `mdns-sd`
- **Async Runtime**: `tokio`

---

## 2. Architecture & Protocol

### 2.1 Discovery Layer

#### BLE Advertisement (Trigger)
```
Service UUID: 0xFE2C (Google Fast Pair)
Model ID: 0xFC128E (Quick Share identifier)
Salt: 10 random bytes (privacy protection)
```

#### mDNS Resolution (Identity)
```
Service Type: _FC9F5ED42C8A._tcp
Instance Name: Base64([PCP][EndpointID][ServiceHash][Padding])
TXT Record (n): Base64-encoded EndpointInfo
Port: 5200 (TCP)
```

### 2.2 Security Layer (UKEY2)

#### ECDH Key Exchange
- **Curve**: P-256 (secp256r1)
- **Critical Fix**: Prepend `0x00` byte if public key coordinate MSB is `1` (Java BigInteger quirk)

#### Key Derivation (HKDF-SHA256)
```
PRK = HMAC_SHA256(salt="UKEY2 v1", IKM=shared_secret_x)

Client Key (32 bytes): HKDF_Expand(PRK, info="client") → Phone encrypts with this
Server Key (32 bytes): HKDF_Expand(PRK, info="server") → We encrypt with this

Role Swap for Decryption:
  - We decrypt with Client Key (phone's encrypted messages)
  - We encrypt with Server Key (our outgoing messages)
```

#### Encryption Scheme
- **Algorithm**: AES-256-CBC
- **MAC**: HMAC-SHA256
- **IV**: First 16 bytes of the encrypted `header_and_body` field in `SecureMessage`

### 2.3 Frame Structure (The "Matryoshka Doll")

Every encrypted packet follows this nesting:

```
Wire Bytes (TCP Stream)
├─ [4 bytes] Length Prefix (Big Endian)
└─ SecureMessage (Protobuf)
   ├─ signature: HMAC-SHA256 of header_and_body
   └─ header_and_body: AES-256-CBC Encrypted Blob
      └─ DeviceToDeviceMessage (Decrypted)
         ├─ sequence_number: Monotonic counter (replay protection)
         └─ message: bytes
            └─ OfflineFrame OR SharingFrame
               └─ (Potentially) PayloadTransfer Wrapper
                  └─ SharingFrame (Actual content)
```

### 2.4 Critical Frame Types

| Type | Name | Wrapping | Purpose |
|------|------|----------|---------|
| 1 | `INTRODUCTION` | Wrapped in `PayloadTransfer` (Type=BYTES) | File metadata (name, size, MIME, `payload_id`) |
| 2 | `RESPONSE` | Wrapped in `PayloadTransfer` (Type=BYTES) | Accept/Reject response |
| 3 | `PAIRED_KEY_ENCRYPTION` | Wrapped in `PayloadTransfer` (Type=BYTES) | Crypto auth proof |
| 4 | `PAIRED_KEY_RESULT` | Direct `OfflineFrame` | Auth status response |
| 6 | `CANCEL` | Direct `OfflineFrame` | Transfer cancellation |
| 12 | `KEEP_ALIVE` | Direct `OfflineFrame` | Heartbeat (requires ACK) |
| N/A | `PayloadTransfer` (Type=FILE) | Container for actual file chunks | Binary file data |

### 2.5 Transfer Flow Diagram

```
┌─────────────┐                            ┌─────────────┐
│   Android   │                            │  OmniShare  │
│   (Client)  │                            │  (Server)   │
└─────────────┘                            └─────────────┘
      │                                          │
      │  ────── CONNECTION_REQUEST ──────────>  │  Plaintext
      │  <───── CONNECTION_RESPONSE (ACCEPT) ── │
      │                                          │
      │  ────── UKEY2 CLIENT_INIT ───────────>  │  Key Exchange
      │  <───── UKEY2 SERVER_INIT ───────────── │
      │  ────── UKEY2 CLIENT_FINISHED ───────>  │
      │                                          │
      │  <───── CONNECTION_RESPONSE (ACCEPT) ── │  Plaintext
      │  ────── CONNECTION_RESPONSE (ACCEPT) ─> │  Plaintext
      │                                          │
      │         ═══ ENCRYPTED MODE ═══          │
      │                                          │
      │  <───── PAIRED_KEY_ENCRYPTION ───────── │  Wrapped (Seq: 1)
      │  ────── PAIRED_KEY_ENCRYPTION ───────>  │  Wrapped (Seq: 1)
      │                                          │
      │  <───── PAIRED_KEY_RESULT (UNABLE) ──── │  Seq: 2
      │  ────── PAIRED_KEY_RESULT (UNABLE) ──>  │  Seq: 2
      │                                          │
      │  ────── INTRODUCTION ─────────────────>  │  Wrapped, File metadata
      │  <───── KEEP_ALIVE (ACK) ──────────────  │  Seq: 3, 4, 5... (every 5s)
      │                                          │
      │         [USER CLICKS ACCEPT]             │
      │  <───── RESPONSE (ACCEPT) ──────────────  │  Wrapped + END marker (Seq: N, N+1)
      │  ────── RESPONSE (ACCEPT) ──────────────> │  Wrapped + END marker (Seq: N+1, N+2)
      │                                          │
      │  ────── FILE_CHUNKS (Type=FILE) ──────>  │  Data transfer
      │  ────── LAST_CHUNK (flags=1) ──────────> │  Transfer complete
      │                                          │
      │         [FILE SAVED TO DISK]             │
```

---

## 3. Recent Major Fixes (v5.0)

### 3.1 The "Early EOF" Problem

#### Symptom
Large file transfers (>50MB) would fail with `Connection closed by client: early eof` after approximately 50MB of data transferred.

#### Root Cause Analysis
1. **Blocking Write Operations**: The main read loop was performing direct `socket.write_all()` calls for KeepAlive responses and Accept/Reject messages, blocking the async executor.
2. **Buffer Saturation**: Large files were buffered entirely in memory (`Vec<u8>`) before writing to disk, causing delays in processing incoming chunks.
3. **Sender Timeout**: Android Near Share has a connection timeout. If OmniShare took too long to process chunks (due to blocking operations or memory reallocation), the sender would timeout and disconnect.

#### Solution: Non-Blocking Writer Task Architecture

**Implementation Details:**

1. **TCP Stream Splitting**:
   ```rust
   let (mut socket, mut writer) = socket.into_split();
   // socket (OwnedReadHalf) - stays in main loop for reading
   // writer (OwnedWriteHalf) - moved to background task
   ```

2. **MPSC Channel Communication**:
   ```rust
   let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);
   // Main loop sends outgoing messages to tx
   // Writer task receives from rx
   ```

3. **Background Writer Task** (spawned with `tokio::spawn`):
   ```rust
   tokio::spawn(async move {
       let mut interval = tokio::time::interval(Duration::from_secs(5));
       loop {
           tokio::select! {
               // Handle outgoing messages from main loop
               msg = rx.recv() => {
                   if let Some(payload) = msg {
                       // Wrap payload in DeviceToDeviceMessage
                       // Encrypt and sign with SecurityEngine
                       // Write to socket with length prefix
                   }
               }
               // Send periodic KeepAlive frames
               _ = interval.tick() => {
                   // Create KeepAlive frame
                   // Encrypt and send
               }
           }
       }
   });
   ```

4. **SecurityEngine Cloning**:
   - Made `SecurityEngine` derive `Clone` to share between main loop and writer task
   - Each task has its own clone for thread-safe encryption/decryption

5. **Connection Lifecycle**:
   - After the secure session loop (where `socket.into_split()` occurs), the handler must `return Ok(())` immediately
   - Cannot loop back to plaintext handshake state (ownership consumed)
   - This is correct behavior: secure sessions are single-use

#### Files Modified
- [`crates/omni-core/src/security/engine.rs`](file:///home/chloycosta/Documents/College_code/projects/OmniShare/crates/omni-core/src/security/engine.rs#L15): Added `#[derive(Clone)]`
- [`crates/omni-core/src/connection_manager.rs`](file:///home/chloycosta/Documents/College_code/projects/OmniShare/crates/omni-core/src/connection_manager.rs): Lines 384-1143 refactored

#### Key Code Locations

**Writer Task Spawn** ([connection_manager.rs:384-400](file:///home/chloycosta/Documents/College_code/projects/OmniShare/crates/omni-core/src/connection_manager.rs#L384-L400)):
```rust
let (mut socket, mut writer) = socket.into_split();
let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

let engine_clone = engine.clone();
let mut server_seq_num_writer = server_seq_num;

tokio::spawn(async move {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            msg = rx.recv() => { /* ... */ }
            _ = interval.tick() => { /* ... */ }
        }
    }
});
```

**Refactored Send Logic** (Example from [connection_manager.rs:689-708](file:///home/chloycosta/Documents/College_code/projects/OmniShare/crates/omni-core/src/connection_manager.rs#L689-L708)):
```rust
// Old (blocking):
// socket.write_all(&len_prefix).await?;
// socket.write_all(&encrypted_resp).await?;

// New (non-blocking):
if let Err(e) = tx.send(pkr_offline_buf).await {
    eprintln!("TCP Handler: Failed to send PKR to writer: {}", e);
}
```

### 3.2 Buffer Memory Optimization

**Change**: Pre-allocate file buffer with known capacity
```rust
// Before:
let mut incoming_file_buffer = Vec::new();

// After:
let mut incoming_file_buffer = Vec::with_capacity(total_size as usize);
```

**Impact**: Eliminates repeated reallocations during chunk appending, reducing processing latency.

### 3.3 Sequence Number Management

**Critical Fix**: Maintain monotonic `server_seq_num` across all outgoing encrypted frames.

**Implementation**:
```rust
let mut server_seq_num = 0i32;

// Every time we send an encrypted frame:
let d2d = DeviceToDeviceMessage {
    sequence_number: Some(server_seq_num),
    message: Some(payload),
};
server_seq_num += 1;
```

**Applies to**:
- `PAIRED_KEY_ENCRYPTION`
- `PAIRED_KEY_RESULT`
- `RESPONSE` (Accept/Reject)
- `KEEP_ALIVE` acknowledgments

**Consequence of Violation**: Android client treats duplicate sequence numbers as replay attacks and immediately drops the connection.

---

## 4. Codebase Structure

### 4.1 Workspace Layout

```
OmniShare/
├── crates/
│   ├── omni-core/          # Protocol implementation (BLE, mDNS, UKEY2, File Transfer)
│   │   ├── src/
│   │   │   ├── lib.rs                # Public API, TransferDelegate trait
│   │   │   ├── connection_manager.rs # TCP handler, frame processing, MAIN LOGIC
│   │   │   ├── ble.rs                # BLE advertisement
│   │   │   ├── mdns.rs               # mDNS service registration
│   │   │   ├── discovery.rs          # Discovery coordinator
│   │   │   ├── security/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── engine.rs         # SecurityEngine (AES, HMAC, HKDF)
│   │   │   │   └── ukey2.rs          # UKEY2 handshake logic
│   │   │   └── proto/                # Protobuf definitions
│   │   │       ├── mod.rs
│   │   │       ├── quick_share.proto
│   │   │       ├── ukey2.proto
│   │   │       └── wire_format.proto
│   │   └── build.rs          # Protobuf compilation
│   │
│   └── omni-cli/            # CLI interface
│       └── src/
│           └── main.rs       # ConsoleDelegate implementation, indicatif progress bars
│
├── omni-gui/                # Tauri GUI application
│   ├── src/
│   │   ├── index.html        # Main UI (system tray, transfer modals)
│   │   ├── main.js           # Event listeners (transfer-request, transfer-progress)
│   │   └── styles.css        # UI styling
│   └── src-tauri/
│       ├── src/
│       │   ├── main.rs       # Tauri app initialization
│       │   └── commands.rs   # TauriDelegate implementation, Tauri commands
│       └── Cargo.toml
│
├── OmniShare_Technical_Guide.md   # Protocol deep dive (MUST READ)
├── HANDOVER_DOCUMENTATION.md      # This file
├── PROTOCOL.md                    # Quick reference for frame types
└── README.md                      # User-facing documentation
```

### 4.2 Critical Modules

#### `connection_manager.rs`
- **Function**: `handle_connection()`
- **Responsibility**: Complete lifecycle of a single TCP connection
- **Key Sections**:
  - Lines 72-380: Plaintext handshake phase (ConnectionRequest, UKEY2)
  - Lines 384-400: TCP stream split and writer task spawn
  - Lines 401-1143: Encrypted frame processing loop
  - Lines 1144+: Error handling and cleanup

#### `security/engine.rs`
- **Struct**: `SecurityEngine`
- **Methods**:
  - `new()`: Initialize with decryption/encryption/HMAC keys
  - `encrypt_and_sign()`: Wrap payload in `SecureMessage` with AES-CBC + HMAC
  - `verify_and_decrypt()`: Verify HMAC, decrypt, extract `DeviceToDeviceMessage`

#### `TransferDelegate` Trait ([lib.rs](file:///home/chloycosta/Documents/College_code/projects/OmniShare/crates/omni-core/src/lib.rs))
```rust
#[async_trait]
pub trait TransferDelegate: Send + Sync {
    async fn on_transfer_request(&self, request: TransferRequest) -> bool;
    async fn on_transfer_progress(&self, payload_id: i64, current_bytes: u64, total_bytes: u64);
}
```

**Implementations**:
- `ConsoleDelegate`: CLI mode (auto-accept or prompt, `indicatif` progress bars)
- `TauriDelegate`: GUI mode (Tauri events, user interaction via modal)

---

## 5. Development Workflow

### 5.1 Build Commands

```bash
# Check compilation
cargo check

# Build all workspace members
cargo build --workspace

# Build specific crate
cargo build -p omni-core
cargo build -p omni-cli

# Run tests
cargo test --workspace
```

### 5.2 Running the Application

#### CLI Mode
```bash
# Default download directory (~/Downloads)
cargo run -p omni-cli -- run

# Custom download directory
cargo run -p omni-cli -- run --download-dir /path/to/folder
# OR
cargo run -p omni-cli -- run -d /path/to/folder
```

#### GUI Mode
```bash
# Development mode (hot reload)
cd omni-gui
cargo tauri dev

# Production build
cargo tauri build
```

### 5.3 Debugging Tips

#### Enable Verbose Logging
The code already has extensive `println!` debug statements. Key patterns:
- `TCP Handler: 📦 Received Frame. Length: X bytes`
- `TCP Handler: 🔓 Decrypted D2D Message!`
- `TCP Handler: 💓 Received KEEP_ALIVE, responding with ack...`
- `TCP Handler: Queued [MESSAGE_TYPE] for sending.`

#### Common Issues

1. **Connection Drops Immediately After Accept**:
   - Check sequence numbers are incrementing
   - Verify END marker is sent after wrapped `RESPONSE`

2. **KeepAlive Not Working**:
   - Verify writer task is spawned correctly
   - Check `interval.tick()` fires every 5 seconds
   - Ensure `SecurityEngine` is `Clone`-able

3. **Decryption Failures**:
   - Verify key derivation (Client/Server key swap)
   - Check IV extraction (first 16 bytes of `header_and_body`)
   - Confirm HMAC verification passes before decryption attempt

4. **BLE Advertisement Not Detected**:
   - Check BlueZ service is running: `systemctl status bluetooth`
   - Verify adapter is powered: `bluetoothctl power on`
   - Check Android device has Quick Share enabled and set to "Everyone" visibility

### 5.4 Protocol Debugging with Wireshark

1. Capture TCP traffic on port 5200
2. Export as raw hex
3. Manually decode:
   - Length prefix (4 bytes, Big Endian)
   - Protobuf structure (`SecureMessage` → decrypt → `DeviceToDeviceMessage` → `OfflineFrame`)

---

## 6. Testing & Verification

### 6.1 Test Scenarios

#### Scenario 1: Small File Transfer (< 10MB)
**Expected Behavior**:
- Transfer completes in < 5 seconds
- No KeepAlive frames needed
- Progress bar reaches 100%
- File saved to disk with correct size and checksum

#### Scenario 2: Large File Transfer (> 100MB)
**Expected Behavior**:
- Multiple KeepAlive frames sent during transfer (every 5s)
- No "Early EOF" errors
- Smooth progress updates (throttled to ~10 updates/sec)
- Transfer completes successfully
- Memory usage remains stable (no runaway allocations)

#### Scenario 3: Multi-File Bundle
**Expected Behavior**:
- Multiple `INTRODUCTION` frames received (one per file)
- Each file tracked by unique `payload_id`
- Progress bars for each file (GUI/CLI)
- All files saved to disk

#### Scenario 4: Transfer Rejection
**Expected Behavior**:
- User clicks "Reject" in GUI or enters 'n' in CLI
- `RESPONSE (REJECT)` + END marker sent
- Connection gracefully closed
- No file saved to disk

### 6.2 Verification Checklist

Before pushing to a new system, verify:

- [ ] `cargo check --workspace` passes with no errors
- [ ] Small file transfer (< 10MB) completes successfully
- [ ] Large file transfer (> 100MB) completes without "Early EOF"
- [ ] GUI shows live progress updates
- [ ] CLI shows `indicatif` progress bars
- [ ] Accept/Reject buttons in GUI work correctly
- [ ] Files saved with correct permissions and naming
- [ ] System tray icon updates with transfer status
- [ ] KeepAlive frames logged every 5 seconds during long transfers

---

## 7. Known Issues & Future Work

### 7.1 Current Limitations

#### Outbound Transfers (Linux → Android)
**Status**: Blocked by cryptographic implementation issues  
**Symptom**: Android device sends `DISCONNECTION` frame immediately after `PairedKeyEncryption` exchange  
**Hypothesis**: Key derivation mismatch or incorrect role assignment in outbound mode  
**Priority**: Deferred (inbound transfers are the primary use case)

#### Transfer History
**Status**: Not implemented  
**Planned**: SQLite database to store transfer logs (timestamp, sender, file list, status)

#### Settings UI
**Status**: Minimal (hardcoded device name, download directory)  
**Planned**: 
- Custom download location picker
- Device name configuration
- BLE visibility toggle

### 7.2 Future Enhancements

1. **Parallel Multi-File Transfer Optimization**:
   - Current: Sequential file processing
   - Planned: Concurrent file writes using separate tasks per `payload_id`

2. **Resume Capability**:
   - Current: Transfer must complete in one session
   - Planned: Checkpoint system to resume interrupted transfers

3. **Notification System**:
   - Current: Basic GUI modal
   - Planned: Native OS notifications (via `notify-rust`)

4. **Network Quality Adaptation**:
   - Current: Fixed chunk size, fixed KeepAlive interval
   - Planned: Dynamic adjustment based on RTT and packet loss

---

## 8. Critical References

### 8.1 Essential Reading (In Order)

1. **[OmniShare_Technical_Guide.md](file:///home/chloycosta/Documents/College_code/projects/OmniShare/OmniShare_Technical_Guide.md)**: Complete protocol breakdown, cryptographic details, frame structures
2. **[PROTOCOL.md](file:///home/chloycosta/Documents/College_code/projects/OmniShare/PROTOCOL.md)**: Quick reference for frame types and fields
3. **This document**: Implementation details, recent fixes, handover context

### 8.2 Code Investigation History

This project was built through reverse engineering. Key artifacts documenting the debugging process:

- **[investigation_plan.md](file:///home/chloycosta/.gemini/antigravity/brain/b38ed64c-4e18-4555-ad33-59420db9cc04/investigation_plan.md)**: Early EOF hypothesis and diagnostic steps
- **[implementation_plan.md](file:///home/chloycosta/.gemini/antigravity/brain/b38ed64c-4e18-4555-ad33-59420db9cc04/implementation_plan.md)**: Phase 4 (Progress Tracking) implementation strategy
- **[task.md](file:///home/chloycosta/.gemini/antigravity/brain/b38ed64c-4e18-4555-ad33-59420db9cc04/task.md)**: Development checklist and status

### 8.3 External Resources

- **UKEY2 Specification**: [Google Security Blog](https://security.googleblog.com/2017/05/introducing-ukey2-security-key-protocol.html)
- **Protobuf**: [Protocol Buffers v3 Language Guide](https://protobuf.dev/programming-guides/proto3/)
- **HKDF RFC**: [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
- **Reference Implementation**: [NearDrop](https://github.com/grishka/NearDrop) (partial, iOS-focused)

---

## 9. Quick Start for New AI Agent

### 9.1 Initial Context Loading

1. Read this entire document
2. Read [OmniShare_Technical_Guide.md](file:///home/chloycosta/Documents/College_code/projects/OmniShare/OmniShare_Technical_Guide.md)
3. Scan [connection_manager.rs](file:///home/chloycosta/Documents/College_code/projects/OmniShare/crates/omni-core/src/connection_manager.rs) (main logic)
4. Review [security/engine.rs](file:///home/chloycosta/Documents/College_code/projects/OmniShare/crates/omni-core/src/security/engine.rs) (crypto implementation)

### 9.2 First Commands to Run

```bash
cd /home/chloycosta/Documents/College_code/projects/OmniShare

# Verify build environment
cargo check --workspace

# Run CLI to verify functionality
cargo run -p omni-cli -- run

# In another terminal, send a file from Android device
# Expected: File transfers successfully
```

### 9.3 Key Mental Models

1. **Frame Nesting**: Always think in layers (Wire → SecureMessage → D2D → OfflineFrame → [Wrapper] → Content)
2. **Sequence Numbers**: Every encrypted frame MUST have a unique, monotonic sequence number
3. **Writer Task**: All writes must go through the channel to the background task (no direct `socket.write_all()` in main loop)
4. **KeepAlive is Critical**: Without periodic heartbeats, Android times out after ~30 seconds of silence
5. **PayloadTransfer Wrapping**: Most control frames are wrapped; file data is also wrapped (different `PacketType`)

### 9.4 Common Development Tasks

**Add a new frame type**:
1. Define protobuf message in `crates/omni-core/src/proto/*.proto`
2. Add parsing logic in `connection_manager.rs` (match on `frame_type` or `v1.type`)
3. Update `OmniShare_Technical_Guide.md` with new frame documentation

**Modify encryption**:
1. Update `security/engine.rs`
2. Ensure changes maintain compatibility with Android's crypto stack
3. Test with small files first, then large transfers

**Add GUI feature**:
1. Define Tauri command in `omni-gui/src-tauri/src/commands.rs`
2. Update frontend in `omni-gui/src/main.js` and `omni-gui/src/index.html`
3. Add corresponding event listener

---

## 10. Final Notes

### 10.1 Code Stability
The current codebase (v5.0) is **production-ready for inbound transfers**. The KeepAlive implementation has been tested with files up to 500MB without issues.

### 10.2 Development Philosophy
This project was built through **empirical observation** rather than official documentation. When debugging:
- Trust the logs (extensive `println!` statements are intentional)
- Compare against known-good reference implementations
- Test hypotheses incrementally (don't change multiple things at once)

### 10.3 Contact & Support
For questions, refer back to:
- Conversation logs: `/home/chloycosta/.gemini/antigravity/brain/b38ed64c-4e18-4555-ad33-59420db9cc04/.system_generated/logs/`
- Artifact history: `/home/chloycosta/.gemini/antigravity/brain/b38ed64c-4e18-4555-ad33-59420db9cc04/`

---

**Good luck with continued development! The foundation is solid, and the protocol is now well-understood.** 🚀
