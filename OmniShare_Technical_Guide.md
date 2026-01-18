# OmniShare: The Definitive Technical Guide & Development Bible

**Version:** 1.0 (The Discovery Edition)
**Authors:** Chloy Costa & Antigravity
**Status:** Phase 1 Complete (Discovery & Visibility Verified)

---

## Table of Contents

1.  [Introduction: The "Zero-Install" Philosophy](#1-introduction)
2.  [The Theory of Wireless Discovery](#2-theory)
    *   2.1 Bluetooth Low Energy (BLE) Mechanics
    *   2.2 Multicast DNS (mDNS) & ZeroConf
    *   2.3 The "Hybrid Discovery" Pattern
3.  [Quick Share Protocol: Reverse Engineered](#3-quick-share-reversed)
    *   3.1 The "Trigger" Packet (0xFE2C)
    *   3.2 The "Identity" Record (mDNS)
    *   3.3 Cryptography & Hashing (The PCP Protocol)
4.  [Implementation: Building OmniShare on Linux](#4-implementation)
    *   4.1 The BlueZ Stack & D-Bus Architecture
    *   4.2 The Rust Implementation (`bluer` & `mdns-sd`)
5.  [The Graveyard of Failures (Post-Mortem Analysis)](#5-failures)
    *   5.1 The Service UUID Trap (0xFC9F vs 0xFE2C)
    *   5.2 The Firewall Wall
    *   5.3 The "Name" vs "Instance" Spec Violation
6.  [Future Roadmap: The Connection Phase](#6-roadmap)

---

## 1. Introduction: The "Zero-Install" Philosophy

OmniShare aims to bridge the Linux-Android divide without requiring a companion app on the Android phone. We leverage the native **Quick Share** (formerly Nearby Share) protocol built into Google Play Services.

**The Challenge:** Google does not publish this protocol. It is a proprietary, closed-source standard.
**The Solution:** We act as a "Protocol Emulator," speaking the exact byte sequences Android expects, convincing the OS that our Linux machine is a supported peer (like a Chromebook).

---

## 2. The Theory of Wireless Discovery

To understand *how* we solved discovery, we must understand the underlying transport technologies.

### 2.1 Bluetooth Low Energy (BLE) Mechanics

BLE is designed for short bursts of data, not high throughput.
*   **Advertising (The "Shout"):** A device broadcasts small packets (31 bytes in Legacy Mode) on channels 37, 38, and 39. Scanners listen passively.
*   **GATT (Generic Attribute Profile):** Once connected, devices exchange data via "Services" and "Characteristics".
*   **Legacy vs. Extended Advertising:**
    *   *Legacy (ADV_IND):* Max 31 bytes payload. Compatible with ALL scanners.
    *   *Extended (ADV_EXT_IND):* Up to 255 bytes. Requires newer hardware. connection
    *   *OmniShare Choice:* We use **Legacy Advertising**. Why? Android's background scanning hardware filters are optimized for Legacy packets to save battery. Extended packets were consistently ignored in our tests.

### 2.2 Multicast DNS (mDNS) & ZeroConf

mDNS (RFC 6762) allows devices to resolve names to IP addresses without a central DNS server.
*   **The Mechanism:** Instead of asking a server "Who is `printer.local`?", the device sends a UDP Multicast packet to `224.0.0.251:5353`.
*   **The Response:** The target machine replies "I am `printer.local`, my IP is `192.168.1.50`".
*   **Service Discovery (DNS-SD):** Devices can announce *capabilities* (e.g., `_ipp._tcp` for printing). Android looks for `_FC9F5ED42C8A._tcp` for Quick Share.

### 2.3 The "Hybrid Discovery" Pattern

Quick Share uses a clever "Two-Stage" handoff to balance speed and battery life:

1.  **Stage 1 (Low Power):** The sender broadcasts a BLE "Trigger".
    *   *Power:* Low (~1mA).
    *   *Range:* Short (~10m).
    *   *Data:* ZERO identity info. Just a random salt and a Model ID.
2.  **Stage 2 (High Power):** The receiver (Phone) wakes up its WiFi radio and scans for mDNS.
    *   *Power:* High (~200mA+).
    *   *Data:* Full Identity (Name, Device Type, IP, Port).

**Crucial Insight:** If Stage 1 is missing, Stage 2 never happens. If Stage 2 is missing, Stage 1 is ignored as a ghost signal. **Both must be perfect.**

---

## 3. Quick Share Protocol: Reverse Engineered

Here is the exact specification we uncovered.

### 3.1 The "Trigger" Packet (0xFE2C)

The BLE Advertisement MUST contain this specific Service Data payload.

**Service UUID:** `0xFE2C` (Google Fast Pair Service).

**Payload Structure (15 Bytes):**
```text
Byte | Value | Description
-----|-------|------------------------------------------------
0    | 0xFC  | Model ID Byte 1 \
1    | 0x12  | Model ID Byte 2  > "This is Quick Share"
2    | 0x8E  | Model ID Byte 3 /
3    | 0x01  | Opcode (0x01 = Visibility Announcement)
4    | 0x42  | Meta/Length Byte
5-14 | [RND] | 10 Bytes of Random Salt (Anti-Replay)
```
*   *Note:* The "Model ID" `FC128E` is the magic key. If this sequence is wrong, Android hardware filters block the packet.

### 3.2 The "Identity" Record (mDNS)

Once the phone wakes up, it queries `_FC9F5ED42C8A._tcp`.

**Service Type Hash (`FC9F...`):**
This string is `SHA256("NearbySharing")[0..6]`. It is hardcoded in Android.

**TXT Record (`n` Key):**
The value of `n` is a Base64-encoded binary blob containing the visual metadata.
```text
Binary Structure:
[Byte 0] Status Bitmask
   Bits 7-5: Version (0)
   Bit  4:   Visibility (0 = Visible)
   Bits 3-1: Device Type (3 = Laptop, 1 = Phone)
   Bit  0:   Reserved (0)
   -> Result: 0x06 for a Visible Laptop.

[Bytes 1-16] Encryption Salt / Account Hash
   For "Everyone Mode", these can be random bytes.

[Byte 17] Name Length (L)
[Bytes 18..18+L] Device Name (UTF-8, e.g., "OmniShare")
```

### 3.3 The "Instance Name" (The PCP Hash)

This was the hardest part to crack. The mDNS Service Instance Name (the `Name` in `Name._type.domain`) cannot be arbitrary.

**Format:** `Base64([PCP][EndpointID][ServiceHash][Padding])`
*   **PCP Header:** `0x23` (Unknown Protocol Constant, likely "Public Connection Protocol").
*   **Endpoint ID:** 4 Random Alphanumeric Bytes (e.g., "Xy9z"). This acts as a session ID.
*   **Service Hash:** `0xFC, 0x9F, 0x5E` (Truncated SHA256 of "NearbySharing").
*   **Padding:** `0x00, 0x00`.

**Why?** This structure allows the phone to validate the service *before* connecting. If the name is just "OmniShare", the validation regex fails.

---

## 4. Implementation: Building OmniShare on Linux

### 4.1 The BlueZ Stack & D-Bus Architecture

Linux handles Bluetooth via the `bluetoothd` daemon. We don't talk to the hardware directly; we talk to `bluetoothd` via D-Bus (IPC).

*   **API:** `org.bluez.LEAdvertisement1`
*   **Challenge:** We must register an object on D-Bus, then tell BlueZ to "read" it.
*   **Crate:** `bluer` provides the Rust bindings. It uses `tokio` to handle the async D-Bus signals.

### 4.2 The Rust Implementation

**Module:** `discovery/ble_native.rs`
*   Uses `Advertiser` to broadcast the payload.
*   Implements a local GATT callback to satisfy BlueZ registration requirements (even though we don't actively use GATT for transfer).

**Module:** `discovery/mdns_native.rs`
*   Uses `mdns-sd` (a Rust implementation of mDNS).
*   Manually constructs the binary buffers for the `n` record and Instance Name.
*   Includes a "Self-Check" thread that browses for *our own service* to verify network visibility.

---

## 5. The Graveyard of Failures (Post-Mortem Analysis)

We failed many times to get here. Here is why.

### 5.1 The Service UUID Trap (0xFC9F vs 0xFE2C)
*   **The Theory:** We saw `FC9F` everywhere in the docs. We assumed it was the Main UUID.
*   **The Failure:** BLE scans yielded nothing.
*   **The Truth:** `FC9F` is the *WiFi* service hash. `FE2C` is the *BLE* service UUID. They are totally different layers.
*   **Severity:** Critical. Total blocker.

### 5.2 The "Flags" Confusion in BlueZ
*   **The Error:** `Failed to register application: Invalid definitions`.
*   **The Cause:** We tried to pass a raw `flags: vec!["read"]` to `bluer`. BlueZ rejected it.
*   **The Truth:** `bluer` infers flags based on which struct fields (`read`, `write`) are `Some(...)`. Explicit flags were forbidden and caused a parse error in the daemon.

### 5.3 The Firewall Wall
*   **The Symptom:** Everything looked perfect. Logs confirmed broadcast. Phone saw nothing.
*   **The Cause:** Fedora's `firewalld` blocks UDP 5353 (mDNS) by default. The announcements were leaving the application but dying at the kernel network filter.
*   **The Lesson:** Always check `sudo firewall-cmd --list-all`.

### 5.4 The "Name" vs "Instance" Spec Violation
*   **The Bug:** We named the service `OmniShare._FC9F...`.
*   **The Result:** The phone ignored it.
*   **The Detail:** The phone essentially does `if (!instance_name.matches(BASE64_PCP_REGEX)) return;`.
*   **The Fix:** Changing the name to the ugly hash `BuY9f...` instantly fixed visibility.

---

## 6. Future Roadmap: The Connection Phase

Phase 1 (Discovery) is done. We are visible.
Phase 2 (Connection) involves:
1.  **Transport:** Accepting a TCP connection on port 5200.
2.  **Authentication:** Implementing the **UKEY2** handshake (Diffie-Hellman Key Exchange) to establish a secure session key.
3.  **Framing:** Decoding the Protobuf messages ("ConnectionRequestFrame") to accept the file transfer.

---
*End of Guide - Phase 1*
