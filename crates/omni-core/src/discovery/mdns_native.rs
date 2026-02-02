use mdns_sd::{ServiceDaemon, ServiceInfo};
use anyhow::{Result, Context};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::Rng;

pub struct MdnsService {
    _daemon: ServiceDaemon,
    _service_type: String,
}

impl MdnsService {
    pub fn start(device_name: &str, port: u16, endpoint_id: &str) -> Result<Self> {
        println!("Starting mDNS Service for Quick Share...");
        println!("Using Endpoint ID: {}", endpoint_id);

        // 1. Create the mDNS Daemon
        let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");

        // 2. Define the Service Type (The "Magic" String)
        // Quick Share looks for: _FC9F5ED42C8A._tcp
        // Library requires full suffix: ._tcp.local.
        let service_type = "_FC9F5ED42C8A._tcp.local."; 
        
        // 3. Construct the "Endpoint Info" (The "n" value)
        // A. Status Byte: 
        // Bits: [Version: 3][Visibility: 1][Type: 3][Res: 1]
        // Version=0, Visible=0, Type=3(Laptop), Res=0 -> 0x06
        let status_byte: u8 = 0x06;

        // B. 16 Random Bytes (Salt)
        let mut random_bytes = [0u8; 16];
        rand::thread_rng().fill(&mut random_bytes);

        // C. Name Length (1 byte)
        let name_bytes = device_name.as_bytes();
        let name_len = name_bytes.len() as u8;

        // Combine into Buffer
        let mut endpoint_info = Vec::new();
        endpoint_info.push(status_byte);
        endpoint_info.extend_from_slice(&random_bytes);
        endpoint_info.push(name_len);
        endpoint_info.extend_from_slice(name_bytes);

        // 4. Encode as URL-Safe Base64
        let n_value = URL_SAFE_NO_PAD.encode(&endpoint_info);
        println!("Generated mDNS 'n' record: {}", n_value);

        // 5. Create Service Info
        // CRITICAL FIX: Instance Name must be the "PCP" string (10 bytes -> Base64), NOT the device name.
        // Source: PROTOCOL.md Line 29 "The name is the following 10 bytes..."
        
        // A. PCP Byte (0x23)
        let pcp: u8 = 0x23;

        // B. Endpoint ID (passed from main - MUST match BLE)

        // C. Service ID (0xFC, 0x9F, 0x5E)
        let service_id = [0xFC, 0x9F, 0x5E];

        // D. Zero Padding (2 bytes)
        let padding = [0x00, 0x00];

        // Construct 10-byte buffer
        let mut name_buffer = Vec::with_capacity(10);
        name_buffer.push(pcp);
        name_buffer.extend_from_slice(endpoint_id.as_bytes());
        name_buffer.extend_from_slice(&service_id);
        name_buffer.extend_from_slice(&padding);

        // Encode Instance Name
        let instance_name = URL_SAFE_NO_PAD.encode(&name_buffer);
        println!("Generated mDNS Instance Name (Base64): {}", instance_name);

        let host_name = format!("{}.local.", instance_name);

        let properties = [("n", n_value.as_str())];

        let service_info = ServiceInfo::new(
            service_type,
            &instance_name,
            &host_name,
            "", // IP (empty = auto)
            port,
            &properties[..], // TXT records
        ).context("Failed to create service info")?
        .enable_addr_auto();

        // 6. Register
        mdns.register(service_info).context("Failed to register mDNS service")?;

        println!("mDNS Service Registered: {} on port {}", service_type, port);

        // 7. Self-Check: Browse for our own service to confirm visibility
        let daemon_clone = mdns.clone();
        let service_type_clone = service_type.to_string();
        std::thread::spawn(move || {
            println!("Self-Check: Starting mDNS Browser for {}...", service_type_clone);
            let receiver = daemon_clone.browse(&service_type_clone).expect("Failed to browse");
            
            while let Ok(event) = receiver.recv() {
                match event {
                    mdns_sd::ServiceEvent::ServiceResolved(info) => {
                        println!("Self-Check: FOUND SERVICE -> {}", info.get_fullname());
                        println!("Self-Check: IP: {:?}", info.get_addresses());
                        println!("Self-Check: Port: {}", info.get_port());
                        // Per PROTOCOL.md: Receiver is SERVER, waits for client to connect
                    },
                    _ => {}
                }
            }
        });

        Ok(MdnsService {
            _daemon: mdns,
            _service_type: service_type.to_string(),
        })
    }
}
