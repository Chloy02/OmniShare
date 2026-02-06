//! Device Discovery Scanner
//!
//! Scans for nearby Android devices advertising Quick Share via mDNS.

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Represents a discovered Quick Share device
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    /// Human-readable device name
    pub name: String,
    /// 4-character endpoint ID
    pub endpoint_id: String,
    /// Device IP address
    pub ip: IpAddr,
    /// TCP port for Quick Share
    pub port: u16,
    /// Full mDNS service name
    pub fullname: String,
}

/// Scan for nearby Quick Share devices
///
/// Returns a list of discovered devices after scanning for the specified duration.
/// Only returns devices that are reachable via TCP.
pub async fn discover_devices(timeout: Duration) -> Result<Vec<DiscoveredDevice>> {
    let mdns = ServiceDaemon::new()?;
    let service_type = "_FC9F5ED42C8A._tcp.local.";
    
    let receiver = mdns.browse(service_type)?;
    let mut devices: HashMap<String, DiscoveredDevice> = HashMap::new();
    
    println!("🔍 Scanning for Quick Share devices ({:?})...", timeout);
    
    let start = std::time::Instant::now();
    
    // Use tokio::time::timeout for async timeout
    loop {
        if start.elapsed() >= timeout {
            break;
        }
        
        // Non-blocking check with small timeout
        match tokio::time::timeout(Duration::from_millis(100), tokio::task::spawn_blocking({
            let rx = receiver.clone();
            move || rx.recv_timeout(Duration::from_millis(50))
        })).await {
            Ok(Ok(Ok(event))) => {
                if let ServiceEvent::ServiceResolved(info) = event {
                    // Only use IPv4 addresses (like rquickshare does)
                    let ipv4_addrs: Vec<_> = info.get_addresses_v4().iter().cloned().collect();
                    
                    if ipv4_addrs.is_empty() {
                        continue;
                    }
                    
                    let ip = ipv4_addrs[0];
                    let port = info.get_port();
                    let ip_port = format!("{}:{}", ip, port);
                    
                    // Skip if already in our list
                    if devices.contains_key(&ip_port) {
                        continue;
                    }
                    
                    // Verify TCP connectivity (like rquickshare does)
                    // This ensures the port is actually open and accepting connections
                    match tokio::time::timeout(
                        Duration::from_millis(500),
                        tokio::net::TcpStream::connect(&ip_port)
                    ).await {
                        Ok(Ok(_stream)) => {
                            // Connection successful - device is reachable
                            let device_name = parse_device_name(info.get_property_val_str("n"));
                            let endpoint_id = parse_endpoint_id(info.get_fullname());
                            
                            let device = DiscoveredDevice {
                                name: device_name,
                                endpoint_id: endpoint_id.clone(),
                                ip: IpAddr::V4(*ip),
                                port,
                                fullname: info.get_fullname().to_string(),
                            };
                            
                            println!("📱 Found: {} ({})", device.name, ip_port);
                            devices.insert(ip_port, device);
                        }
                        _ => {
                            // Connection failed or timed out - skip this device
                            // Port might not be open yet, or device is not ready
                        }
                    }
                }
            }
            _ => {} // Timeout or error, continue scanning
        }
    }
    
    // Stop browsing
    let _ = mdns.stop_browse(service_type);
    
    let device_list: Vec<_> = devices.into_values().collect();
    println!("✅ Found {} device(s)", device_list.len());
    
    Ok(device_list)
}

/// Parse device name from mDNS "n" TXT record
fn parse_device_name(n_value: Option<&str>) -> String {
    if let Some(encoded) = n_value {
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded) {
            // Format: [status_byte][16 random bytes][name_len][name...]
            if decoded.len() > 18 {
                let name_len = decoded[17] as usize;
                if decoded.len() >= 18 + name_len {
                    if let Ok(name) = String::from_utf8(decoded[18..18+name_len].to_vec()) {
                        return name;
                    }
                }
            }
        }
    }
    "Unknown Device".to_string()
}

/// Parse endpoint ID from mDNS instance name
fn parse_endpoint_id(fullname: &str) -> String {
    // Instance name is Base64 encoded: [pcp][endpoint_id:4][service_id:3][padding:2]
    if let Some(instance) = fullname.split('.').next() {
        if let Ok(decoded) = URL_SAFE_NO_PAD.decode(instance) {
            // Bytes 1-4 are the endpoint ID
            if decoded.len() >= 5 {
                if let Ok(id) = String::from_utf8(decoded[1..5].to_vec()) {
                    return id;
                }
            }
        }
    }
    "????".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_device_name() {
        // Should return "Unknown Device" for empty/invalid input
        assert_eq!(parse_device_name(None), "Unknown Device");
        assert_eq!(parse_device_name(Some("invalid")), "Unknown Device");
    }
}
