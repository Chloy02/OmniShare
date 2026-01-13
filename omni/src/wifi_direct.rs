use std::process::Command;
use anyhow::{Context, Result, anyhow};
use std::fs;

pub struct WpaClient {
    interface: String,
    dbus_path: String,
}

impl WpaClient {
    pub fn new(interface: &str) -> Result<Self> {
        let dbus_path = Self::resolve_dbus_path(interface)
            .context(format!("Could not find DBus path for interface '{}'. Ensure wpa_supplicant is running.", interface))?;
            
        Ok(Self {
            interface: interface.to_string(),
            dbus_path,
        })
    }

    /// Attempts to auto-detect a WiFi interface (starts with "wl")
    pub fn auto_detect_interface() -> Option<String> {
        if let Ok(entries) = fs::read_dir("/sys/class/net") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if name.starts_with("wl") {
                        return Some(name);
                    }
                }
            }
        }
        None
    }

    /// Finds the DBus object path for a given interface name
    fn resolve_dbus_path(target_iface: &str) -> Result<String> {
        // List all interfaces: busctl call fi.w1.wpa_supplicant1 /fi/w1/wpa_supplicant1org.freedesktop.DBus.Properties Get s s fi.w1.wpa_supplicant1 Interfaces
        // Easier: Parse "busctl tree"
        let output = Command::new("busctl")
            .args(["tree", "fi.w1.wpa_supplicant1"])
            .output()
            .context("Failed to run busctl tree")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Look for lines containing /Interfaces/
        for line in stdout.lines() {
            // Line format usually: └─ /fi/w1/wpa_supplicant1/Interfaces/3
            // We just want the path part.
            if let Some(start) = line.find("/") {
                let path = line[start..].trim().split_whitespace().next().unwrap_or("");
                if path.contains("/Interfaces/") && !path.contains("/BSSs") && !path.contains("/Networks") {
                    // Check if this path belongs to our interface
                    if Self::check_interface_name(path, target_iface) {
                        return Ok(path.to_string());
                    }
                }
            }
        }
        
        Err(anyhow!("Interface {} not found in wpa_supplicant DBus tree", target_iface))
    }

    fn check_interface_name(path: &str, target: &str) -> bool {
        // busctl get-property fi.w1.wpa_supplicant1 <path> fi.w1.wpa_supplicant1.Interface Ifname
        let output = Command::new("busctl")
            .args(["get-property", "fi.w1.wpa_supplicant1", path, "fi.w1.wpa_supplicant1.Interface", "Ifname"])
            .output();

        if let Ok(out) = output {
            let s = String::from_utf8_lossy(&out.stdout);
            // Output format: s "wlan0"
            if s.contains(&format!("\"{}\"", target)) {
                return true;
            }
        }
        false
    }

    /// Triggers a P2P scan via DBus
    pub fn p2p_find(&self) -> Result<()> {
        println!("Initiating scan on interface: {} (DBus path: {})", self.interface, self.dbus_path);
        // busctl call fi.w1.wpa_supplicant1 <path> fi.w1.wpa_supplicant1.Interface.P2PDevice Find a{sv} 0
        let status = Command::new("busctl")
            .args([
                "call", 
                "fi.w1.wpa_supplicant1", 
                &self.dbus_path, 
                "fi.w1.wpa_supplicant1.Interface.P2PDevice", 
                "Find", 
                "a{sv}", 
                "0"
            ])
            .status()
            .context("Failed to execute busctl call Find")?;

        if status.success() {
            println!("P2P Scan started (DBus).");
            Ok(())
        } else {
            Err(anyhow!("Failed to start P2P scan via DBus"))
        }
    }

    /// Returns a list of peers found (formatted strings)
    pub fn p2p_peers(&self) -> Result<Vec<String>> {
        // 1. Get Peers property (array of object paths)
        // busctl get-property fi.w1.wpa_supplicant1 <path> fi.w1.wpa_supplicant1.Interface.P2PDevice Peers
        // Output: ao 2 "/fi/w1/wpa_supplicant1/Interfaces/3/Peers/aa_bb_cc_dd_ee_ff" ...
        
        let output = Command::new("busctl")
            .args([
                "get-property", 
                "fi.w1.wpa_supplicant1", 
                &self.dbus_path, 
                "fi.w1.wpa_supplicant1.Interface.P2PDevice", 
                "Peers"
            ])
            .output()
            .context("Failed to get Peers property")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse object paths. Format: ao 2 "/path/1" "/path/2"
        // We look for strings starting with "/fi/w1/..." inside quotes.
        let paths: Vec<&str> = stdout
            .split('"')
            .filter(|s| s.starts_with("/fi/w1/wpa_supplicant1/Interfaces"))
            .collect();

        let mut results = Vec::new();
        for peer_path in paths {
            // Get properties for this peer
            // DeviceName, Manufacturer, ModelName
            let name = Self::get_peer_property(peer_path, "DeviceName").unwrap_or("Unknown".to_string());
            let model = Self::get_peer_property(peer_path, "ModelName").unwrap_or("Unknown".to_string());
            let addr = peer_path.split('/').last().unwrap_or("Unknown").replace("_", ":");

            results.push(format!("{} (Name: {}, Model: {})", addr, name, model));
        }
            
        Ok(results)
    }

    /// Connect to a peer using PBC (Push Button) or PIN method.
    /// For this phase, we use "pbc" (Push Button Configuration) or "display" which is common for Quick Share.
    pub fn p2p_connect(&self, peer_addr: &str) -> Result<()> {
        let peer_path = format!("{}/Peers/{}", self.dbus_path, peer_addr.replace(":", "_"));
        
        println!("Calling P2PConnect on {}", peer_path);

        let status = Command::new("busctl")
            .args([
                "call", 
                "fi.w1.wpa_supplicant1", 
                &self.dbus_path, 
                "fi.w1.wpa_supplicant1.Interface.P2PDevice", 
                "GroupAdd", // Start Group Formation
                "a{sv}", 
                "0"
            ])
            .status()
            .context("Failed to execute GroupAdd")?;

        if status.success() {
             println!("Group Formation Initiated.");
             Ok(())
        } else {
             Err(anyhow!("Failed to initiate P2P Group"))
        }
    }

    fn get_peer_property(path: &str, prop: &str) -> Option<String> {
         let output = Command::new("busctl")
            .args([
                "get-property", 
                "fi.w1.wpa_supplicant1", 
                path, 
                "fi.w1.wpa_supplicant1.Peer", 
                prop
            ])
            .output()
            .ok()?;
        
        let s = String::from_utf8_lossy(&output.stdout);
        // Format: s "Galaxy S24"
        if let Some(start) = s.find('"') {
            if let Some(end) = s[start+1..].find('"') {
                return Some(s[start+1..start+1+end].to_string());
            }
        }
        None
    }
}
