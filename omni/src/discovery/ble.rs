use anyhow::{Result, anyhow};
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use futures::stream::StreamExt;
use std::time::Duration;
use tokio::time;
use uuid::Uuid;

// Google Quick Share Service UUID: 0000FEF3-0000-1000-8000-00805F9B34FB
const QUICK_SHARE_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000FEF3_0000_1000_8000_00805F9B34FB);

pub async fn scan_for_quick_share() -> Result<()> {
    let manager = Manager::new().await?;

    // get the first bluetooth adapter
    let adapters = manager.adapters().await?;
    let central = adapters.into_iter().nth(0).ok_or_else(|| anyhow!("No Bluetooth adapters found"))?;

    // start scanning for devices
    central.start_scan(ScanFilter::default()).await?;
    println!("Scanning for Quick Share devices (Service UUID: {:?})...", QUICK_SHARE_SERVICE_UUID);

    // Using a stream to handle events is more robust for async
    let mut events = central.events().await?;

    // Scan for 10 seconds effectively (looping over events)
    let scan_duration = Duration::from_secs(15);
    let start_time = time::Instant::now();

    while start_time.elapsed() < scan_duration {
        // Poll for events with timeout
        if let Ok(Some(event)) = time::timeout(Duration::from_millis(100), events.next()).await {
             match event {
                btleplug::api::CentralEvent::DeviceDiscovered(id) | 
                btleplug::api::CentralEvent::DeviceUpdated(id) => {
                    if let Ok(device) = central.peripheral(&id).await {
                        if let Ok(Some(props)) = device.properties().await {
                            // Check if the device advertises the Quick Share Service UUID
                             if props.services.contains(&QUICK_SHARE_SERVICE_UUID) || props.service_data.contains_key(&QUICK_SHARE_SERVICE_UUID) {
                                println!("Found Quick Share Device!");
                                println!("   - Name: {}", props.local_name.as_deref().unwrap_or("Unknown"));
                                println!("   - ID: {:?}", id);
                                println!("   - RSSI: {:?}", props.rssi);
                                
                                // Parse the 'Service Data' (The Quick Share Payload)
                                if let Some(data) = props.service_data.get(&QUICK_SHARE_SERVICE_UUID) {
                                    println!("   - Raw Payload ({} bytes): {:02X?}", data.len(), data);
                                    
                                    // According to Nearby Connections Spec:
                                    // Byte 0: Version & PCP (Topology)
                                    // Bytes 1-4: Endpoint ID (Random 4-char string)
                                    // Bytes 5+: Encrypted Metadata
                                    
                                    if data.len() >= 5 {
                                        let endpoint_id_bytes = &data[1..5];
                                        let endpoint_id = String::from_utf8_lossy(endpoint_id_bytes);
                                        println!("   ------------------------------------");
                                        println!("   DECODED ENDPOINT ID: \"{}\"", endpoint_id);
                                        println!("   ------------------------------------");
                                    }
                                }
                             }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(())
}
