use bluer::{
    adv::{Advertisement, AdvertisementHandle},
    gatt::local::{
        Application, Characteristic, Service, 
        CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod,
        CharacteristicNotify, CharacteristicNotifyMethod,
    },
    Session,
    UuidExt,
};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::sleep;
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;
use anyhow::{Context, Result};
use uuid::Uuid;

/// The Google Fast Pair Service UUID (0xFE2C) used for discovery
const FAST_PAIR_SERVICE_UUID: u16 = 0xFE2C;
/// Model ID Characteristic: FE2C1233-8366-4814-8EB0-01DE32100BEA
const MODEL_ID_UUID: Uuid = Uuid::from_u128(0xFE2C1233_8366_4814_8EB0_01DE32100BEA);
/// Key-based Pairing Characteristic: FE2C1234-8366-4814-8EB0-01DE32100BEA
const KEY_BASED_PAIRING_UUID: Uuid = Uuid::from_u128(0xFE2C1234_8366_4814_8EB0_01DE32100BEA);

pub struct BleService {
    _adv_handle: AdvertisementHandle,
    _app_handle: bluer::gatt::local::ApplicationHandle,
}

impl BleService {
    /// Starts the specific BLE Advertisement AND GATT Service.
    pub async fn start() -> Result<Self> {
        let session = Session::new().await.context("Failed to connect to BlueZ")?;
        let adapter = session.default_adapter().await.context("No Bluetooth adapter found")?;
        
        println!("Bluetooth Adapter: {}", adapter.name());
        adapter.set_powered(true).await.context("Failed to power on adapter")?;

        // 1. Register GATT Service (The "Menu")
        // Android scans 0xFE2C, then connects to checking for these characteristics.
        println!("Registering GATT Service (0xFE2C)...");
        let app = Application {
            services: vec![Service {
                uuid: Uuid::from_u16(FAST_PAIR_SERVICE_UUID),
                primary: true,
                characteristics: vec![
                    // Model ID (Read-only stub)
                    Characteristic {
                        uuid: MODEL_ID_UUID,
                        read: Some(CharacteristicRead {
                            fun: Box::new(|_| Box::pin(async {
                                Ok(vec![0x00, 0x00, 0x01]) // Dummy Model ID
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    /*
                    // Key-based Pairing (Write/Notify stub)
                    Characteristic {
                        uuid: KEY_BASED_PAIRING_UUID,
                        write: Some(CharacteristicWrite {
                            method: CharacteristicWriteMethod::Fun(Box::new(|new_value, _| Box::pin(async move {
                                println!("Remote wrote to Key-based Pairing: {:?}", new_value);
                                Ok(())
                            }))),
                            ..Default::default()
                        }),
                        notify: Some(CharacteristicNotify {
                            method: CharacteristicNotifyMethod::Fun(Box::new(|_| Box::pin(async {
                                // Notification subscription handler
                                println!("Remote subscribed to notifications");
                                // Notification handler returns () not Result
                            }))),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    */
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app_handle = adapter.serve_gatt_application(app).await
            .context("Failed to register GATT application")?;

        // 2. Start Advertising (The "Sign")

        // Generate a random 4-byte Endpoint ID (e.g., "AB12")
        let endpoint_id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(4)
            .map(char::from)
            .collect();
        
        println!("Generated Session Endpoint ID: {}", endpoint_id);

        // Construct the 0xFC9F Service Data Payload
        // According to research:
        // [0] = Status/Version (3 bits version, 1 bit visibility)
        //       Let's try 0x00 (Version 0, Visible) or match captured logs.
        //       Ref: NearDrop uses specific bytes. 
        //       For "Advertising as standard device", we often see:
        //       [Status Byte] [3 bytes Salt] [2 bytes Encryption Info...]
        // However, strictly following the "Null" salt for Anonymous:
        // We will construct a basic payload that at least identifies us.
        
        // SIMPLE PAYLOAD STRATEGY (Phase 1):
        // Byte 0: 0x23 (PCP High Priority + Version) - Just a guess based on logs, 
        //         but let's stick to the research doc's implied verification hash.
        // ACTUALLY: The safest bet is the "Fast Advertisement" format.
        // We will start with a payload that mimics a generic visible device.
        
        let mut service_data_payload = Vec::new();
        // 1. Status Byte (Visible, Version 1) -> Binary 00100000 ??
        // Let's use a placeholder that has worked in rquickshare: 
        // [0x00] (Visible) + Endpoint ID bytes?
        
        // Let's trust the "Reverse Engineer" doc table loosely but ensure we include the ID.
        // Payload = [Status Byte] + [Endpoint ID (4 bytes)] + [Salt (3 bytes)]
        // ADVERTISING STRATEGY v7 (The "Golden Sequence"):
        // Source: BLE Service Data Payload Structure.txt
        // UUID Key: 0xFE2C (Google Fast Pair) - NOT 0xFC9F!
        // Payload Header: FC 12 8E 01 42
        
        // 1. Fixed Header (5 Bytes)
        service_data_payload.push(0xFC); // OpCode: Nearby Share
        service_data_payload.push(0x12); // Version
        service_data_payload.push(0x8E); // Status: Visible
        service_data_payload.push(0x01); // Trigger: Public
        service_data_payload.push(0x42); // Magic Checksum

        // 2. Padding (9 Bytes)
        service_data_payload.extend_from_slice(&[0x00; 9]);

        // 3. Random Salt (10 Bytes)
        // "This is arguably the most critical dynamic part... must be randomized"
        let salt: [u8; 10] = thread_rng().gen(); 
        service_data_payload.extend_from_slice(&salt);
        
        println!("Generated Salt: {:?}", salt);

        let mut service_data = BTreeMap::new();
        // CRITICAL FIX: The Key MUST be 0xFE2C (Fast Pair), not 0xFC9F.
        let fast_pair_uuid = Uuid::from_u16(FAST_PAIR_SERVICE_UUID);
        service_data.insert(fast_pair_uuid, service_data_payload);

        let le_advertisement = Advertisement {
            // Reverting Legacy Optimization as requested.
            // This will push the packet size > 31 bytes, triggering Extended Advertising.
            service_uuids: vec![Uuid::from_u16(FAST_PAIR_SERVICE_UUID)].into_iter().collect(),
            service_data,
            discoverable: Some(true),
            local_name: Some("OmniShare".to_string()),
            // CRITICAL FIX: Force "Fast Advertising" (100ms) to trigger Android scan window.
            // Default (1.28s) is considered "Background" and ignored by Fast Pair.
            min_interval: Some(Duration::from_millis(100)),
            max_interval: Some(Duration::from_millis(100)),
            ..Default::default()
        };

        println!("Registering LE Advertisement...");
        let handle = adapter.advertise(le_advertisement).await
            .context("Failed to register advertisement. Is bluetoothd running?")?;

        println!("Success! Advertising as 'OmniShare' (ID: {}).", endpoint_id);
        println!("Android phones should now see a 'Device Nearby' notification (if close).");

        Ok(BleService { 
            _adv_handle: handle,
            _app_handle: app_handle,
        })
    }
}

/// Helper to keep the process alive while advertising
pub async fn run_forever() -> Result<()> {
    let _service = BleService::start().await?;
    
    // Keep alive
    loop {
        sleep(Duration::from_secs(600)).await;
    }
}
