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
// CONFIRMED: Quick Share uses 0xFE2C (Fast Pair) with Model ID 0xFC128E.
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
                            read: true, // <--- CRITICAL: Enables "Read" flag
                            fun: Box::new(|_| Box::pin(async {
                                Ok(vec![0x00, 0x00, 0x01]) // Dummy Model ID
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    // Key-based Pairing (Write/Notify stub)
                    Characteristic {
                        uuid: KEY_BASED_PAIRING_UUID,
                        write: Some(CharacteristicWrite {
                            write: true, // <--- CRITICAL: Enables "Write" flag
                            method: CharacteristicWriteMethod::Fun(Box::new(|new_value, _| Box::pin(async move {
                                println!("Remote wrote to Key-based Pairing: {:?}", new_value);
                                Ok(())
                            }))),
                            ..Default::default()
                        }),
                        notify: Some(CharacteristicNotify {
                            notify: true, // <--- CRITICAL: Enables "Notify" flag
                            method: CharacteristicNotifyMethod::Fun(Box::new(|_| Box::pin(async {
                                // Notification subscription handler
                                println!("Remote subscribed to notifications");
                            }))),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };
        let app_handle = adapter.serve_gatt_application(app).await
            .context("Failed to register GATT application")?;

        // 2. Register Advertisement (The "Sign")
        // Generate Session Endpoint ID (4 chars) - Used for mDNS later
        let endpoint_id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(4)
            .map(char::from)
            .collect();
        
        println!("Generated Session Endpoint ID: {}", endpoint_id);

        // Construct 15-byte Quick Share "Trigger" Payload
        // Header: [0xFC, 0x12, 0x8E] (Model ID) + [0x01] (OpCode) + [0x42] (Meta)
        let mut service_data_payload = Vec::with_capacity(15);
        service_data_payload.push(0xFC);
        service_data_payload.push(0x12);
        service_data_payload.push(0x8E);
        service_data_payload.push(0x01);
        service_data_payload.push(0x42);

        // Salt: 10 Bytes of Randomness
        let salt: [u8; 10] = thread_rng().gen(); 
        service_data_payload.extend_from_slice(&salt);
        println!("Generated Payload (15 bytes): {:02X?}", service_data_payload);

        let mut service_data = BTreeMap::new();
        // The Key MUST be 0xFE2C (Fast Pair)
        let fast_pair_uuid = Uuid::from_u16(FAST_PAIR_SERVICE_UUID);
        service_data.insert(fast_pair_uuid, service_data_payload);

        let le_advertisement = Advertisement {
            service_data,
            discoverable: Some(true),
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
