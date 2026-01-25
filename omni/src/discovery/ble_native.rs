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
    pub async fn start(endpoint_id: String) -> Result<Self> {
        let session = Session::new().await.context("Failed to connect to BlueZ")?;
        let adapter = session.default_adapter().await.context("No Bluetooth adapter found")?;
        
        println!("Bluetooth Adapter: {}", adapter.name());
        adapter.set_powered(true).await.context("Failed to power on adapter")?;

        // 1. Register GATT Service (Fast Pair Verification)
        // Android requires BLE GATT connection to verify Model ID before TCP
        println!("Registering GATT Service (0xFE2C)...");
        let app = Application {
            services: vec![Service {
                uuid: Uuid::from_u16(FAST_PAIR_SERVICE_UUID),
                primary: true,
                characteristics: vec![
                    // Model ID (Read-only)
                    Characteristic {
                        uuid: MODEL_ID_UUID,
                        read: Some(CharacteristicRead {
                            read: true,
                            fun: Box::new(|_| Box::pin(async {
                                println!("GATT: Phone reading Model ID...");
                                // MUST match advertised Model ID
                                Ok(vec![0xFC, 0x12, 0x8E])
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    // Key-based Pairing (Write/Notify stub)
                    Characteristic {
                        uuid: KEY_BASED_PAIRING_UUID,
                        write: Some(CharacteristicWrite {
                            write: true,
                            method: CharacteristicWriteMethod::Fun(Box::new(|new_value, _| Box::pin(async move {
                                println!("GATT: Remote wrote to Key-based Pairing: {:?}", new_value);
                                Ok(())
                            }))),
                            ..Default::default()
                        }),
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Fun(Box::new(|_| Box::pin(async {
                                println!("GATT: Remote subscribed to notifications");
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
        // Endpoint ID passed from main (MUST match mDNS)
        println!("Using Shared Endpoint ID: {}", endpoint_id);

        // Construct 24-byte Quick Share "Trigger" Payload
        // PROTOCOL.MD Line 56: fc 12 8e 01 42 00 00 00 00 00 00 00 00 00 [10 random bytes]
        // CRITICAL: The 9 zero bytes are MANDATORY, not optional!
        let mut service_data_payload = Vec::with_capacity(24);
        
        // Header (5 bytes)
        service_data_payload.push(0xFC);  // Model ID byte 1
        service_data_payload.push(0x12);  // Model ID byte 2
        service_data_payload.push(0x8E);  // Model ID byte 3
        service_data_payload.push(0x01);  // OpCode
        service_data_payload.push(0x42);  // Meta
        
        // MANDATORY: 9 zero bytes padding (PROTOCOL.md compliance)
        service_data_payload.extend_from_slice(&[0x00; 9]);

        // Salt: 10 random bytes
        let salt: [u8; 10] = thread_rng().gen(); 
        service_data_payload.extend_from_slice(&salt);
        println!("Generated Payload (24 bytes): {:02X?}", service_data_payload);

        let mut service_data = BTreeMap::new();
        let fast_pair_uuid = Uuid::from_u16(FAST_PAIR_SERVICE_UUID);
        service_data.insert(fast_pair_uuid, service_data_payload);

        let le_advertisement = Advertisement {
            service_data,
            discoverable: Some(true), // MUST be connectable for GATT
            min_interval: Some(Duration::from_millis(100)),
            max_interval: Some(Duration::from_millis(100)),
            ..Default::default()
        };

        println!("Registering LE Advertisement...");
        let handle = adapter.advertise(le_advertisement).await
            .context("Failed to register advertisement")?;

        println!("Success! Advertising as 'OmniShare' (ID: {}).", endpoint_id);
        println!("Android phones should now see a 'Device Nearby' notification (if close).");

        Ok(BleService { 
            _adv_handle: handle,
            _app_handle: app_handle,
        })
    }
}

/// Helper to keep the process alive while advertising
pub async fn run_forever(endpoint_id: String) -> Result<()> {
    let _service = BleService::start(endpoint_id).await?;
    
    // Keep alive
    loop {
        sleep(Duration::from_secs(600)).await;
    }
}
