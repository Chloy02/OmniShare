mod commands;

use commands::{AppState, SharedState};
use std::sync::Arc;
use tauri::{
    menu::{Menu, MenuItem},
    tray::TrayIconBuilder,
    Manager,
};
use tokio::sync::Mutex;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let state: SharedState = Arc::new(Mutex::new(AppState::default()));

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state)
        .setup(|app| {
            // Create system tray menu
            let quit = MenuItem::with_id(app, "quit", "Quit OmniShare", true, None::<&str>)?;
            let show = MenuItem::with_id(app, "show", "Open OmniShare", true, None::<&str>)?;
            let toggle_visible = MenuItem::with_id(app, "toggle_visible", "Toggle Visibility", true, None::<&str>)?;
            
            let menu = Menu::with_items(app, &[&show, &toggle_visible, &quit])?;

            // Build tray icon
            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("OmniShare - Quick Share for Linux")
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "quit" => {
                            app.exit(0);
                        }
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "toggle_visible" => {
                            // TODO: Toggle BLE visibility
                            println!("Toggle visibility clicked");
                        }
                        _ => {}
                    }
                })
                .build(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::start_receiver,
            commands::stop_receiver,
            commands::is_receiver_running,
            commands::accept_transfer,
            commands::reject_transfer,
            commands::get_pending_transfers,
            commands::get_transfer_history,
            commands::get_settings,
            commands::set_save_location,
            commands::set_device_name,
            commands::set_visibility,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
