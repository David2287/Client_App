// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use tauri::{
    AppHandle, CustomMenuItem, Manager, State, SystemTray, SystemTrayEvent, SystemTrayMenu,
    SystemTrayMenuItem, Window,
};

mod service_client;
mod protocol;

use service_client::ServiceClient;

// Application state
#[derive(Default)]
struct AppState {
    service_client: Arc<Mutex<Option<ServiceClient>>>,
}

// Tauri commands
#[tauri::command]
async fn authenticate(
    username: String,
    password: String,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let client = state.service_client.lock().unwrap();
    if let Some(client) = client.as_ref() {
        client.authenticate(&username, &password).await.map_err(|e| e.to_string())
    } else {
        Err("Service client not connected".to_string())
    }
}

#[tauri::command]
async fn check_license(
    username: String,
    state: State<'_, AppState>,
) -> Result<protocol::LicenseInfo, String> {
    let client = state.service_client.lock().unwrap();
    if let Some(client) = client.as_ref() {
        client.check_license(&username).await.map_err(|e| e.to_string())
    } else {
        Err("Service client not connected".to_string())
    }
}

#[tauri::command]
async fn activate_license(
    username: String,
    activation_key: String,
    state: State<'_, AppState>,
) -> Result<protocol::ActivationResult, String> {
    let client = state.service_client.lock().unwrap();
    if let Some(client) = client.as_ref() {
        client.activate_license(&username, &activation_key).await.map_err(|e| e.to_string())
    } else {
        Err("Service client not connected".to_string())
    }
}

#[tauri::command]
async fn start_scan(
    scan_type: String,
    path: String,
    deep_scan: bool,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let client = state.service_client.lock().unwrap();
    if let Some(client) = client.as_ref() {
        client.start_scan(&scan_type, &path, deep_scan).await.map_err(|e| e.to_string())
    } else {
        Err("Service client not connected".to_string())
    }
}

#[tauri::command]
async fn get_status(
    state: State<'_, AppState>,
) -> Result<protocol::ServiceStatus, String> {
    let client = state.service_client.lock().unwrap();
    if let Some(client) = client.as_ref() {
        client.get_status().await.map_err(|e| e.to_string())
    } else {
        Err("Service client not connected".to_string())
    }
}

#[tauri::command]
async fn get_settings(
    state: State<'_, AppState>,
) -> Result<protocol::Settings, String> {
    let client = state.service_client.lock().unwrap();
    if let Some(client) = client.as_ref() {
        client.get_settings().await.map_err(|e| e.to_string())
    } else {
        Err("Service client not connected".to_string())
    }
}

#[tauri::command]
async fn update_settings(
    settings: protocol::Settings,
    state: State<'_, AppState>,
) -> Result<bool, String> {
    let client = state.service_client.lock().unwrap();
    if let Some(client) = client.as_ref() {
        client.update_settings(settings).await.map_err(|e| e.to_string())
    } else {
        Err("Service client not connected".to_string())
    }
}

#[tauri::command]
fn show_main_window(window: Window) {
    window.get_window("main").unwrap().show().unwrap();
    window.get_window("main").unwrap().set_focus().unwrap();
}

#[tauri::command]
fn hide_main_window(window: Window) {
    window.get_window("main").unwrap().hide().unwrap();
}

// System tray setup
fn create_system_tray() -> SystemTray {
    let open = CustomMenuItem::new("open".to_string(), "Open Antivirus");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide Window");
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    
    let tray_menu = SystemTrayMenu::new()
        .add_item(open)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(hide)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);

    SystemTray::new().with_menu(tray_menu)
}

fn main() {
    env_logger::init();

    let tray = create_system_tray();
    
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_shell::init())
        .system_tray(tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick {
                position: _,
                size: _,
                ..
            } => {
                let window = app.get_window("main").unwrap();
                if window.is_visible().unwrap() {
                    window.hide().unwrap();
                } else {
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
            }
            SystemTrayEvent::RightClick {
                position: _,
                size: _,
                ..
            } => {
                // Context menu will show automatically
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "open" => {
                    let window = app.get_window("main").unwrap();
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
                "hide" => {
                    let window = app.get_window("main").unwrap();
                    window.hide().unwrap();
                }
                "quit" => {
                    std::process::exit(0);
                }
                _ => {}
            },
            _ => {}
        })
        .on_window_event(|event| match event.event() {
            tauri::WindowEvent::CloseRequested { api, .. } => {
                event.window().hide().unwrap();
                api.prevent_close();
            }
            _ => {}
        })
        .setup(|app| {
            let app_handle = app.handle();
            
            // Initialize service client connection
            tauri::async_runtime::spawn(async move {
                let state: State<AppState> = app_handle.state();
                let mut client_guard = state.service_client.lock().unwrap();
                
                match ServiceClient::new().await {
                    Ok(client) => {
                        *client_guard = Some(client);
                        log::info!("Successfully connected to antivirus service");
                    }
                    Err(e) => {
                        log::error!("Failed to connect to antivirus service: {}", e);
                        // Show error notification
                        if let Err(e) = app_handle.notification()
                            .builder()
                            .title("Antivirus Client")
                            .body("Failed to connect to antivirus service")
                            .show() {
                            log::error!("Failed to show notification: {}", e);
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            authenticate,
            check_license,
            activate_license,
            start_scan,
            get_status,
            get_settings,
            update_settings,
            show_main_window,
            hide_main_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
