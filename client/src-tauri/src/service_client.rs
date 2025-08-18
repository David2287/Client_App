use crate::protocol::*;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use thiserror::Error;
use windows::{
    core::PCSTR,
    Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE},
    Win32::System::Pipes::{CreateFileA, PIPE_ACCESS_DUPLEX},
    Win32::Storage::FileSystem::{
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
};

#[derive(Error, Debug)]
pub enum ServiceClientError {
    #[error("Failed to connect to service: {0}")]
    ConnectionFailed(String),
    #[error("Communication error: {0}")]
    CommunicationError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Service returned error: {0}")]
    ServiceError(String),
}

pub struct ServiceClient {
    pipe_handle: HANDLE,
}

impl ServiceClient {
    pub async fn new() -> Result<Self, ServiceClientError> {
        let pipe_name = PIPE_NAME;
        
        // Convert to PCSTR
        let pipe_name_cstr = std::ffi::CString::new(pipe_name)
            .map_err(|e| ServiceClientError::ConnectionFailed(e.to_string()))?;
        
        unsafe {
            let handle = CreateFileA(
                PCSTR(pipe_name_cstr.as_ptr() as *const u8),
                FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            );

            if handle == INVALID_HANDLE_VALUE {
                return Err(ServiceClientError::ConnectionFailed(
                    "Failed to connect to named pipe".to_string(),
                ));
            }

            Ok(ServiceClient {
                pipe_handle: handle,
            })
        }
    }

    pub async fn authenticate(&self, username: &str, password: &str) -> Result<bool, ServiceClientError> {
        let request = serde_json::json!({
            "type": "auth_request",
            "username": username,
            "password": password
        });

        let response = self.send_request(request).await?;
        
        if let Some(result) = response.get("result").and_then(|v| v.as_bool()) {
            Ok(result)
        } else {
            Err(ServiceClientError::ServiceError(
                response.get("message")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Authentication failed")
                    .to_string()
            ))
        }
    }

    pub async fn check_license(&self, username: &str) -> Result<LicenseInfo, ServiceClientError> {
        let request = serde_json::json!({
            "type": "license_check",
            "username": username
        });

        let response = self.send_request(request).await?;
        
        Ok(LicenseInfo {
            is_valid: response.get("is_valid").and_then(|v| v.as_bool()).unwrap_or(false),
            expires_at: response.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0),
            license_type: response.get("license_type").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            message: response.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    }

    pub async fn activate_license(&self, username: &str, activation_key: &str) -> Result<ActivationResult, ServiceClientError> {
        let request = serde_json::json!({
            "type": "activate_request",
            "username": username,
            "activation_key": activation_key
        });

        let response = self.send_request(request).await?;
        
        Ok(ActivationResult {
            activated: response.get("activated").and_then(|v| v.as_bool()).unwrap_or(false),
            expires_at: response.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0),
            message: response.get("message").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    }

    pub async fn start_scan(&self, scan_type: &str, path: &str, deep_scan: bool) -> Result<String, ServiceClientError> {
        let request = serde_json::json!({
            "type": "scan_request",
            "scan_type": scan_type,
            "path": path,
            "deep_scan": deep_scan
        });

        let response = self.send_request(request).await?;
        
        Ok(response.get("scan_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    pub async fn get_status(&self) -> Result<ServiceStatus, ServiceClientError> {
        let request = serde_json::json!({
            "type": "status_request"
        });

        let response = self.send_request(request).await?;
        
        Ok(ServiceStatus {
            is_running: response.get("is_running").and_then(|v| v.as_bool()).unwrap_or(false),
            real_time_protection: response.get("real_time_protection").and_then(|v| v.as_bool()).unwrap_or(false),
            auto_scan_enabled: response.get("auto_scan_enabled").and_then(|v| v.as_bool()).unwrap_or(false),
            last_scan_time: response.get("last_scan_time").and_then(|v| v.as_u64()).unwrap_or(0),
            last_update_time: response.get("last_update_time").and_then(|v| v.as_u64()).unwrap_or(0),
            database_version: response.get("database_version").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            total_threats_blocked: response.get("total_threats_blocked").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
        })
    }

    pub async fn get_settings(&self) -> Result<Settings, ServiceClientError> {
        let request = serde_json::json!({
            "type": "settings_get"
        });

        let response = self.send_request(request).await?;
        
        let settings = response.get("settings").ok_or_else(|| {
            ServiceClientError::ServiceError("No settings in response".to_string())
        })?;

        Ok(Settings {
            real_time_protection: settings.get("real_time_protection").and_then(|v| v.as_bool()).unwrap_or(true),
            scan_on_access: settings.get("scan_on_access").and_then(|v| v.as_bool()).unwrap_or(true),
            scan_archives: settings.get("scan_archives").and_then(|v| v.as_bool()).unwrap_or(false),
            auto_update: settings.get("auto_update").and_then(|v| v.as_bool()).unwrap_or(true),
            scan_schedule: settings.get("scan_schedule").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
            scan_time: settings.get("scan_time").and_then(|v| v.as_u64()).unwrap_or(2) as u32,
            quarantine_path: settings.get("quarantine_path").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            exclusion_paths: settings.get("exclusion_paths").and_then(|v| v.as_str()).unwrap_or("").to_string(),
        })
    }

    pub async fn update_settings(&self, settings: Settings) -> Result<bool, ServiceClientError> {
        let request = serde_json::json!({
            "type": "settings_set",
            "settings": {
                "real_time_protection": settings.real_time_protection,
                "scan_on_access": settings.scan_on_access,
                "scan_archives": settings.scan_archives,
                "auto_update": settings.auto_update,
                "scan_schedule": settings.scan_schedule,
                "scan_time": settings.scan_time,
                "quarantine_path": settings.quarantine_path,
                "exclusion_paths": settings.exclusion_paths
            }
        });

        let response = self.send_request(request).await?;
        
        Ok(response.get("success").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    async fn send_request(&self, request: serde_json::Value) -> Result<serde_json::Value, ServiceClientError> {
        let request_str = serde_json::to_string(&request)
            .map_err(|e| ServiceClientError::SerializationError(e.to_string()))?;

        // Convert HANDLE to std::fs::File for easier I/O
        let mut file = unsafe { 
            std::fs::File::from_raw_handle(self.pipe_handle.0 as *mut std::ffi::c_void) 
        };

        // Send request
        file.write_all(request_str.as_bytes())
            .map_err(|e| ServiceClientError::CommunicationError(e.to_string()))?;
        
        // Read response
        let mut response_buffer = vec![0u8; 4096];
        let bytes_read = file.read(&mut response_buffer)
            .map_err(|e| ServiceClientError::CommunicationError(e.to_string()))?;
        
        response_buffer.truncate(bytes_read);
        let response_str = String::from_utf8(response_buffer)
            .map_err(|e| ServiceClientError::CommunicationError(e.to_string()))?;

        let response: serde_json::Value = serde_json::from_str(&response_str)
            .map_err(|e| ServiceClientError::SerializationError(e.to_string()))?;

        // Forget the file so we don't close the handle
        std::mem::forget(file);

        Ok(response)
    }
}

impl Drop for ServiceClient {
    fn drop(&mut self) {
        if self.pipe_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.pipe_handle);
            }
        }
    }
}
