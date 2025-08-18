use serde::{Deserialize, Serialize};

pub const PIPE_NAME: &str = r"\\.\pipe\AntivirusService";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub is_valid: bool,
    pub expires_at: u64,
    pub license_type: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivationResult {
    pub activated: bool,
    pub expires_at: u64,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    pub is_running: bool,
    pub real_time_protection: bool,
    pub auto_scan_enabled: bool,
    pub last_scan_time: u64,
    pub last_update_time: u64,
    pub database_version: u32,
    pub total_threats_blocked: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    pub real_time_protection: bool,
    pub scan_on_access: bool,
    pub scan_archives: bool,
    pub auto_update: bool,
    pub scan_schedule: u32, // 0=disabled, 1=daily, 2=weekly
    pub scan_time: u32,     // Hour of day (0-23)
    pub quarantine_path: String,
    pub exclusion_paths: String, // Semicolon separated
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatInfo {
    pub file_path: String,
    pub threat_name: String,
    pub threat_level: u32,
    pub file_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub files_scanned: u32,
    pub threats_found: u32,
    pub progress_percent: u32,
    pub current_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub total_files: u32,
    pub total_threats: u32,
    pub threats: Vec<ThreatInfo>,
}
