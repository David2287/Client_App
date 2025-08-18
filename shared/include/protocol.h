#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Protocol {

// Named pipe name for communication
constexpr const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\AntivirusService";

// Message types
enum class MessageType : uint32_t {
    // Authentication
    AUTH_REQUEST = 1,
    AUTH_RESPONSE = 2,
    LICENSE_CHECK = 3,
    LICENSE_RESPONSE = 4,
    ACTIVATE_REQUEST = 5,
    ACTIVATE_RESPONSE = 6,

    // Scanning
    SCAN_REQUEST = 10,
    SCAN_RESPONSE = 11,
    SCAN_PROGRESS = 12,
    SCAN_COMPLETE = 13,

    // Status
    STATUS_REQUEST = 20,
    STATUS_RESPONSE = 21,
    THREAT_DETECTED = 22,

    // Settings
    SETTINGS_GET = 30,
    SETTINGS_SET = 31,
    SETTINGS_RESPONSE = 32,

    // Updates
    UPDATE_CHECK = 40,
    UPDATE_DOWNLOAD = 41,
    UPDATE_STATUS = 42,

    // Control
    SHUTDOWN_REQUEST = 50,
    SHUTDOWN_RESPONSE = 51,

    // Error
    ERROR_RESPONSE = 99
};

// Result codes
enum class ResultCode : uint32_t {
    SUCCESS = 0,
    INVALID_CREDENTIALS = 1,
    NO_LICENSE = 2,
    INVALID_LICENSE = 3,
    SCAN_FAILED = 4,
    ACCESS_DENIED = 5,
    INTERNAL_ERROR = 6
};

// Scan types
enum class ScanType : uint32_t {
    FILE = 1,
    FOLDER = 2,
    DRIVE = 3,
    SYSTEM = 4
};

// Message header
struct MessageHeader {
    uint32_t magic;           // Magic number for validation
    MessageType type;         // Message type
    uint32_t length;          // Total message length including header
    uint32_t sequence;        // Sequence number for request/response matching
    uint32_t reserved;        // Reserved for future use

    static constexpr uint32_t MAGIC_NUMBER = 0x41565353; // 'AVSS'
};

// Authentication request
struct AuthRequest {
    MessageHeader header;
    wchar_t username[256];
    wchar_t password[256];
};

// Authentication response
struct AuthResponse {
    MessageHeader header;
    ResultCode result;
    bool has_license;
    wchar_t message[512];
};

// License check request
struct LicenseCheckRequest {
    MessageHeader header;
    wchar_t username[256];
};

// License response
struct LicenseResponse {
    MessageHeader header;
    ResultCode result;
    bool is_valid;
    uint64_t expires_at;
    wchar_t license_type[64];
    wchar_t message[512];
};

// Activation request
struct ActivationRequest {
    MessageHeader header;
    wchar_t username[256];
    wchar_t activation_key[128];
};

// Activation response
struct ActivationResponse {
    MessageHeader header;
    ResultCode result;
    bool activated;
    uint64_t expires_at;
    wchar_t message[512];
};

// Scan request
struct ScanRequest {
    MessageHeader header;
    ScanType scan_type;
    wchar_t path[512];
    bool deep_scan;
    bool scan_archives;
};

// Threat info
struct ThreatInfo {
    wchar_t file_path[512];
    wchar_t threat_name[256];
    uint32_t threat_level;    // 1-10 severity
    uint64_t file_size;
};

// Scan progress
struct ScanProgress {
    MessageHeader header;
    uint32_t files_scanned;
    uint32_t threats_found;
    uint32_t progress_percent;
    wchar_t current_file[512];
};

// Scan response
struct ScanResponse {
    MessageHeader header;
    ResultCode result;
    uint32_t total_files;
    uint32_t total_threats;
    uint32_t threat_count;
    // Followed by ThreatInfo array if threat_count > 0
};

// Status request
struct StatusRequest {
    MessageHeader header;
};

// Service status
struct ServiceStatus {
    MessageHeader header;
    bool is_running;
    bool real_time_protection;
    bool auto_scan_enabled;
    uint64_t last_scan_time;
    uint64_t last_update_time;
    uint32_t database_version;
    uint32_t total_threats_blocked;
};

// Settings request
struct SettingsRequest {
    MessageHeader header;
    bool get_settings;        // true = get, false = set
    // Settings data follows if set operation
};

// Settings data
struct Settings {
    bool real_time_protection;
    bool scan_on_access;
    bool scan_archives;
    bool auto_update;
    uint32_t scan_schedule;   // 0=disabled, 1=daily, 2=weekly
    uint32_t scan_time;       // Hour of day (0-23)
    wchar_t quarantine_path[512];
    wchar_t exclusion_paths[2048]; // Semicolon separated
};

// Settings response
struct SettingsResponse {
    MessageHeader header;
    ResultCode result;
    Settings settings;
};

// Update check request
struct UpdateCheckRequest {
    MessageHeader header;
};

// Update status
struct UpdateStatus {
    MessageHeader header;
    bool update_available;
    uint32_t current_version;
    uint32_t latest_version;
    uint64_t update_size;
    wchar_t update_description[1024];
};

// Error response
struct ErrorResponse {
    MessageHeader header;
    ResultCode error_code;
    wchar_t error_message[1024];
};

} // namespace Protocol
