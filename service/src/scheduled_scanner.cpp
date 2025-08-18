#include "scheduled_scanner.h"
#include "scanner.h"
#include "threat_engine.h"
#include "logger.h"
#include <iomanip>
#include <sstream>
#include <ctime>

ScheduledScanner::ScheduledScanner(Logger* logger, Scanner* scanner, ThreatEngine* threatEngine)
    : m_logger(logger)
    , m_scanner(scanner)
    , m_threatEngine(threatEngine)
    , m_running(false)
    , m_scanInProgress(false) {
}

ScheduledScanner::~ScheduledScanner() {
    Shutdown();
}

bool ScheduledScanner::Initialize() {
    if (m_running.load()) {
        return true;
    }

    if (m_logger) {
        m_logger->Info(L"Initializing Scheduled Scanner...");
    }

    try {
        m_running.store(true);
        m_schedulerThread = std::thread(&ScheduledScanner::SchedulerThread, this);

        if (m_logger) {
            m_logger->Info(L"Scheduled Scanner initialized successfully");
        }

        return true;
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Failed to initialize Scheduled Scanner: %S", e.what());
        }
        return false;
    }
}

void ScheduledScanner::Shutdown() {
    if (!m_running.load()) {
        return;
    }

    if (m_logger) {
        m_logger->Info(L"Shutting down Scheduled Scanner...");
    }

    m_running.store(false);

    if (m_schedulerThread.joinable()) {
        m_schedulerThread.join();
    }

    if (m_logger) {
        m_logger->Info(L"Scheduled Scanner shutdown complete");
    }
}

void ScheduledScanner::SetScheduleConfig(const ScheduleConfig& config) {
    m_config = config;

    if (m_logger) {
        std::wstring scheduleType;
        switch (config.type) {
        case ScheduleType::Disabled:
            scheduleType = L"Disabled";
            break;
        case ScheduleType::Daily:
            scheduleType = L"Daily";
            break;
        case ScheduleType::Weekly:
            scheduleType = L"Weekly";
            break;
        case ScheduleType::Monthly:
            scheduleType = L"Monthly";
            break;
        }

        if (config.enabled) {
            auto nextScan = GetNextScheduledScan();
            auto nextTime = std::chrono::system_clock::to_time_t(nextScan);
            
            std::wstringstream ss;
            ss << std::put_time(std::localtime(&nextTime), L"%Y-%m-%d %H:%M:%S");
            
            m_logger->LogFormat(LogLevel::Info, 
                               L"Schedule updated: %s at %d:00, next scan: %s", 
                               scheduleType.c_str(), config.hour, ss.str().c_str());
        } else {
            m_logger->LogFormat(LogLevel::Info, L"Schedule set to: %s", scheduleType.c_str());
        }
    }
}

bool ScheduledScanner::TriggerScanNow(const std::wstring& scanType) {
    if (m_scanInProgress.load()) {
        if (m_logger) {
            m_logger->Warning(L"Cannot trigger scan - scan already in progress");
        }
        return false;
    }

    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Manually triggered scan: %s", scanType.c_str());
    }

    // Execute scan in a separate thread
    std::thread([this, scanType]() {
        ExecuteScan(scanType);
    }).detach();

    return true;
}

std::chrono::system_clock::time_point ScheduledScanner::GetNextScheduledScan() const {
    if (!m_config.enabled || m_config.type == ScheduleType::Disabled) {
        return std::chrono::system_clock::time_point::max();
    }

    return CalculateNextScanTime();
}

void ScheduledScanner::SchedulerThread() {
    if (m_logger) {
        m_logger->Info(L"Scheduled Scanner thread started");
    }

    while (m_running.load()) {
        try {
            // Check if it's time for a scheduled scan
            if (m_config.enabled && IsTimeForScan()) {
                ExecuteScheduledScan();
            }

            // Sleep for 1 minute before checking again
            std::this_thread::sleep_for(std::chrono::minutes(1));
        }
        catch (const std::exception& e) {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Error, L"Exception in scheduler thread: %S", e.what());
            }
            std::this_thread::sleep_for(std::chrono::minutes(5)); // Wait longer on error
        }
    }

    if (m_logger) {
        m_logger->Info(L"Scheduled Scanner thread stopped");
    }
}

std::chrono::system_clock::time_point ScheduledScanner::CalculateNextScanTime() const {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto local_tm = *std::localtime(&now_time_t);

    // Set the target hour
    local_tm.tm_hour = m_config.hour;
    local_tm.tm_min = 0;
    local_tm.tm_sec = 0;

    std::chrono::system_clock::time_point nextScan;

    switch (m_config.type) {
    case ScheduleType::Daily: {
        // Schedule for today at the specified hour, or tomorrow if already past
        nextScan = std::chrono::system_clock::from_time_t(std::mktime(&local_tm));
        if (nextScan <= now) {
            local_tm.tm_mday += 1; // Add one day
            nextScan = std::chrono::system_clock::from_time_t(std::mktime(&local_tm));
        }
        break;
    }

    case ScheduleType::Weekly: {
        // Calculate days until the target day of week
        int daysUntilTarget = (m_config.dayOfWeek - local_tm.tm_wday + 7) % 7;
        if (daysUntilTarget == 0) {
            // Today is the target day - check if we've already passed the hour
            nextScan = std::chrono::system_clock::from_time_t(std::mktime(&local_tm));
            if (nextScan <= now) {
                daysUntilTarget = 7; // Next week
            }
        }
        
        local_tm.tm_mday += daysUntilTarget;
        nextScan = std::chrono::system_clock::from_time_t(std::mktime(&local_tm));
        break;
    }

    case ScheduleType::Monthly: {
        // Set target day of month
        local_tm.tm_mday = m_config.dayOfMonth;
        nextScan = std::chrono::system_clock::from_time_t(std::mktime(&local_tm));
        
        if (nextScan <= now) {
            // Next month
            if (local_tm.tm_mon == 11) {
                local_tm.tm_mon = 0;
                local_tm.tm_year += 1;
            } else {
                local_tm.tm_mon += 1;
            }
            local_tm.tm_mday = m_config.dayOfMonth;
            nextScan = std::chrono::system_clock::from_time_t(std::mktime(&local_tm));
        }
        break;
    }

    default:
        return std::chrono::system_clock::time_point::max();
    }

    return nextScan;
}

bool ScheduledScanner::IsTimeForScan() const {
    if (!m_config.enabled || m_config.type == ScheduleType::Disabled) {
        return false;
    }

    if (m_scanInProgress.load()) {
        return false; // Don't start another scan if one is in progress
    }

    auto now = std::chrono::system_clock::now();
    auto nextScan = CalculateNextScanTime();
    
    // Check if we're within the scan window (within 1 minute of the scheduled time)
    auto timeDiff = std::chrono::duration_cast<std::chrono::minutes>(nextScan - now);
    
    // Also ensure we haven't run a scan recently (within the last hour)
    if (m_lastScanTime != std::chrono::system_clock::time_point{}) {
        auto timeSinceLastScan = std::chrono::duration_cast<std::chrono::hours>(now - m_lastScanTime);
        if (timeSinceLastScan.count() < 1) {
            return false;
        }
    }

    return timeDiff.count() <= 1 && timeDiff.count() >= 0;
}

void ScheduledScanner::ExecuteScheduledScan() {
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Executing scheduled scan: %s at %s", 
                           m_config.scanType.c_str(), GetCurrentTimeString().c_str());
    }

    ExecuteScan(m_config.scanType);
}

void ScheduledScanner::ExecuteScan(const std::wstring& scanType) {
    if (m_scanInProgress.exchange(true)) {
        if (m_logger) {
            m_logger->Warning(L"Scan already in progress, skipping");
        }
        return;
    }

    auto scanStart = std::chrono::steady_clock::now();
    std::vector<ThreatInfo> threats;

    try {
        if (!m_scanner) {
            if (m_logger) {
                m_logger->Error(L"Scanner not available");
            }
            m_scanInProgress.store(false);
            return;
        }

        ScanResult result = ScanResult::Failed;

        if (scanType == L"quick") {
            result = m_scanner->QuickScan(threats);
        }
        else if (scanType == L"full") {
            result = m_scanner->FullScan(threats);
        }
        else if (scanType == L"system") {
            result = m_scanner->ScanSystem(threats);
        }
        else {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Warning, L"Unknown scan type: %s, defaulting to quick scan", 
                                   scanType.c_str());
            }
            result = m_scanner->QuickScan(threats);
        }

        auto scanEnd = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(scanEnd - scanStart);

        m_lastScanTime = std::chrono::system_clock::now();

        if (m_logger) {
            m_logger->LogFormat(LogLevel::Info, 
                               L"Scheduled scan completed. Duration: %lld ms, Threats found: %zu, Result: %d", 
                               duration.count(), threats.size(), static_cast<int>(result));
        }

        // Call completion callback
        if (m_scanCompleteCallback) {
            m_scanCompleteCallback(threats, duration);
        }

        // Handle found threats
        if (!threats.empty()) {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Critical, L"Scheduled scan found %zu threats!", threats.size());
                
                for (const auto& threat : threats) {
                    m_logger->LogFormat(LogLevel::Critical, L"Threat: %s in file %s (Level: %d)", 
                                       threat.threat_name.c_str(), threat.file_path.c_str(), threat.threat_level);
                    
                    // Auto-quarantine high-severity threats
                    if (threat.threat_level >= 8 && m_threatEngine) {
                        if (m_threatEngine->QuarantineFile(threat.file_path, threat.threat_name)) {
                            m_logger->LogFormat(LogLevel::Info, L"High-severity threat auto-quarantined: %s", 
                                               threat.file_path.c_str());
                        }
                    }
                }
            }
        }
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Exception during scheduled scan: %S", e.what());
        }
    }

    m_scanInProgress.store(false);
}

std::wstring ScheduledScanner::GetCurrentTimeString() const {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    
    std::wstringstream ss;
    ss << std::put_time(std::localtime(&now_time_t), L"%Y-%m-%d %H:%M:%S");
    return ss.str();
}
