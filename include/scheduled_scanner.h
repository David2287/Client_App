#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>
#include <functional>

class Logger;
class Scanner;
class ThreatEngine;
struct ThreatInfo;

enum class ScheduleType {
    Disabled = 0,
    Daily = 1,
    Weekly = 2,
    Monthly = 3
};

struct ScheduleConfig {
    ScheduleType type;
    uint32_t hour;        // Hour of day (0-23)
    uint32_t dayOfWeek;   // Day of week for weekly scans (0=Sunday, 6=Saturday)
    uint32_t dayOfMonth;  // Day of month for monthly scans (1-31)
    bool enabled;
    std::wstring scanType; // "quick", "full", "system"
    
    ScheduleConfig() : type(ScheduleType::Disabled), hour(2), dayOfWeek(0), 
                      dayOfMonth(1), enabled(false), scanType(L"quick") {}
};

class ScheduledScanner {
public:
    // Scan complete callback: (threats found, scan duration)
    using ScanCompleteCallback = std::function<void(const std::vector<ThreatInfo>&, std::chrono::milliseconds)>;

    ScheduledScanner(Logger* logger, Scanner* scanner, ThreatEngine* threatEngine);
    ~ScheduledScanner();

    bool Initialize();
    void Shutdown();

    // Configuration
    void SetScheduleConfig(const ScheduleConfig& config);
    const ScheduleConfig& GetScheduleConfig() const { return m_config; }
    
    // Manual trigger
    bool TriggerScanNow(const std::wstring& scanType = L"quick");
    
    // Status
    bool IsRunning() const { return m_running.load(); }
    bool IsScheduleEnabled() const { return m_config.enabled; }
    bool IsScanInProgress() const { return m_scanInProgress.load(); }
    
    std::chrono::system_clock::time_point GetNextScheduledScan() const;
    std::chrono::system_clock::time_point GetLastScanTime() const { return m_lastScanTime; }
    
    // Callbacks
    void SetScanCompleteCallback(ScanCompleteCallback callback) { m_scanCompleteCallback = callback; }

private:
    Logger* m_logger;
    Scanner* m_scanner;
    ThreatEngine* m_threatEngine;
    
    ScheduleConfig m_config;
    std::atomic<bool> m_running;
    std::atomic<bool> m_scanInProgress;
    std::thread m_schedulerThread;
    
    std::chrono::system_clock::time_point m_lastScanTime;
    ScanCompleteCallback m_scanCompleteCallback;
    
    // Scheduler thread
    void SchedulerThread();
    
    // Time calculations
    std::chrono::system_clock::time_point CalculateNextScanTime() const;
    bool IsTimeForScan() const;
    
    // Scan execution
    void ExecuteScheduledScan();
    void ExecuteScan(const std::wstring& scanType);
    
    // Utility
    std::wstring GetCurrentTimeString() const;
};
