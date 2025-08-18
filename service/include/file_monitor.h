#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <atomic>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <map>
#include <chrono>

class Logger;
class ThreatEngine;
struct ThreatInfo;

struct ScanRequest {
    std::wstring filePath;
    uint32_t priority;
    std::chrono::steady_clock::time_point timestamp;
    
    // For priority queue (higher priority first)
    bool operator<(const ScanRequest& other) const {
        return priority < other.priority;
    }
};

struct WatchInfo {
    HANDLE handle;
    std::wstring path;
    std::vector<char> buffer;
    OVERLAPPED overlapped;
};

class FileMonitor {
public:
    FileMonitor(Logger* logger, ThreatEngine* threatEngine);
    ~FileMonitor();

    bool Initialize();
    void Shutdown();

    // Configuration
    void AddWatchPath(const std::wstring& path);
    void RemoveWatchPath(const std::wstring& path);
    void SetRealTimeProtection(bool enabled);
    
    // Status
    bool IsRunning() const { return m_running.load(); }
    bool IsRealTimeProtectionEnabled() const { return m_realTimeProtectionEnabled.load(); }
    size_t GetWatchedPathCount() const { return m_watchedPaths.size(); }

private:
    Logger* m_logger;
    ThreatEngine* m_threatEngine;
    std::atomic<bool> m_running;
    std::atomic<bool> m_realTimeProtectionEnabled;
    
    // Threading
    std::thread m_monitorThread;
    std::vector<std::thread> m_workerThreads;
    size_t m_maxThreads;
    
    // Synchronization
    std::mutex m_pathsMutex;
    std::mutex m_queueMutex;
    std::condition_variable m_workCondition;
    
    // File watching
    std::vector<std::wstring> m_watchedPaths;
    std::map<std::wstring, WatchInfo> m_watchHandles;
    
    // Scan queue
    std::priority_queue<ScanRequest> m_scanQueue;
    
    // Configuration
    uint32_t m_scanDelayMs;
    
    // Thread functions
    void MonitorThread();
    void WorkerThread();
    
    // Event processing
    void ProcessDirectoryChanges(const std::wstring& watchPath);
    void ProcessFileEvent(const std::wstring& filePath, DWORD action);
    void ProcessScanRequest(const ScanRequest& request);
    
    // Threat handling
    void HandleThreatDetection(const ThreatInfo& threat);
    
    // Utility functions
    bool ShouldSkipFile(const std::wstring& filePath) const;
    uint32_t DetermineScanPriority(const std::wstring& filePath) const;
};
