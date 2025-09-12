#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <functional>
#include <thread>
#include <mutex>

class Logger;
class ThreatEngine;
struct ThreatInfo;

enum class ScanType {
    File = 1,
    Folder = 2,
    Drive = 3,
    System = 4,
    Quick = 5,
    Full = 6,
    Custom = 7
};

enum class ScanResult {
    Success = 0,
    Failed = 1,
    Cancelled = 2,
    AccessDenied = 3
};

struct ScanStatistics {
    uint64_t totalFiles;
    uint64_t scannedFiles;
    uint64_t skippedFiles;
    uint64_t threatsFound;
    uint64_t totalBytes;
    uint64_t scannedBytes;
    uint32_t progressPercent;
    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    
    ScanStatistics() : totalFiles(0), scannedFiles(0), skippedFiles(0), 
                      threatsFound(0), totalBytes(0), scannedBytes(0), 
                      progressPercent(0) {}
};

struct ScanOptions {
    bool scanArchives;
    bool deepScan;
    bool heuristicAnalysis;
    bool followSymlinks;
    uint64_t maxFileSize;
    std::vector<std::wstring> exclusions;
    std::vector<std::wstring> extensions;
    
    ScanOptions() : scanArchives(false), deepScan(false), heuristicAnalysis(true),
                    followSymlinks(false), maxFileSize(100 * 1024 * 1024) {} // 100MB
};

class Scanner {
public:
    // Progress callback: (current file, progress percent, statistics)
    using ProgressCallback = std::function<void(const std::wstring&, uint32_t, const ScanStatistics&)>;
    // Threat callback: (threat info)
    using ThreatCallback = std::function<void(const ThreatInfo&)>;

    Scanner(Logger* logger, ThreatEngine* threatEngine);
    ~Scanner();

    // Scanning operations
    ScanResult ScanFile(const std::wstring& filePath, std::vector<ThreatInfo>& threats);
    ScanResult ScanFolder(const std::wstring& folderPath, std::vector<ThreatInfo>& threats);
    ScanResult ScanDrive(const std::wstring& driveLetter, std::vector<ThreatInfo>& threats);
    ScanResult ScanSystem(std::vector<ThreatInfo>& threats);
    ScanResult QuickScan(std::vector<ThreatInfo>& threats);
    ScanResult FullScan(std::vector<ThreatInfo>& threats);
    ScanResult CustomScan(const std::vector<std::wstring>& paths, std::vector<ThreatInfo>& threats);
    
    // Async scanning
    bool StartScanAsync(ScanType type, const std::vector<std::wstring>& targets);
    void CancelScan();
    bool IsScanning() const { return m_isScanning.load(); }
    bool IsCancelled() const { return m_cancelRequested.load(); }
    
    // Configuration
    void SetScanOptions(const ScanOptions& options) { m_options = options; }
    const ScanOptions& GetScanOptions() const { return m_options; }
    
    // Callbacks
    void SetProgressCallback(ProgressCallback callback) { m_progressCallback = callback; }
    void SetThreatCallback(ThreatCallback callback) { m_threatCallback = callback; }
    
    // Statistics
    const ScanStatistics& GetStatistics() const { return m_statistics; }
    
private:
    Logger* m_logger;
    ThreatEngine* m_threatEngine;
    ScanOptions m_options;
    ScanStatistics m_statistics;
    
    std::atomic<bool> m_isScanning;
    std::atomic<bool> m_cancelRequested;
    std::thread m_scanThread;
    std::mutex m_statisticsMutex;
    
    ProgressCallback m_progressCallback;
    ThreatCallback m_threatCallback;
    
    // Internal scanning methods
    ScanResult ScanPath(const std::wstring& path, std::vector<ThreatInfo>& threats);
    ScanResult ScanSingleFile(const std::wstring& filePath, std::vector<ThreatInfo>& threats);
    void ScanDirectoryRecursive(const std::wstring& dirPath, std::vector<ThreatInfo>& threats);
    
    // Async scan thread
    void AsyncScanThread(ScanType type, std::vector<std::wstring> targets);
    
    // Utility methods
    bool ShouldScanFile(const std::wstring& filePath) const;
    bool IsExcludedPath(const std::wstring& path) const;
    bool IsAllowedExtension(const std::wstring& extension) const;
    std::vector<std::wstring> GetSystemPaths() const;
    std::vector<std::wstring> GetQuickScanPaths() const;
    std::vector<std::wstring> GetAvailableDrives() const;
    
    // Statistics helpers
    void UpdateProgress();
    void ResetStatistics();
    
    // Archive scanning
    bool ScanArchive(const std::wstring& archivePath, std::vector<ThreatInfo>& threats);
};
