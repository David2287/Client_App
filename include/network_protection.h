#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <set>
#include <atomic>

// Forward declarations
class CloudIntelligence;

struct ConnectionBlock {
    std::string remoteAddress;
    uint16_t port;
    std::chrono::system_clock::time_point timestamp;
    std::string reason;
};

struct DownloadScanRequest {
    std::string filePath;
    std::string sourceUrl;
    std::chrono::system_clock::time_point timestamp;
};

struct NetworkProtectionStats {
    bool enabled;
    std::atomic<uint64_t> blockedConnections;
    std::atomic<uint64_t> scannedDownloads;
    size_t maliciousDomainsCount;
    size_t maliciousUrlPatternsCount;
    size_t recentBlocksCount;
};

struct DownloadScannerConfig {
    bool scanExecutables;
    bool scanArchives;
    bool scanDocuments;
    uint32_t maxFileSizeKB;
    bool quarantineMalicious;
};

class NetworkProtection {
public:
    NetworkProtection();
    ~NetworkProtection();
    
    bool initialize(CloudIntelligence* cloudIntelligence);
    void shutdown();
    
    bool start();
    void stop();
    
    bool isUrlBlocked(const std::string& url);
    bool scanDownload(const std::string& filePath, const std::string& sourceUrl);
    
    void blockConnection(const std::string& remoteAddress, uint16_t port);
    std::vector<ConnectionBlock> getRecentBlocks() const;
    
    NetworkProtectionStats getStatistics() const;
    void updateMaliciousDomains(const std::vector<std::string>& domains);
    
private:
    void loadMaliciousDomains();
    void loadMaliciousUrls();
    void initializeDownloadScanner();
    
    std::string extractDomain(const std::string& url);
    
    void monitoringLoop();
    void downloadScanLoop();
    
    void monitorActiveConnections();
    void processDownloadScan(const DownloadScanRequest& request);
    
    bool shouldBlockConnection(const std::string& remoteAddress, uint16_t port);
    bool shouldScanFileType(const std::string& extension);
    std::string getFileExtension(const std::string& filePath);
    
    void updateThreatIntelligence();
    void cleanupOldData();
    
private:
    mutable std::mutex m_mutex;
    bool m_initialized;
    bool m_enabled;
    bool m_running;
    
    CloudIntelligence* m_cloudIntelligence;
    
    std::thread m_monitoringThread;
    std::thread m_downloadScanThread;
    
    std::unordered_set<std::string> m_maliciousDomains;
    std::vector<std::string> m_maliciousUrlPatterns;
    
    std::queue<DownloadScanRequest> m_downloadScanQueue;
    mutable std::mutex m_downloadQueueMutex;
    std::condition_variable m_downloadQueueCondition;
    
    std::vector<ConnectionBlock> m_connectionBlocks;
    
    std::atomic<uint64_t> m_blockedConnections;
    std::atomic<uint64_t> m_scannedDownloads;
    
    DownloadScannerConfig m_downloadScannerConfig;
};
