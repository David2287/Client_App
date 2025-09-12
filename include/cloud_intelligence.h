#pragma once
#include <windows.h>
#include <wininet.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <thread>
#include <mutex>
#include <chrono>

// Forward declarations
enum class ThreatVerdict {
    UNKNOWN,
    CLEAN,
    SUSPICIOUS,
    MALICIOUS
};

enum class ReputationScore {
    UNKNOWN,
    TRUSTED,
    SUSPICIOUS,
    MALICIOUS
};

struct ThreatIndicator {
    enum class Type {
        UNKNOWN,
        MALWARE,
        TROJAN,
        VIRUS,
        RANSOMWARE
    };
    
    std::string hash;
    Type type;
    std::string description;
    std::chrono::system_clock::time_point timestamp;
};

struct ThreatReport {
    std::string filePath;
    std::string threatName;
    int severity;
    std::string fileHash;
    size_t fileSize;
    std::string timestamp;
};

struct ThreatCacheEntry {
    ThreatVerdict verdict;
    std::chrono::system_clock::time_point timestamp;
};

class CloudIntelligence {
public:
    CloudIntelligence();
    ~CloudIntelligence();
    
    bool initialize(const std::string& serverUrl, const std::string& apiKey);
    void shutdown();
    
    bool startUpdates();
    
    ThreatVerdict queryFileHash(const std::string& sha256Hash);
    std::vector<ThreatIndicator> getLatestIndicators();
    ReputationScore getFileReputation(const std::string& filePath);
    bool reportThreat(const ThreatReport& report);
    
private:
    bool testConnection();
    ThreatVerdict queryCloudService(const std::string& hash);
    
    bool sendHttpRequest(const std::string& endpoint, 
                        const std::string& data, 
                        const std::string& method,
                        std::string* response = nullptr);
    
    std::string calculateFileHash(const std::string& filePath);
    
    void updateLoop();
    bool updateThreatIndicators();
    bool updateGlobalStatistics();
    
    void loadCachedData();
    void saveCachedData();
    
    std::string extractHostFromUrl(const std::string& url);
    std::string createThreatReportJson(const ThreatReport& report);
    std::string escapeJsonString(const std::string& str);
    ThreatVerdict parseThreatVerdictFromJson(const std::string& json);
    std::vector<ThreatIndicator> parseThreatIndicatorsFromJson(const std::string& json);
    
private:
    mutable std::mutex m_mutex;
    bool m_initialized;
    std::string m_serverUrl;
    std::string m_apiKey;
    HINTERNET m_hInternet;
    
    std::thread m_updateThread;
    bool m_running;
    int m_updateInterval;  // seconds
    int64_t m_lastUpdate;
    
    std::unordered_map<std::string, ThreatCacheEntry> m_hashCache;
    std::vector<ThreatIndicator> m_threatIndicators;
};
