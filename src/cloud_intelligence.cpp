#include "cloud_intelligence.h"
#include "logger.h"
#include "utils.h"
#include <wininet.h>
#include <wincrypt.h>
#include <thread>
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "crypt32.lib")

CloudIntelligence::CloudIntelligence() 
    : m_initialized(false)
    , m_updateInterval(3600) // 1 hour default
    , m_lastUpdate(0)
    , m_running(false) {
}

CloudIntelligence::~CloudIntelligence() {
    shutdown();
}

bool CloudIntelligence::initialize(const std::string& serverUrl, const std::string& apiKey) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Logger::log(Logger::Level::INFO, "Initializing cloud intelligence service");
    
    m_serverUrl = serverUrl;
    m_apiKey = apiKey;
    
    // Initialize WinINet
    m_hInternet = InternetOpenA("AntivirusCloudClient/1.0",
                               INTERNET_OPEN_TYPE_PRECONFIG,
                               NULL, NULL, 0);
    
    if (!m_hInternet) {
        Logger::log(Logger::Level::ERROR, "Failed to initialize internet connection");
        return false;
    }
    
    // Test connection
    if (!testConnection()) {
        Logger::log(Logger::Level::WARNING, "Could not connect to cloud service, operating in offline mode");
    }
    
    // Load cached threat intelligence
    loadCachedData();
    
    m_initialized = true;
    Logger::log(Logger::Level::INFO, "Cloud intelligence service initialized");
    
    return true;
}

void CloudIntelligence::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return;
    
    Logger::log(Logger::Level::INFO, "Shutting down cloud intelligence service");
    
    m_running = false;
    if (m_updateThread.joinable()) {
        m_updateThread.join();
    }
    
    // Save cached data
    saveCachedData();
    
    if (m_hInternet) {
        InternetCloseHandle(m_hInternet);
        m_hInternet = nullptr;
    }
    
    m_initialized = false;
}

bool CloudIntelligence::startUpdates() {
    if (!m_initialized || m_running) return false;
    
    m_running = true;
    m_updateThread = std::thread(&CloudIntelligence::updateLoop, this);
    
    Logger::log(Logger::Level::INFO, "Cloud intelligence update service started");
    return true;
}

ThreatVerdict CloudIntelligence::queryFileHash(const std::string& sha256Hash) {
    if (!m_initialized) {
        return ThreatVerdict::UNKNOWN;
    }
    
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_hashCache.find(sha256Hash);
        if (it != m_hashCache.end()) {
            // Check if cache entry is still valid (24 hours)
            auto now = std::chrono::system_clock::now();
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - it->second.timestamp);
            
            if (age.count() < 24) {
                Logger::log(Logger::Level::DEBUG, "Hash found in cache: " + sha256Hash);
                return it->second.verdict;
            } else {
                m_hashCache.erase(it);
            }
        }
    }
    
    // Query cloud service
    ThreatVerdict verdict = queryCloudService(sha256Hash);
    
    // Cache result
    if (verdict != ThreatVerdict::UNKNOWN) {
        std::lock_guard<std::mutex> lock(m_mutex);
        ThreatCacheEntry entry;
        entry.verdict = verdict;
        entry.timestamp = std::chrono::system_clock::now();
        m_hashCache[sha256Hash] = entry;
    }
    
    return verdict;
}

std::vector<ThreatIndicator> CloudIntelligence::getLatestIndicators() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_threatIndicators;
}

ReputationScore CloudIntelligence::getFileReputation(const std::string& filePath) {
    // Calculate file hash
    std::string hash = calculateFileHash(filePath);
    if (hash.empty()) {
        return ReputationScore::UNKNOWN;
    }
    
    ThreatVerdict verdict = queryFileHash(hash);
    
    switch (verdict) {
        case ThreatVerdict::MALICIOUS:
            return ReputationScore::MALICIOUS;
        case ThreatVerdict::SUSPICIOUS:
            return ReputationScore::SUSPICIOUS;
        case ThreatVerdict::CLEAN:
            return ReputationScore::TRUSTED;
        default:
            return ReputationScore::UNKNOWN;
    }
}

bool CloudIntelligence::reportThreat(const ThreatReport& report) {
    if (!m_initialized) return false;
    
    Logger::log(Logger::Level::INFO, "Reporting threat to cloud service: " + report.filePath);
    
    // Prepare JSON payload
    std::string json = createThreatReportJson(report);
    
    // Send to cloud service
    return sendHttpRequest("/api/threats/report", json, "POST");
}

bool CloudIntelligence::testConnection() {
    HINTERNET hConnect = InternetConnectA(m_hInternet,
                                         extractHostFromUrl(m_serverUrl).c_str(),
                                         INTERNET_DEFAULT_HTTPS_PORT,
                                         NULL, NULL,
                                         INTERNET_SERVICE_HTTP,
                                         0, 0);
    
    if (!hConnect) {
        return false;
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect,
                                         "GET",
                                         "/api/health",
                                         NULL,
                                         NULL,
                                         NULL,
                                         INTERNET_FLAG_SECURE,
                                         0);
    
    bool success = false;
    if (hRequest) {
        // Add API key header
        std::string authHeader = "Authorization: Bearer " + m_apiKey;
        HttpAddRequestHeadersA(hRequest, authHeader.c_str(), authHeader.length(), HTTP_ADDREQ_FLAG_ADD);
        
        if (HttpSendRequestA(hRequest, NULL, 0, NULL, 0)) {
            DWORD statusCode;
            DWORD statusCodeSize = sizeof(statusCode);
            
            if (HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                              &statusCode, &statusCodeSize, NULL)) {
                success = (statusCode == 200);
            }
        }
        
        InternetCloseHandle(hRequest);
    }
    
    InternetCloseHandle(hConnect);
    return success;
}

ThreatVerdict CloudIntelligence::queryCloudService(const std::string& hash) {
    std::string endpoint = "/api/threats/lookup/" + hash;
    std::string response;
    
    if (!sendHttpRequest(endpoint, "", "GET", &response)) {
        return ThreatVerdict::UNKNOWN;
    }
    
    // Parse JSON response
    return parseThreatVerdictFromJson(response);
}

bool CloudIntelligence::sendHttpRequest(const std::string& endpoint, 
                                       const std::string& data, 
                                       const std::string& method,
                                       std::string* response) {
    std::string host = extractHostFromUrl(m_serverUrl);
    
    HINTERNET hConnect = InternetConnectA(m_hInternet,
                                         host.c_str(),
                                         INTERNET_DEFAULT_HTTPS_PORT,
                                         NULL, NULL,
                                         INTERNET_SERVICE_HTTP,
                                         0, 0);
    
    if (!hConnect) {
        Logger::log(Logger::Level::ERROR, "Failed to connect to cloud service");
        return false;
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect,
                                         method.c_str(),
                                         endpoint.c_str(),
                                         NULL,
                                         NULL,
                                         NULL,
                                         INTERNET_FLAG_SECURE | INTERNET_FLAG_NO_CACHE_WRITE,
                                         0);
    
    bool success = false;
    if (hRequest) {
        // Add headers
        std::string authHeader = "Authorization: Bearer " + m_apiKey;
        HttpAddRequestHeadersA(hRequest, authHeader.c_str(), authHeader.length(), HTTP_ADDREQ_FLAG_ADD);
        
        if (!data.empty()) {
            std::string contentType = "Content-Type: application/json";
            HttpAddRequestHeadersA(hRequest, contentType.c_str(), contentType.length(), HTTP_ADDREQ_FLAG_ADD);
        }
        
        if (HttpSendRequestA(hRequest, NULL, 0, 
                            const_cast<char*>(data.c_str()), data.length())) {
            
            DWORD statusCode;
            DWORD statusCodeSize = sizeof(statusCode);
            
            if (HttpQueryInfoA(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                              &statusCode, &statusCodeSize, NULL)) {
                
                if (statusCode == 200 && response) {
                    // Read response body
                    char buffer[4096];
                    DWORD bytesRead;
                    
                    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
                        buffer[bytesRead] = '\0';
                        response->append(buffer);
                    }
                }
                
                success = (statusCode == 200);
            }
        }
        
        InternetCloseHandle(hRequest);
    }
    
    InternetCloseHandle(hConnect);
    
    if (!success) {
        Logger::log(Logger::Level::WARNING, "HTTP request failed: " + method + " " + endpoint);
    }
    
    return success;
}

std::string CloudIntelligence::calculateFileHash(const std::string& filePath) {
    HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return "";
    }
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;
    
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            
            BYTE buffer[4096];
            DWORD bytesRead;
            
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
                    break;
                }
            }
            
            DWORD hashSize = 32; // SHA-256
            BYTE hashBytes[32];
            
            if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashSize, 0)) {
                std::stringstream ss;
                for (DWORD i = 0; i < hashSize; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
                }
                result = ss.str();
            }
            
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    
    CloseHandle(hFile);
    return result;
}

void CloudIntelligence::updateLoop() {
    Logger::log(Logger::Level::INFO, "Cloud intelligence update loop started");
    
    while (m_running) {
        try {
            auto now = std::chrono::system_clock::now();
            auto timeSinceEpoch = now.time_since_epoch();
            auto currentTime = std::chrono::duration_cast<std::chrono::seconds>(timeSinceEpoch).count();
            
            if (currentTime - m_lastUpdate >= m_updateInterval) {
                Logger::log(Logger::Level::DEBUG, "Performing cloud intelligence update");
                
                if (updateThreatIndicators() && updateGlobalStatistics()) {
                    m_lastUpdate = currentTime;
                    Logger::log(Logger::Level::INFO, "Cloud intelligence update completed successfully");
                } else {
                    Logger::log(Logger::Level::WARNING, "Cloud intelligence update failed");
                }
            }
            
            // Sleep for 5 minutes between checks
            std::this_thread::sleep_for(std::chrono::minutes(5));
            
        } catch (const std::exception& e) {
            Logger::log(Logger::Level::ERROR, "Exception in cloud intelligence update loop: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::minutes(10));
        }
    }
    
    Logger::log(Logger::Level::INFO, "Cloud intelligence update loop stopped");
}

bool CloudIntelligence::updateThreatIndicators() {
    std::string response;
    if (!sendHttpRequest("/api/indicators/latest", "", "GET", &response)) {
        return false;
    }
    
    auto indicators = parseThreatIndicatorsFromJson(response);
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_threatIndicators = indicators;
    
    Logger::log(Logger::Level::INFO, "Updated " + std::to_string(indicators.size()) + " threat indicators");
    return true;
}

bool CloudIntelligence::updateGlobalStatistics() {
    std::string response;
    if (!sendHttpRequest("/api/statistics/global", "", "GET", &response)) {
        return false;
    }
    
    // Parse and store global statistics (implementation depends on JSON format)
    Logger::log(Logger::Level::DEBUG, "Global threat statistics updated");
    return true;
}

void CloudIntelligence::loadCachedData() {
    // Load cached threat intelligence from local storage
    std::string cachePath = Utils::getAppDataPath() + "\\ThreatCache.dat";
    
    HANDLE hFile = CreateFileA(cachePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize > 0 && fileSize < 100 * 1024 * 1024) { // Max 100MB cache
            std::vector<char> buffer(fileSize);
            DWORD bytesRead;
            
            if (ReadFile(hFile, buffer.data(), fileSize, &bytesRead, NULL)) {
                // Parse cached data (implementation depends on format)
                Logger::log(Logger::Level::DEBUG, "Loaded cached threat intelligence data");
            }
        }
        CloseHandle(hFile);
    }
}

void CloudIntelligence::saveCachedData() {
    // Save cached threat intelligence to local storage
    std::string cachePath = Utils::getAppDataPath() + "\\ThreatCache.dat";
    
    HANDLE hFile = CreateFileA(cachePath.c_str(), GENERIC_WRITE, 0,
                              NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        std::lock_guard<std::mutex> lock(m_mutex);
        
        // Serialize and save cache data (implementation depends on format)
        // For now, just create placeholder
        const char* placeholder = "CACHE_DATA_PLACEHOLDER";
        DWORD bytesWritten;
        WriteFile(hFile, placeholder, strlen(placeholder), &bytesWritten, NULL);
        
        CloseHandle(hFile);
        Logger::log(Logger::Level::DEBUG, "Saved cached threat intelligence data");
    }
}

std::string CloudIntelligence::extractHostFromUrl(const std::string& url) {
    size_t start = url.find("://");
    if (start != std::string::npos) {
        start += 3;
        size_t end = url.find("/", start);
        if (end == std::string::npos) end = url.length();
        return url.substr(start, end - start);
    }
    return url;
}

std::string CloudIntelligence::createThreatReportJson(const ThreatReport& report) {
    // Simple JSON creation (in production, use a proper JSON library)
    std::stringstream json;
    json << "{"
         << "\"file_path\":\"" << escapeJsonString(report.filePath) << "\","
         << "\"threat_name\":\"" << escapeJsonString(report.threatName) << "\","
         << "\"severity\":" << static_cast<int>(report.severity) << ","
         << "\"hash\":\"" << report.fileHash << "\","
         << "\"size\":" << report.fileSize << ","
         << "\"timestamp\":\"" << report.timestamp << "\""
         << "}";
    
    return json.str();
}

std::string CloudIntelligence::escapeJsonString(const std::string& str) {
    std::string result;
    for (char c : str) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c; break;
        }
    }
    return result;
}

ThreatVerdict CloudIntelligence::parseThreatVerdictFromJson(const std::string& json) {
    // Simple JSON parsing (in production, use a proper JSON library)
    if (json.find("\"verdict\":\"malicious\"") != std::string::npos) {
        return ThreatVerdict::MALICIOUS;
    } else if (json.find("\"verdict\":\"suspicious\"") != std::string::npos) {
        return ThreatVerdict::SUSPICIOUS;
    } else if (json.find("\"verdict\":\"clean\"") != std::string::npos) {
        return ThreatVerdict::CLEAN;
    }
    
    return ThreatVerdict::UNKNOWN;
}

std::vector<ThreatIndicator> CloudIntelligence::parseThreatIndicatorsFromJson(const std::string& json) {
    std::vector<ThreatIndicator> indicators;
    
    // Simple parsing implementation
    // In production, use a proper JSON library like nlohmann/json
    
    size_t pos = 0;
    while ((pos = json.find("\"hash\":", pos)) != std::string::npos) {
        ThreatIndicator indicator;
        
        // Extract hash
        size_t start = json.find("\"", pos + 7) + 1;
        size_t end = json.find("\"", start);
        if (end != std::string::npos) {
            indicator.hash = json.substr(start, end - start);
        }
        
        // Extract type
        pos = json.find("\"type\":", end);
        if (pos != std::string::npos) {
            start = json.find("\"", pos + 7) + 1;
            end = json.find("\"", start);
            if (end != std::string::npos) {
                std::string typeStr = json.substr(start, end - start);
                if (typeStr == "malware") indicator.type = ThreatIndicator::Type::MALWARE;
                else if (typeStr == "trojan") indicator.type = ThreatIndicator::Type::TROJAN;
                else if (typeStr == "virus") indicator.type = ThreatIndicator::Type::VIRUS;
                else if (typeStr == "ransomware") indicator.type = ThreatIndicator::Type::RANSOMWARE;
                else indicator.type = ThreatIndicator::Type::UNKNOWN;
            }
        }
        
        indicators.push_back(indicator);
        pos = end;
    }
    
    return indicators;
}
