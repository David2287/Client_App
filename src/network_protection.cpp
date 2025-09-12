#include "network_protection.h"
#include "logger.h"
#include "cloud_intelligence.h"
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <thread>
#include <chrono>
#include <regex>
#include <fstream>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

NetworkProtection::NetworkProtection() 
    : m_initialized(false)
    , m_enabled(false)
    , m_running(false)
    , m_cloudIntelligence(nullptr)
    , m_blockedConnections(0)
    , m_scannedDownloads(0) {
}

NetworkProtection::~NetworkProtection() {
    shutdown();
}

bool NetworkProtection::initialize(CloudIntelligence* cloudIntelligence) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Logger::log(Logger::Level::INFO, "Initializing network protection");
    
    m_cloudIntelligence = cloudIntelligence;
    
    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        Logger::log(Logger::Level::ERROR, "Failed to initialize Winsock: " + std::to_string(result));
        return false;
    }
    
    // Load malicious domains and URLs
    loadMaliciousDomains();
    loadMaliciousUrls();
    
    // Initialize download scanner
    initializeDownloadScanner();
    
    m_initialized = true;
    Logger::log(Logger::Level::INFO, "Network protection initialized");
    
    return true;
}

void NetworkProtection::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return;
    
    Logger::log(Logger::Level::INFO, "Shutting down network protection");
    
    stop();
    
    // Cleanup Winsock
    WSACleanup();
    
    m_initialized = false;
}

bool NetworkProtection::start() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized || m_running) return false;
    
    Logger::log(Logger::Level::INFO, "Starting network protection service");
    
    m_running = true;
    m_enabled = true;
    
    // Start monitoring threads
    m_monitoringThread = std::thread(&NetworkProtection::monitoringLoop, this);
    m_downloadScanThread = std::thread(&NetworkProtection::downloadScanLoop, this);
    
    Logger::log(Logger::Level::INFO, "Network protection service started");
    return true;
}

void NetworkProtection::stop() {
    if (!m_running) return;
    
    Logger::log(Logger::Level::INFO, "Stopping network protection service");
    
    m_running = false;
    m_enabled = false;
    
    if (m_monitoringThread.joinable()) {
        m_monitoringThread.join();
    }
    
    if (m_downloadScanThread.joinable()) {
        m_downloadScanThread.join();
    }
    
    Logger::log(Logger::Level::INFO, "Network protection service stopped");
}

bool NetworkProtection::isUrlBlocked(const std::string& url) {
    if (!m_enabled) return false;
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Extract domain from URL
    std::string domain = extractDomain(url);
    
    // Check against malicious domains
    if (m_maliciousDomains.find(domain) != m_maliciousDomains.end()) {
        Logger::log(Logger::Level::WARNING, "Blocked malicious domain: " + domain);
        m_blockedConnections++;
        return true;
    }
    
    // Check against malicious URL patterns
    for (const auto& pattern : m_maliciousUrlPatterns) {
        try {
            std::regex regex(pattern, std::regex_constants::icase);
            if (std::regex_search(url, regex)) {
                Logger::log(Logger::Level::WARNING, "Blocked malicious URL pattern: " + url);
                m_blockedConnections++;
                return true;
            }
        } catch (const std::regex_error&) {
            // Invalid regex pattern, skip
            continue;
        }
    }
    
    // Check with cloud intelligence if available
    if (m_cloudIntelligence) {
        // For demonstration - in real implementation, you'd have URL reputation API
        // ReputationScore score = m_cloudIntelligence->getUrlReputation(url);
        // if (score == ReputationScore::MALICIOUS) {
        //     Logger::log(Logger::Level::WARNING, "Cloud service blocked URL: " + url);
        //     m_blockedConnections++;
        //     return true;
        // }
    }
    
    return false;
}

bool NetworkProtection::scanDownload(const std::string& filePath, const std::string& sourceUrl) {
    if (!m_enabled) return true; // Allow if protection disabled
    
    Logger::log(Logger::Level::DEBUG, "Scanning download: " + filePath);
    
    DownloadScanRequest request;
    request.filePath = filePath;
    request.sourceUrl = sourceUrl;
    request.timestamp = std::chrono::system_clock::now();
    
    {
        std::lock_guard<std::mutex> lock(m_downloadQueueMutex);
        m_downloadScanQueue.push(request);
    }
    m_downloadQueueCondition.notify_one();
    
    m_scannedDownloads++;
    return true;
}

void NetworkProtection::blockConnection(const std::string& remoteAddress, uint16_t port) {
    Logger::log(Logger::Level::WARNING, "Blocking connection to " + remoteAddress + ":" + std::to_string(port));
    
    // In a real implementation, this would integrate with Windows Firewall
    // or use a network filter driver to actually block the connection
    
    ConnectionBlock block;
    block.remoteAddress = remoteAddress;
    block.port = port;
    block.timestamp = std::chrono::system_clock::now();
    block.reason = "Malicious destination";
    
    std::lock_guard<std::mutex> lock(m_mutex);
    m_blockedConnections++;
    m_connectionBlocks.push_back(block);
    
    // Keep only recent blocks (last 1000)
    if (m_connectionBlocks.size() > 1000) {
        m_connectionBlocks.erase(m_connectionBlocks.begin(), 
                                m_connectionBlocks.begin() + 500);
    }
}

std::vector<ConnectionBlock> NetworkProtection::getRecentBlocks() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<ConnectionBlock> recent;
    auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24);
    
    for (const auto& block : m_connectionBlocks) {
        if (block.timestamp > cutoff) {
            recent.push_back(block);
        }
    }
    
    return recent;
}

NetworkProtectionStats NetworkProtection::getStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    NetworkProtectionStats stats;
    stats.enabled = m_enabled;
    stats.blockedConnections = m_blockedConnections;
    stats.scannedDownloads = m_scannedDownloads;
    stats.maliciousDomainsCount = m_maliciousDomains.size();
    stats.maliciousUrlPatternsCount = m_maliciousUrlPatterns.size();
    stats.recentBlocksCount = getRecentBlocks().size();
    
    return stats;
}

void NetworkProtection::updateMaliciousDomains(const std::vector<std::string>& domains) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& domain : domains) {
        m_maliciousDomains.insert(domain);
    }
    
    Logger::log(Logger::Level::INFO, "Updated malicious domains list: " + 
                std::to_string(domains.size()) + " new domains");
}

void NetworkProtection::loadMaliciousDomains() {
    std::string domainFile = "malicious_domains.txt";
    std::ifstream file(domainFile);
    
    if (!file.is_open()) {
        Logger::log(Logger::Level::WARNING, "Could not load malicious domains file");
        
        // Add some default malicious domains for demonstration
        m_maliciousDomains.insert("malware.example.com");
        m_maliciousDomains.insert("phishing.test");
        m_maliciousDomains.insert("trojan.bad");
        m_maliciousDomains.insert("ransomware.evil");
        
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') { // Skip empty lines and comments
            // Remove whitespace
            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);
            
            if (!line.empty()) {
                m_maliciousDomains.insert(line);
            }
        }
    }
    
    Logger::log(Logger::Level::INFO, "Loaded " + std::to_string(m_maliciousDomains.size()) + 
                " malicious domains");
}

void NetworkProtection::loadMaliciousUrls() {
    std::string urlFile = "malicious_urls.txt";
    std::ifstream file(urlFile);
    
    if (!file.is_open()) {
        Logger::log(Logger::Level::WARNING, "Could not load malicious URLs file");
        
        // Add some default malicious URL patterns
        m_maliciousUrlPatterns.push_back(".*\\.exe\\?download=.*");
        m_maliciousUrlPatterns.push_back(".*phishing.*");
        m_maliciousUrlPatterns.push_back(".*malware.*");
        m_maliciousUrlPatterns.push_back(".*\\.tk/.*\\.exe");
        m_maliciousUrlPatterns.push_back(".*\\.ml/.*\\.scr");
        
        return;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            line.erase(0, line.find_first_not_of(" \t"));
            line.erase(line.find_last_not_of(" \t") + 1);
            
            if (!line.empty()) {
                m_maliciousUrlPatterns.push_back(line);
            }
        }
    }
    
    Logger::log(Logger::Level::INFO, "Loaded " + std::to_string(m_maliciousUrlPatterns.size()) + 
                " malicious URL patterns");
}

void NetworkProtection::initializeDownloadScanner() {
    // Initialize download scanner configuration
    m_downloadScannerConfig.scanExecutables = true;
    m_downloadScannerConfig.scanArchives = true;
    m_downloadScannerConfig.scanDocuments = false;
    m_downloadScannerConfig.maxFileSizeKB = 100 * 1024; // 100MB
    m_downloadScannerConfig.quarantineMalicious = true;
    
    Logger::log(Logger::Level::DEBUG, "Download scanner initialized");
}

std::string NetworkProtection::extractDomain(const std::string& url) {
    // Simple domain extraction
    size_t start = url.find("://");
    if (start == std::string::npos) {
        start = 0;
    } else {
        start += 3;
    }
    
    size_t end = url.find("/", start);
    if (end == std::string::npos) {
        end = url.find("?", start);
        if (end == std::string::npos) {
            end = url.length();
        }
    }
    
    std::string domain = url.substr(start, end - start);
    
    // Remove port if present
    size_t portPos = domain.find(":");
    if (portPos != std::string::npos) {
        domain = domain.substr(0, portPos);
    }
    
    // Convert to lowercase
    std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
    
    return domain;
}

void NetworkProtection::monitoringLoop() {
    Logger::log(Logger::Level::INFO, "Network monitoring loop started");
    
    while (m_running) {
        try {
            // Monitor network connections
            monitorActiveConnections();
            
            // Update threat intelligence
            if (m_cloudIntelligence) {
                updateThreatIntelligence();
            }
            
            // Clean up old data
            cleanupOldData();
            
            // Sleep for monitoring interval
            std::this_thread::sleep_for(std::chrono::seconds(30));
            
        } catch (const std::exception& e) {
            Logger::log(Logger::Level::ERROR, "Exception in network monitoring loop: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::minutes(1));
        }
    }
    
    Logger::log(Logger::Level::INFO, "Network monitoring loop stopped");
}

void NetworkProtection::downloadScanLoop() {
    Logger::log(Logger::Level::INFO, "Download scan loop started");
    
    while (m_running) {
        try {
            std::unique_lock<std::mutex> lock(m_downloadQueueMutex);
            
            // Wait for download scan requests
            m_downloadQueueCondition.wait(lock, [this] {
                return !m_downloadScanQueue.empty() || !m_running;
            });
            
            if (!m_running) break;
            
            // Process scan request
            DownloadScanRequest request = m_downloadScanQueue.front();
            m_downloadScanQueue.pop();
            lock.unlock();
            
            // Perform the actual scan
            processDownloadScan(request);
            
        } catch (const std::exception& e) {
            Logger::log(Logger::Level::ERROR, "Exception in download scan loop: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    
    Logger::log(Logger::Level::INFO, "Download scan loop stopped");
}

void NetworkProtection::monitorActiveConnections() {
    // Get active TCP connections
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        return;
    }
    
    std::vector<BYTE> buffer(size);
    PMIB_TCPTABLE_OWNER_PID tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
    
    result = GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != NO_ERROR) {
        return;
    }
    
    // Check each connection
    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID& row = tcpTable->table[i];
        
        if (row.dwState == MIB_TCP_STATE_ESTAB) {
            // Convert remote address to string
            struct in_addr addr;
            addr.S_un.S_addr = row.dwRemoteAddr;
            char* remoteIp = inet_ntoa(addr);
            
            if (remoteIp) {
                std::string remoteAddress(remoteIp);
                uint16_t remotePort = ntohs((uint16_t)row.dwRemotePort);
                
                // Check if this connection should be blocked
                if (shouldBlockConnection(remoteAddress, remotePort)) {
                    // Log the connection attempt (actual blocking would require more complex implementation)
                    Logger::log(Logger::Level::WARNING, 
                               "Detected connection to suspicious address: " + 
                               remoteAddress + ":" + std::to_string(remotePort));
                }
            }
        }
    }
}

void NetworkProtection::processDownloadScan(const DownloadScanRequest& request) {
    Logger::log(Logger::Level::DEBUG, "Processing download scan: " + request.filePath);
    
    // Check if file exists
    DWORD attributes = GetFileAttributesA(request.filePath.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        Logger::log(Logger::Level::WARNING, "Downloaded file not found: " + request.filePath);
        return;
    }
    
    // Get file size
    HANDLE hFile = CreateFileA(request.filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        Logger::log(Logger::Level::WARNING, "Could not open downloaded file: " + request.filePath);
        return;
    }
    
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    CloseHandle(hFile);
    
    // Check file size limit
    if (fileSize.QuadPart > static_cast<LONGLONG>(m_downloadScannerConfig.maxFileSizeKB) * 1024) {
        Logger::log(Logger::Level::DEBUG, "Downloaded file too large for scanning: " + request.filePath);
        return;
    }
    
    // Check file extension
    std::string extension = getFileExtension(request.filePath);
    if (!shouldScanFileType(extension)) {
        Logger::log(Logger::Level::DEBUG, "Skipping scan for file type: " + extension);
        return;
    }
    
    // Perform virus scan (would integrate with main threat engine)
    // For now, just log the scan
    Logger::log(Logger::Level::INFO, "Scanned download: " + request.filePath + 
                " (size: " + std::to_string(fileSize.QuadPart) + " bytes)");
    
    // Check source URL reputation
    if (isUrlBlocked(request.sourceUrl)) {
        Logger::log(Logger::Level::WARNING, "Download from blocked URL detected: " + request.sourceUrl);
        
        if (m_downloadScannerConfig.quarantineMalicious) {
            // Move file to quarantine (would integrate with quarantine system)
            Logger::log(Logger::Level::WARNING, "Quarantining download from malicious source: " + request.filePath);
        }
    }
}

bool NetworkProtection::shouldBlockConnection(const std::string& remoteAddress, uint16_t port) {
    // Check against known malicious IPs
    // In a real implementation, this would check against threat intelligence feeds
    
    // For demonstration, block connections to private IP ranges that shouldn't be contacted externally
    // (this is just an example - in practice, you'd have sophisticated threat intelligence)
    
    if (remoteAddress.find("10.0.0.") == 0 || 
        remoteAddress.find("192.168.") == 0 ||
        remoteAddress.find("172.16.") == 0) {
        // These are private IPs, generally okay
        return false;
    }
    
    // Check against cloud intelligence
    if (m_cloudIntelligence) {
        // In a real implementation, you'd check IP reputation
        // ReputationScore score = m_cloudIntelligence->getIpReputation(remoteAddress);
        // return (score == ReputationScore::MALICIOUS);
    }
    
    return false;
}

bool NetworkProtection::shouldScanFileType(const std::string& extension) {
    std::string lowerExt = extension;
    std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::tolower);
    
    // Executable files
    if (m_downloadScannerConfig.scanExecutables) {
        if (lowerExt == ".exe" || lowerExt == ".dll" || lowerExt == ".scr" ||
            lowerExt == ".com" || lowerExt == ".bat" || lowerExt == ".cmd" ||
            lowerExt == ".pif" || lowerExt == ".vbs" || lowerExt == ".js") {
            return true;
        }
    }
    
    // Archive files
    if (m_downloadScannerConfig.scanArchives) {
        if (lowerExt == ".zip" || lowerExt == ".rar" || lowerExt == ".7z" ||
            lowerExt == ".tar" || lowerExt == ".gz" || lowerExt == ".bz2") {
            return true;
        }
    }
    
    // Document files
    if (m_downloadScannerConfig.scanDocuments) {
        if (lowerExt == ".doc" || lowerExt == ".docx" || lowerExt == ".xls" ||
            lowerExt == ".xlsx" || lowerExt == ".ppt" || lowerExt == ".pptx" ||
            lowerExt == ".pdf" || lowerExt == ".rtf") {
            return true;
        }
    }
    
    return false;
}

std::string NetworkProtection::getFileExtension(const std::string& filePath) {
    size_t dotPos = filePath.find_last_of('.');
    if (dotPos == std::string::npos) {
        return "";
    }
    return filePath.substr(dotPos);
}

void NetworkProtection::updateThreatIntelligence() {
    // Update malicious domains and URLs from cloud intelligence
    auto indicators = m_cloudIntelligence->getLatestIndicators();
    
    std::vector<std::string> newDomains;
    for (const auto& indicator : indicators) {
        // Extract domains from indicators (implementation depends on indicator format)
        // For now, just log that we're updating
    }
    
    if (!newDomains.empty()) {
        updateMaliciousDomains(newDomains);
    }
}

void NetworkProtection::cleanupOldData() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Remove old connection blocks (older than 7 days)
    auto cutoff = std::chrono::system_clock::now() - std::chrono::hours(24 * 7);
    
    m_connectionBlocks.erase(
        std::remove_if(m_connectionBlocks.begin(), m_connectionBlocks.end(),
                      [cutoff](const ConnectionBlock& block) {
                          return block.timestamp < cutoff;
                      }),
        m_connectionBlocks.end()
    );
}
