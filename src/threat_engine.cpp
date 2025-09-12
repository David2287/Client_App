#include "threat_engine.h"
#include "logger.h"
#include "utils.h"
#include <fstream>
#include <algorithm>
#include <regex>
#include <filesystem>
#include <map>
#include <thread>
#include <chrono>

ThreatEngine::ThreatEngine(Logger* logger)
    : m_logger(logger)
    , m_initialized(false)
    , m_databaseVersion(0)
    , m_signatureCount(0)
    , m_heuristicsEnabled(true)
    , m_cloudEnabled(false) {
}

ThreatEngine::~ThreatEngine() {
    Shutdown();
}

bool ThreatEngine::Initialize() {
    if (m_initialized) {
        return true;
    }

    if (m_logger) {
        m_logger->Info(L"Initializing Threat Engine...");
    }

    try {
        // Create database directory
        m_databasePath = L"C:\\ProgramData\\AntivirusService\\Database";
        std::filesystem::create_directories(m_databasePath);

        // Initialize signature database
        if (!LoadSignatureDatabase()) {
            if (m_logger) {
                m_logger->Warning(L"No signature database found, creating default");
            }
            CreateDefaultDatabase();
        }

        // Initialize quarantine system
        m_quarantinePath = L"C:\\ProgramData\\AntivirusService\\Quarantine";
        std::filesystem::create_directories(m_quarantinePath);

        // Initialize heuristics engine
        InitializeHeuristicsEngine();

        m_initialized = true;
        
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Info, L"Threat Engine initialized successfully. Signatures: %d, Version: %d", 
                               m_signatureCount, m_databaseVersion);
        }

        return true;
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Failed to initialize Threat Engine: %S", e.what());
        }
        return false;
    }
}

void ThreatEngine::Shutdown() {
    if (!m_initialized) {
        return;
    }

    if (m_logger) {
        m_logger->Info(L"Shutting down Threat Engine...");
    }

    m_signatures.clear();
    m_fileTypeSignatures.clear();
    m_heuristicRules.clear();
    m_initialized = false;

    if (m_logger) {
        m_logger->Info(L"Threat Engine shutdown complete");
    }
}

bool ThreatEngine::ScanFile(const std::wstring& filePath, ThreatInfo& threat) {
    if (!m_initialized) {
        return false;
    }

    try {
        // Check if file exists and is accessible
        if (!Utils::FileExists(filePath)) {
            return false;
        }

        uint64_t fileSize = Utils::GetFileSize(filePath);
        if (fileSize == 0) {
            return false; // Empty file, no threat
        }

        // Skip very large files to avoid performance issues
        const uint64_t MAX_SCAN_SIZE = 100 * 1024 * 1024; // 100MB
        if (fileSize > MAX_SCAN_SIZE) {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Info, L"Skipping large file: %s (Size: %llu bytes)", 
                                   filePath.c_str(), fileSize);
            }
            return false;
        }

        // Open file for reading
        std::ifstream file(filePath, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Read file content
        std::vector<char> buffer(static_cast<size_t>(fileSize));
        file.read(buffer.data(), fileSize);
        file.close();

        // Perform signature-based scan
        if (ScanWithSignatures(buffer, threat)) {
            threat.file_path = filePath;
            threat.file_size = fileSize;
            
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Warning, L"Threat detected: %s in file %s", 
                                   threat.threat_name.c_str(), filePath.c_str());
            }
            return true;
        }

        // Perform heuristic analysis
        if (m_heuristicsEnabled && ScanWithHeuristics(buffer, filePath, threat)) {
            threat.file_path = filePath;
            threat.file_size = fileSize;
            
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Warning, L"Heuristic threat detected: %s in file %s", 
                                   threat.threat_name.c_str(), filePath.c_str());
            }
            return true;
        }

        return false; // No threat found
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Error scanning file %s: %S", 
                               filePath.c_str(), e.what());
        }
        return false;
    }
}

bool ThreatEngine::ScanDirectory(const std::wstring& dirPath, std::vector<ThreatInfo>& threats) {
    if (!m_initialized) {
        return false;
    }

    try {
        if (!Utils::DirectoryExists(dirPath)) {
            return false;
        }

        if (m_logger) {
            m_logger->LogFormat(LogLevel::Info, L"Scanning directory: %s", dirPath.c_str());
        }

        size_t initialThreats = threats.size();
        
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                ThreatInfo threat;
                if (ScanFile(entry.path().wstring(), threat)) {
                    threats.push_back(threat);
                }
            }
        }

        size_t threatsFound = threats.size() - initialThreats;
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Info, L"Directory scan complete. Threats found: %zu", threatsFound);
        }

        return true;
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Error scanning directory %s: %S", 
                               dirPath.c_str(), e.what());
        }
        return false;
    }
}

bool ThreatEngine::QuarantineFile(const std::wstring& filePath, const std::wstring& threatName) {
    if (!m_initialized) {
        return false;
    }

    try {
        if (!Utils::FileExists(filePath)) {
            return false;
        }

        // Generate unique quarantine filename
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        
        std::wstring fileName = std::filesystem::path(filePath).filename();
        std::wstring quarantineFile = m_quarantinePath + L"\\" + std::to_wstring(timestamp) + L"_" + fileName;

        // Move file to quarantine
        if (MoveFile(filePath.c_str(), quarantineFile.c_str())) {
            // Store quarantine metadata
            QuarantineEntry entry;
            entry.originalPath = filePath;
            entry.quarantinePath = quarantineFile;
            entry.threatName = threatName;
            entry.quarantineTime = timestamp;
            
            m_quarantineEntries.push_back(entry);
            SaveQuarantineMetadata();

            if (m_logger) {
                m_logger->LogFormat(LogLevel::Info, L"File quarantined: %s -> %s (Threat: %s)", 
                                   filePath.c_str(), quarantineFile.c_str(), threatName.c_str());
            }
            return true;
        }
        else {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Error, L"Failed to quarantine file: %s", filePath.c_str());
            }
            return false;
        }
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Error quarantining file %s: %S", 
                               filePath.c_str(), e.what());
        }
        return false;
    }
}

bool ThreatEngine::RestoreFromQuarantine(const std::wstring& quarantinePath) {
    auto it = std::find_if(m_quarantineEntries.begin(), m_quarantineEntries.end(),
        [&quarantinePath](const QuarantineEntry& entry) {
            return entry.quarantinePath == quarantinePath;
        });

    if (it != m_quarantineEntries.end()) {
        if (MoveFile(it->quarantinePath.c_str(), it->originalPath.c_str())) {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Info, L"File restored from quarantine: %s -> %s", 
                                   it->quarantinePath.c_str(), it->originalPath.c_str());
            }
            m_quarantineEntries.erase(it);
            SaveQuarantineMetadata();
            return true;
        }
    }

    return false;
}

bool ThreatEngine::UpdateDatabase() {
    if (m_logger) {
        m_logger->Info(L"Updating threat database...");
    }

    // TODO: Implement actual database update from server
    // For now, increment version to simulate update
    m_databaseVersion++;
    
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Database updated to version %d", m_databaseVersion);
    }

    return true;
}

uint32_t ThreatEngine::GetDatabaseVersion() const {
    return m_databaseVersion;
}

bool ThreatEngine::LoadSignatureDatabase() {
    std::wstring dbFile = m_databasePath + L"\\signatures.db";
    std::ifstream file(dbFile, std::ios::binary);
    
    if (!file.is_open()) {
        return false;
    }

    try {
        // Read database header
        uint32_t magic, version, count;
        file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        file.read(reinterpret_cast<char*>(&version), sizeof(version));
        file.read(reinterpret_cast<char*>(&count), sizeof(count));

        if (magic != 0x53494753) { // 'SIGS'
            return false;
        }

        m_databaseVersion = version;
        m_signatures.clear();

        // Read signatures
        for (uint32_t i = 0; i < count; ++i) {
            VirusSignature sig;
            
            uint32_t nameLen, sigLen;
            file.read(reinterpret_cast<char*>(&nameLen), sizeof(nameLen));
            
            sig.name.resize(nameLen);
            file.read(reinterpret_cast<char*>(sig.name.data()), nameLen * sizeof(wchar_t));
            
            file.read(reinterpret_cast<char*>(&sig.severity), sizeof(sig.severity));
            file.read(reinterpret_cast<char*>(&sigLen), sizeof(sigLen));
            
            sig.signature.resize(sigLen);
            file.read(sig.signature.data(), sigLen);
            
            file.read(reinterpret_cast<char*>(&sig.offset), sizeof(sig.offset));

            m_signatures.push_back(sig);
        }

        m_signatureCount = static_cast<uint32_t>(m_signatures.size());
        return true;
    }
    catch (...) {
        return false;
    }
}

void ThreatEngine::CreateDefaultDatabase() {
    // Create some basic signatures for common malware patterns
    m_signatures.clear();
    
    // PE executable signatures
    VirusSignature peSignature;
    peSignature.name = L"PE.Suspicious.Header";
    peSignature.signature = {'M', 'Z'};  // MZ header
    peSignature.severity = 3;
    peSignature.offset = 0;
    m_signatures.push_back(peSignature);

    // Script-based threats
    VirusSignature scriptSignature;
    scriptSignature.name = L"Script.Suspicious.PowerShell";
    std::string psPattern = "powershell";
    scriptSignature.signature.assign(psPattern.begin(), psPattern.end());
    scriptSignature.severity = 5;
    scriptSignature.offset = -1; // Search anywhere
    m_signatures.push_back(scriptSignature);

    // Ransomware patterns
    VirusSignature ransomwareSignature;
    ransomwareSignature.name = L"Ransomware.Generic.Extension";
    std::string ransomPattern = ".locked";
    ransomwareSignature.signature.assign(ransomPattern.begin(), ransomPattern.end());
    ransomwareSignature.severity = 10;
    ransomwareSignature.offset = -1;
    m_signatures.push_back(ransomwareSignature);

    m_signatureCount = static_cast<uint32_t>(m_signatures.size());
    m_databaseVersion = 1;

    // Save default database
    SaveSignatureDatabase();
}

bool ThreatEngine::SaveSignatureDatabase() {
    std::wstring dbFile = m_databasePath + L"\\signatures.db";
    std::ofstream file(dbFile, std::ios::binary);
    
    if (!file.is_open()) {
        return false;
    }

    try {
        // Write header
        uint32_t magic = 0x53494753; // 'SIGS'
        file.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
        file.write(reinterpret_cast<const char*>(&m_databaseVersion), sizeof(m_databaseVersion));
        file.write(reinterpret_cast<const char*>(&m_signatureCount), sizeof(m_signatureCount));

        // Write signatures
        for (const auto& sig : m_signatures) {
            uint32_t nameLen = static_cast<uint32_t>(sig.name.length());
            uint32_t sigLen = static_cast<uint32_t>(sig.signature.size());
            
            file.write(reinterpret_cast<const char*>(&nameLen), sizeof(nameLen));
            file.write(reinterpret_cast<const char*>(sig.name.data()), nameLen * sizeof(wchar_t));
            file.write(reinterpret_cast<const char*>(&sig.severity), sizeof(sig.severity));
            file.write(reinterpret_cast<const char*>(&sigLen), sizeof(sigLen));
            file.write(sig.signature.data(), sigLen);
            file.write(reinterpret_cast<const char*>(&sig.offset), sizeof(sig.offset));
        }

        return true;
    }
    catch (...) {
        return false;
    }
}

bool ThreatEngine::ScanWithSignatures(const std::vector<char>& data, ThreatInfo& threat) {
    for (const auto& signature : m_signatures) {
        if (signature.signature.empty()) {
            continue;
        }

        if (signature.offset >= 0) {
            // Fixed offset signature
            if (static_cast<size_t>(signature.offset) + signature.signature.size() <= data.size()) {
                if (std::equal(signature.signature.begin(), signature.signature.end(),
                              data.begin() + signature.offset)) {
                    threat.threat_name = signature.name;
                    threat.threat_level = signature.severity;
                    return true;
                }
            }
        }
        else {
            // Search anywhere in file
            auto it = std::search(data.begin(), data.end(),
                                 signature.signature.begin(), signature.signature.end());
            if (it != data.end()) {
                threat.threat_name = signature.name;
                threat.threat_level = signature.severity;
                return true;
            }
        }
    }

    return false;
}

void ThreatEngine::InitializeHeuristicsEngine() {
    // Initialize heuristic rules
    m_heuristicRules.clear();

    // Rule 1: Suspicious file size (very small executables)
    HeuristicRule rule1;
    rule1.name = L"Heuristic.Suspicious.TinyExecutable";
    rule1.severity = 6;
    rule1.description = L"Executable file with suspiciously small size";
    m_heuristicRules.push_back(rule1);

    // Rule 2: High entropy (possibly packed/encrypted)
    HeuristicRule rule2;
    rule2.name = L"Heuristic.Suspicious.HighEntropy";
    rule2.severity = 7;
    rule2.description = L"File content has high entropy, possibly packed or encrypted";
    m_heuristicRules.push_back(rule2);

    // Rule 3: Suspicious string patterns
    HeuristicRule rule3;
    rule3.name = L"Heuristic.Suspicious.Strings";
    rule3.severity = 5;
    rule3.description = L"Contains suspicious strings or API calls";
    m_heuristicRules.push_back(rule3);
}

bool ThreatEngine::ScanWithHeuristics(const std::vector<char>& data, const std::wstring& filePath, ThreatInfo& threat) {
    auto ext = std::filesystem::path(filePath).extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    // Check for executable files
    bool isExecutable = (ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".com");

    // Rule 1: Tiny executable check
    if (isExecutable && data.size() < 1024) {
        threat.threat_name = L"Heuristic.Suspicious.TinyExecutable";
        threat.threat_level = 6;
        return true;
    }

    // Rule 2: High entropy check (simplified)
    if (CalculateEntropy(data) > 7.5) {
        threat.threat_name = L"Heuristic.Suspicious.HighEntropy";
        threat.threat_level = 7;
        return true;
    }

    // Rule 3: Suspicious strings check
    if (ContainsSuspiciousStrings(data)) {
        threat.threat_name = L"Heuristic.Suspicious.Strings";
        threat.threat_level = 5;
        return true;
    }

    return false;
}

double ThreatEngine::CalculateEntropy(const std::vector<char>& data) {
    if (data.empty()) {
        return 0.0;
    }

    std::map<char, int> frequency;
    for (char byte : data) {
        frequency[byte]++;
    }

    double entropy = 0.0;
    double dataSize = static_cast<double>(data.size());

    for (const auto& pair : frequency) {
        double probability = static_cast<double>(pair.second) / dataSize;
        if (probability > 0) {
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

bool ThreatEngine::ContainsSuspiciousStrings(const std::vector<char>& data) {
    // Convert to string for pattern matching
    std::string content(data.begin(), data.end());
    std::transform(content.begin(), content.end(), content.begin(), ::tolower);

    // List of suspicious strings
    std::vector<std::string> suspiciousStrings = {
        "cryptolocker",
        "ransomware",
        "bitcoin",
        "your files have been encrypted",
        "pay the ransom",
        "keylogger",
        "password stealer",
        "backdoor",
        "trojan"
    };

    for (const auto& suspicious : suspiciousStrings) {
        if (content.find(suspicious) != std::string::npos) {
            return true;
        }
    }

    return false;
}

void ThreatEngine::SaveQuarantineMetadata() {
    std::wstring metadataFile = m_quarantinePath + L"\\metadata.dat";
    std::ofstream file(metadataFile, std::ios::binary);
    
    if (file.is_open()) {
        uint32_t count = static_cast<uint32_t>(m_quarantineEntries.size());
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));

        for (const auto& entry : m_quarantineEntries) {
            // Save strings with length prefix
            uint32_t len = static_cast<uint32_t>(entry.originalPath.length());
            file.write(reinterpret_cast<const char*>(&len), sizeof(len));
            file.write(reinterpret_cast<const char*>(entry.originalPath.data()), len * sizeof(wchar_t));

            len = static_cast<uint32_t>(entry.quarantinePath.length());
            file.write(reinterpret_cast<const char*>(&len), sizeof(len));
            file.write(reinterpret_cast<const char*>(entry.quarantinePath.data()), len * sizeof(wchar_t));

            len = static_cast<uint32_t>(entry.threatName.length());
            file.write(reinterpret_cast<const char*>(&len), sizeof(len));
            file.write(reinterpret_cast<const char*>(entry.threatName.data()), len * sizeof(wchar_t));

            file.write(reinterpret_cast<const char*>(&entry.quarantineTime), sizeof(entry.quarantineTime));
        }
    }
}
