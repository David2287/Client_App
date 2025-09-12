#pragma once

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <atomic>

class Logger;

struct ThreatInfo {
    std::wstring file_path;
    std::wstring threat_name;
    uint32_t threat_level;
    uint64_t file_size;
};

struct VirusSignature {
    std::wstring name;
    std::vector<char> signature;
    uint32_t severity;
    int32_t offset; // -1 for anywhere, >= 0 for fixed offset
};

struct HeuristicRule {
    std::wstring name;
    std::wstring description;
    uint32_t severity;
};

struct QuarantineEntry {
    std::wstring originalPath;
    std::wstring quarantinePath;
    std::wstring threatName;
    uint64_t quarantineTime;
};

class ThreatEngine {
public:
    ThreatEngine(Logger* logger);
    ~ThreatEngine();

    bool Initialize();
    void Shutdown();

    // Scanning
    bool ScanFile(const std::wstring& filePath, ThreatInfo& threat);
    bool ScanDirectory(const std::wstring& dirPath, std::vector<ThreatInfo>& threats);
    
    // Quarantine system
    bool QuarantineFile(const std::wstring& filePath, const std::wstring& threatName);
    bool RestoreFromQuarantine(const std::wstring& quarantinePath);
    const std::vector<QuarantineEntry>& GetQuarantineEntries() const { return m_quarantineEntries; }
    
    // Database
    bool UpdateDatabase();
    uint32_t GetDatabaseVersion() const;
    uint32_t GetSignatureCount() const { return m_signatureCount; }
    
    // Configuration
    void EnableHeuristics(bool enable) { m_heuristicsEnabled = enable; }
    bool IsHeuristicsEnabled() const { return m_heuristicsEnabled; }
    
private:
    Logger* m_logger;
    bool m_initialized;
    uint32_t m_databaseVersion;
    uint32_t m_signatureCount;
    std::atomic<bool> m_heuristicsEnabled;
    std::atomic<bool> m_cloudEnabled;
    
    // Paths
    std::wstring m_databasePath;
    std::wstring m_quarantinePath;
    
    // Signature data
    std::vector<VirusSignature> m_signatures;
    std::map<std::wstring, std::vector<VirusSignature>> m_fileTypeSignatures;
    std::vector<HeuristicRule> m_heuristicRules;
    std::vector<QuarantineEntry> m_quarantineEntries;
    
    // Database methods
    bool LoadSignatureDatabase();
    bool SaveSignatureDatabase();
    void CreateDefaultDatabase();
    
    // Scanning methods
    bool ScanWithSignatures(const std::vector<char>& data, ThreatInfo& threat);
    bool ScanWithHeuristics(const std::vector<char>& data, const std::wstring& filePath, ThreatInfo& threat);
    
    // Heuristics methods
    void InitializeHeuristicsEngine();
    double CalculateEntropy(const std::vector<char>& data);
    bool ContainsSuspiciousStrings(const std::vector<char>& data);
    
    // Quarantine methods
    void SaveQuarantineMetadata();
    void LoadQuarantineMetadata();
};
