#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <unordered_set>
#include <mutex>

// Forward declarations
class ThreatEngine;
enum class ThreatLevel;

struct ArchiveEntry {
    std::string name;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint32_t crc32;
    bool encrypted;
    bool isDirectory;
    uint16_t compressionMethod;
    uint32_t localHeaderOffset;
};

struct ArchiveFileResult {
    std::string fileName;
    std::string filePath;
    uint32_t size;
    bool scanned;
    bool isThreat;
    ThreatLevel threatLevel;
    std::string threatName;
    std::string errorMessage;
};

struct ArchiveScanResult {
    std::string archivePath;
    bool scanned;
    bool nested;
    int nestingLevel;
    int filesExtracted;
    int threatsFound;
    uint64_t totalSize;
    std::string errorMessage;
    
    std::vector<ArchiveFileResult> fileResults;
    std::vector<ArchiveScanResult> nestedResults;
};

struct ArchiveScanStats {
    bool initialized;
    size_t supportedFormats;
    int maxNestingLevel;
    size_t maxExtractedSizeMB;
    std::string tempDirectory;
};

class ArchiveScanner {
public:
    ArchiveScanner();
    ~ArchiveScanner();
    
    bool initialize(ThreatEngine* threatEngine);
    void shutdown();
    
    ArchiveScanResult scanArchive(const std::string& archivePath);
    
    bool isArchiveFile(const std::string& filePath);
    bool isPasswordProtected(const std::string& archivePath);
    
    std::vector<ArchiveEntry> listArchiveContents(const std::string& archivePath);
    
    ArchiveScanStats getStatistics() const;
    void setMaxNestingLevel(int maxLevel);
    void setMaxExtractedSize(size_t maxSize);
    
private:
    ArchiveScanResult scanZipArchive(const std::string& zipPath, int nestingLevel);
    
    bool isZipArchive(const std::string& filePath);
    bool checkZipPasswordProtection(const std::string& zipPath);
    
    std::vector<ArchiveEntry> listZipContents(const std::string& zipPath);
    bool extractZipEntry(const std::string& zipPath, const ArchiveEntry& entry, const std::string& outputPath);
    
    std::string getFileExtension(const std::string& filePath);
    std::string sanitizeFileName(const std::string& fileName);
    
    void cleanupTempDirectory();
    
private:
    mutable std::mutex m_mutex;
    bool m_initialized;
    ThreatEngine* m_threatEngine;
    
    std::unordered_set<std::string> m_supportedExtensions;
    
    int m_maxNestingLevel;
    size_t m_maxExtractedSize;
    std::string m_tempDirectory;
};
