#include "archive_scanner.h"
#include "logger.h"
#include "threat_engine.h"
#include <windows.h>
#include <shlwapi.h>
#include <vector>
#include <fstream>
#include <memory>
#include <algorithm>

#pragma comment(lib, "shlwapi.lib")

// Simple ZIP file format structures
#pragma pack(push, 1)
struct ZipLocalFileHeader {
    uint32_t signature;          // 0x04034b50
    uint16_t version;
    uint16_t flags;
    uint16_t compression;
    uint16_t modTime;
    uint16_t modDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t fileNameLength;
    uint16_t extraFieldLength;
};

struct ZipCentralDirEntry {
    uint32_t signature;          // 0x02014b50
    uint16_t versionMadeBy;
    uint16_t versionNeeded;
    uint16_t flags;
    uint16_t compression;
    uint16_t modTime;
    uint16_t modDate;
    uint32_t crc32;
    uint32_t compressedSize;
    uint32_t uncompressedSize;
    uint16_t fileNameLength;
    uint16_t extraFieldLength;
    uint16_t commentLength;
    uint16_t diskNumber;
    uint16_t internalAttributes;
    uint32_t externalAttributes;
    uint32_t localHeaderOffset;
};

struct ZipEndOfCentralDir {
    uint32_t signature;          // 0x06054b50
    uint16_t diskNumber;
    uint16_t centralDirDisk;
    uint16_t centralDirEntries;
    uint16_t totalEntries;
    uint32_t centralDirSize;
    uint32_t centralDirOffset;
    uint16_t commentLength;
};
#pragma pack(pop)

ArchiveScanner::ArchiveScanner() 
    : m_initialized(false)
    , m_threatEngine(nullptr)
    , m_maxNestingLevel(5)
    , m_maxExtractedSize(100 * 1024 * 1024) // 100MB
    , m_tempDirectory("") {
}

ArchiveScanner::~ArchiveScanner() {
    shutdown();
}

bool ArchiveScanner::initialize(ThreatEngine* threatEngine) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Logger::log(Logger::Level::INFO, "Initializing archive scanner");
    
    m_threatEngine = threatEngine;
    
    // Create temporary directory for extraction
    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    
    m_tempDirectory = std::string(tempPath) + "AntivirusArchiveTemp\\";
    
    if (!CreateDirectoryA(m_tempDirectory.c_str(), nullptr)) {
        DWORD error = GetLastError();
        if (error != ERROR_ALREADY_EXISTS) {
            Logger::log(Logger::Level::ERROR, "Failed to create temp directory: " + std::to_string(error));
            return false;
        }
    }
    
    // Initialize supported formats
    m_supportedExtensions.insert(".zip");
    m_supportedExtensions.insert(".jar");
    m_supportedExtensions.insert(".war");
    m_supportedExtensions.insert(".ear");
    // Note: RAR and 7Z would require external libraries in full implementation
    
    m_initialized = true;
    Logger::log(Logger::Level::INFO, "Archive scanner initialized");
    
    return true;
}

void ArchiveScanner::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return;
    
    Logger::log(Logger::Level::INFO, "Shutting down archive scanner");
    
    // Clean up temporary directory
    cleanupTempDirectory();
    
    m_initialized = false;
}

ArchiveScanResult ArchiveScanner::scanArchive(const std::string& archivePath) {
    if (!m_initialized || !m_threatEngine) {
        ArchiveScanResult result;
        result.scanned = false;
        result.errorMessage = "Archive scanner not initialized";
        return result;
    }
    
    Logger::log(Logger::Level::DEBUG, "Scanning archive: " + archivePath);
    
    ArchiveScanResult result;
    result.archivePath = archivePath;
    result.scanned = true;
    result.nested = false;
    result.nestingLevel = 0;
    result.filesExtracted = 0;
    result.threatsFound = 0;
    result.totalSize = 0;
    
    try {
        if (isZipArchive(archivePath)) {
            result = scanZipArchive(archivePath, 0);
        } else {
            result.scanned = false;
            result.errorMessage = "Unsupported archive format";
        }
    } catch (const std::exception& e) {
        result.scanned = false;
        result.errorMessage = "Exception during scan: " + std::string(e.what());
        Logger::log(Logger::Level::ERROR, "Archive scan exception: " + std::string(e.what()));
    }
    
    return result;
}

bool ArchiveScanner::isArchiveFile(const std::string& filePath) {
    std::string extension = getFileExtension(filePath);
    std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
    
    return m_supportedExtensions.find(extension) != m_supportedExtensions.end();
}

bool ArchiveScanner::isPasswordProtected(const std::string& archivePath) {
    if (isZipArchive(archivePath)) {
        return checkZipPasswordProtection(archivePath);
    }
    
    return false;
}

std::vector<ArchiveEntry> ArchiveScanner::listArchiveContents(const std::string& archivePath) {
    std::vector<ArchiveEntry> entries;
    
    if (!m_initialized) {
        Logger::log(Logger::Level::ERROR, "Archive scanner not initialized");
        return entries;
    }
    
    if (isZipArchive(archivePath)) {
        entries = listZipContents(archivePath);
    }
    
    return entries;
}

ArchiveScanResult ArchiveScanner::scanZipArchive(const std::string& zipPath, int nestingLevel) {
    ArchiveScanResult result;
    result.archivePath = zipPath;
    result.scanned = true;
    result.nested = (nestingLevel > 0);
    result.nestingLevel = nestingLevel;
    result.filesExtracted = 0;
    result.threatsFound = 0;
    result.totalSize = 0;
    
    if (nestingLevel >= m_maxNestingLevel) {
        result.scanned = false;
        result.errorMessage = "Maximum nesting level exceeded";
        return result;
    }
    
    // Create extraction directory for this archive
    std::string extractPath = m_tempDirectory + "extract_" + std::to_string(GetTickCount64()) + "\\";
    
    if (!CreateDirectoryA(extractPath.c_str(), nullptr)) {
        result.scanned = false;
        result.errorMessage = "Failed to create extraction directory";
        return result;
    }
    
    try {
        // Extract and scan ZIP contents
        std::vector<ArchiveEntry> entries = listZipContents(zipPath);
        
        for (const auto& entry : entries) {
            if (result.totalSize > m_maxExtractedSize) {
                Logger::log(Logger::Level::WARNING, "Archive extraction size limit reached");
                break;
            }
            
            if (entry.isDirectory) {
                continue;
            }
            
            // Extract file
            std::string extractedPath = extractPath + sanitizeFileName(entry.name);
            
            if (extractZipEntry(zipPath, entry, extractedPath)) {
                result.filesExtracted++;
                result.totalSize += entry.uncompressedSize;
                
                // Scan extracted file
                ScanResult scanResult = m_threatEngine->scanFile(extractedPath);
                
                ArchiveFileResult fileResult;
                fileResult.fileName = entry.name;
                fileResult.filePath = extractedPath;
                fileResult.size = entry.uncompressedSize;
                fileResult.scanned = true;
                fileResult.threatLevel = scanResult.threat_level;
                fileResult.threatName = scanResult.threat_name;
                
                if (scanResult.threat_level >= ThreatLevel::MEDIUM) {
                    result.threatsFound++;
                    fileResult.isThreat = true;
                    
                    Logger::log(Logger::Level::WARNING, "Threat found in archive: " + 
                               zipPath + " -> " + entry.name + " (" + scanResult.threat_name + ")");
                } else {
                    fileResult.isThreat = false;
                }
                
                result.fileResults.push_back(fileResult);
                
                // Check if extracted file is also an archive (nested scanning)
                if (isArchiveFile(extractedPath) && nestingLevel < m_maxNestingLevel) {
                    Logger::log(Logger::Level::DEBUG, "Nested archive found: " + entry.name);
                    
                    ArchiveScanResult nestedResult = scanZipArchive(extractedPath, nestingLevel + 1);
                    if (nestedResult.scanned) {
                        result.nestedResults.push_back(nestedResult);
                        result.threatsFound += nestedResult.threatsFound;
                        result.filesExtracted += nestedResult.filesExtracted;
                        result.totalSize += nestedResult.totalSize;
                    }
                }
                
                // Clean up extracted file
                DeleteFileA(extractedPath.c_str());
            } else {
                ArchiveFileResult fileResult;
                fileResult.fileName = entry.name;
                fileResult.size = entry.uncompressedSize;
                fileResult.scanned = false;
                fileResult.errorMessage = "Failed to extract";
                result.fileResults.push_back(fileResult);
            }
        }
        
    } catch (const std::exception& e) {
        result.errorMessage = "Exception during ZIP scan: " + std::string(e.what());
        Logger::log(Logger::Level::ERROR, result.errorMessage);
    }
    
    // Clean up extraction directory
    RemoveDirectoryA(extractPath.c_str());
    
    Logger::log(Logger::Level::INFO, "Archive scan completed: " + zipPath + 
                " (Files: " + std::to_string(result.filesExtracted) + 
                ", Threats: " + std::to_string(result.threatsFound) + ")");
    
    return result;
}

bool ArchiveScanner::isZipArchive(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }
    
    // Check for ZIP signature (PK)
    char signature[2];
    file.read(signature, 2);
    
    return (signature[0] == 'P' && signature[1] == 'K');
}

bool ArchiveScanner::checkZipPasswordProtection(const std::string& zipPath) {
    std::vector<ArchiveEntry> entries = listZipContents(zipPath);
    
    for (const auto& entry : entries) {
        if (entry.encrypted) {
            return true;
        }
    }
    
    return false;
}

std::vector<ArchiveEntry> ArchiveScanner::listZipContents(const std::string& zipPath) {
    std::vector<ArchiveEntry> entries;
    
    std::ifstream file(zipPath, std::ios::binary);
    if (!file.is_open()) {
        Logger::log(Logger::Level::ERROR, "Cannot open ZIP file: " + zipPath);
        return entries;
    }
    
    // Find End of Central Directory record
    file.seekg(-22, std::ios::end);
    ZipEndOfCentralDir eocdr;
    
    // Search backwards for EOCDR signature
    for (int i = 0; i < 65536 + 22; i++) {
        file.seekg(-22 - i, std::ios::end);
        file.read(reinterpret_cast<char*>(&eocdr), sizeof(eocdr));
        
        if (eocdr.signature == 0x06054b50) {
            break;
        }
        
        if (file.tellg() <= 0) {
            Logger::log(Logger::Level::ERROR, "EOCDR not found in ZIP file");
            return entries;
        }
    }
    
    if (eocdr.signature != 0x06054b50) {
        Logger::log(Logger::Level::ERROR, "Invalid ZIP file format");
        return entries;
    }
    
    // Read central directory entries
    file.seekg(eocdr.centralDirOffset, std::ios::beg);
    
    for (uint16_t i = 0; i < eocdr.totalEntries; i++) {
        ZipCentralDirEntry cde;
        file.read(reinterpret_cast<char*>(&cde), sizeof(cde));
        
        if (cde.signature != 0x02014b50) {
            Logger::log(Logger::Level::WARNING, "Invalid central directory entry");
            break;
        }
        
        ArchiveEntry entry;
        entry.compressedSize = cde.compressedSize;
        entry.uncompressedSize = cde.uncompressedSize;
        entry.crc32 = cde.crc32;
        entry.encrypted = (cde.flags & 0x1) != 0;
        entry.compressionMethod = cde.compression;
        entry.localHeaderOffset = cde.localHeaderOffset;
        
        // Read filename
        if (cde.fileNameLength > 0) {
            std::vector<char> filename(cde.fileNameLength + 1);
            file.read(filename.data(), cde.fileNameLength);
            filename[cde.fileNameLength] = '\0';
            entry.name = std::string(filename.data());
            
            // Check if it's a directory
            entry.isDirectory = !entry.name.empty() && entry.name.back() == '/';
        }
        
        // Skip extra field and comment
        file.seekg(cde.extraFieldLength + cde.commentLength, std::ios::cur);
        
        entries.push_back(entry);
    }
    
    return entries;
}

bool ArchiveScanner::extractZipEntry(const std::string& zipPath, const ArchiveEntry& entry, const std::string& outputPath) {
    if (entry.encrypted) {
        Logger::log(Logger::Level::WARNING, "Cannot extract encrypted file: " + entry.name);
        return false;
    }
    
    if (entry.uncompressedSize > m_maxExtractedSize / 10) {
        Logger::log(Logger::Level::WARNING, "File too large to extract: " + entry.name);
        return false;
    }
    
    std::ifstream zipFile(zipPath, std::ios::binary);
    if (!zipFile.is_open()) {
        return false;
    }
    
    // Read local file header
    zipFile.seekg(entry.localHeaderOffset, std::ios::beg);
    ZipLocalFileHeader lfh;
    zipFile.read(reinterpret_cast<char*>(&lfh), sizeof(lfh));
    
    if (lfh.signature != 0x04034b50) {
        Logger::log(Logger::Level::ERROR, "Invalid local file header");
        return false;
    }
    
    // Skip filename and extra field
    zipFile.seekg(lfh.fileNameLength + lfh.extraFieldLength, std::ios::cur);
    
    // Create output directory if needed
    std::string outputDir = outputPath.substr(0, outputPath.find_last_of("\\/"));
    CreateDirectoryA(outputDir.c_str(), nullptr);
    
    std::ofstream outputFile(outputPath, std::ios::binary);
    if (!outputFile.is_open()) {
        Logger::log(Logger::Level::ERROR, "Cannot create output file: " + outputPath);
        return false;
    }
    
    // Extract file data
    if (lfh.compression == 0) {
        // No compression (stored)
        std::vector<char> buffer(lfh.compressedSize);
        zipFile.read(buffer.data(), lfh.compressedSize);
        outputFile.write(buffer.data(), lfh.compressedSize);
    } else if (lfh.compression == 8) {
        // Deflate compression - simplified extraction
        // In a full implementation, you'd use zlib for proper decompression
        // For now, we'll just copy the compressed data as a placeholder
        Logger::log(Logger::Level::WARNING, "Deflate compression not fully supported: " + entry.name);
        
        // Copy compressed data (this won't work for actual compressed files)
        std::vector<char> buffer(lfh.compressedSize);
        zipFile.read(buffer.data(), lfh.compressedSize);
        
        // This is a simplified approach - in reality, you'd decompress here
        if (lfh.compressedSize == lfh.uncompressedSize) {
            outputFile.write(buffer.data(), lfh.compressedSize);
        } else {
            outputFile.close();
            DeleteFileA(outputPath.c_str());
            return false;
        }
    } else {
        Logger::log(Logger::Level::WARNING, "Unsupported compression method: " + std::to_string(lfh.compression));
        outputFile.close();
        DeleteFileA(outputPath.c_str());
        return false;
    }
    
    outputFile.close();
    return true;
}

std::string ArchiveScanner::getFileExtension(const std::string& filePath) {
    size_t dotPos = filePath.find_last_of('.');
    if (dotPos == std::string::npos) {
        return "";
    }
    return filePath.substr(dotPos);
}

std::string ArchiveScanner::sanitizeFileName(const std::string& fileName) {
    std::string sanitized = fileName;
    
    // Replace path separators and dangerous characters
    std::replace(sanitized.begin(), sanitized.end(), '/', '_');
    std::replace(sanitized.begin(), sanitized.end(), '\\', '_');
    std::replace(sanitized.begin(), sanitized.end(), ':', '_');
    std::replace(sanitized.begin(), sanitized.end(), '*', '_');
    std::replace(sanitized.begin(), sanitized.end(), '?', '_');
    std::replace(sanitized.begin(), sanitized.end(), '"', '_');
    std::replace(sanitized.begin(), sanitized.end(), '<', '_');
    std::replace(sanitized.begin(), sanitized.end(), '>', '_');
    std::replace(sanitized.begin(), sanitized.end(), '|', '_');
    
    // Remove leading dots and spaces
    while (!sanitized.empty() && (sanitized[0] == '.' || sanitized[0] == ' ')) {
        sanitized.erase(0, 1);
    }
    
    // Truncate if too long
    if (sanitized.length() > 200) {
        sanitized = sanitized.substr(0, 200);
    }
    
    // Ensure not empty
    if (sanitized.empty()) {
        sanitized = "extracted_file";
    }
    
    return sanitized;
}

void ArchiveScanner::cleanupTempDirectory() {
    if (m_tempDirectory.empty()) {
        return;
    }
    
    Logger::log(Logger::Level::DEBUG, "Cleaning up temp directory: " + m_tempDirectory);
    
    // Remove all files and subdirectories
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA((m_tempDirectory + "*").c_str(), &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0) {
                continue;
            }
            
            std::string fullPath = m_tempDirectory + findData.cFileName;
            
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Recursively remove directory
                RemoveDirectoryA(fullPath.c_str());
            } else {
                DeleteFileA(fullPath.c_str());
            }
        } while (FindNextFileA(hFind, &findData));
        
        FindClose(hFind);
    }
    
    // Remove the temp directory itself
    RemoveDirectoryA(m_tempDirectory.c_str());
}

ArchiveScanStats ArchiveScanner::getStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    ArchiveScanStats stats;
    stats.initialized = m_initialized;
    stats.supportedFormats = m_supportedExtensions.size();
    stats.maxNestingLevel = m_maxNestingLevel;
    stats.maxExtractedSizeMB = m_maxExtractedSize / (1024 * 1024);
    stats.tempDirectory = m_tempDirectory;
    
    return stats;
}

void ArchiveScanner::setMaxNestingLevel(int maxLevel) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxNestingLevel = std::max(1, std::min(maxLevel, 10));
    Logger::log(Logger::Level::INFO, "Archive max nesting level set to: " + std::to_string(m_maxNestingLevel));
}

void ArchiveScanner::setMaxExtractedSize(size_t maxSize) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxExtractedSize = maxSize;
    Logger::log(Logger::Level::INFO, "Archive max extracted size set to: " + std::to_string(maxSize) + " bytes");
}
