#include "scanner.h"
#include "threat_engine.h"
#include "logger.h"
#include "utils.h"
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <sstream>

Scanner::Scanner(Logger* logger, ThreatEngine* threatEngine)
    : m_logger(logger)
    , m_threatEngine(threatEngine)
    , m_isScanning(false)
    , m_cancelRequested(false) {
    
    // Set default exclusions
    m_options.exclusions = {
        L"C:\\Windows\\WinSxS",
        L"C:\\Windows\\Servicing",
        L"C:\\System Volume Information",
        L"C:\\$Recycle.Bin",
        L"C:\\hiberfil.sys",
        L"C:\\pagefile.sys",
        L"C:\\swapfile.sys"
    };
}

Scanner::~Scanner() {
    CancelScan();
}

ScanResult Scanner::ScanFile(const std::wstring& filePath, std::vector<ThreatInfo>& threats) {
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Starting file scan: %s", filePath.c_str());
    }
    
    ResetStatistics();
    m_statistics.startTime = std::chrono::steady_clock::now();
    
    ScanResult result = ScanSingleFile(filePath, threats);
    
    m_statistics.endTime = std::chrono::steady_clock::now();
    m_statistics.progressPercent = 100;
    
    if (m_logger) {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            m_statistics.endTime - m_statistics.startTime);
        m_logger->LogFormat(LogLevel::Info, L"File scan completed in %lld ms. Threats found: %llu", 
                           duration.count(), m_statistics.threatsFound);
    }
    
    return result;
}

ScanResult Scanner::ScanFolder(const std::wstring& folderPath, std::vector<ThreatInfo>& threats) {
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Starting folder scan: %s", folderPath.c_str());
    }
    
    return ScanPath(folderPath, threats);
}

ScanResult Scanner::ScanDrive(const std::wstring& driveLetter, std::vector<ThreatInfo>& threats) {
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Starting drive scan: %s", driveLetter.c_str());
    }
    
    std::wstring drivePath = driveLetter;
    if (drivePath.length() == 1) {
        drivePath += L":\\";
    } else if (drivePath.length() == 2 && drivePath[1] == L':') {
        drivePath += L"\\";
    }
    
    return ScanPath(drivePath, threats);
}

ScanResult Scanner::ScanSystem(std::vector<ThreatInfo>& threats) {
    if (m_logger) {
        m_logger->Info(L"Starting system scan");
    }
    
    std::vector<std::wstring> systemPaths = GetSystemPaths();
    return CustomScan(systemPaths, threats);
}

ScanResult Scanner::QuickScan(std::vector<ThreatInfo>& threats) {
    if (m_logger) {
        m_logger->Info(L"Starting quick scan");
    }
    
    std::vector<std::wstring> quickPaths = GetQuickScanPaths();
    return CustomScan(quickPaths, threats);
}

ScanResult Scanner::FullScan(std::vector<ThreatInfo>& threats) {
    if (m_logger) {
        m_logger->Info(L"Starting full scan");
    }
    
    std::vector<std::wstring> drives = GetAvailableDrives();
    return CustomScan(drives, threats);
}

ScanResult Scanner::CustomScan(const std::vector<std::wstring>& paths, std::vector<ThreatInfo>& threats) {
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Starting custom scan of %zu paths", paths.size());
    }
    
    ResetStatistics();
    m_statistics.startTime = std::chrono::steady_clock::now();
    
    ScanResult finalResult = ScanResult::Success;
    
    for (const auto& path : paths) {
        if (m_cancelRequested.load()) {
            finalResult = ScanResult::Cancelled;
            break;
        }
        
        ScanResult result = ScanPath(path, threats);
        if (result != ScanResult::Success && finalResult == ScanResult::Success) {
            finalResult = result;
        }
    }
    
    m_statistics.endTime = std::chrono::steady_clock::now();
    m_statistics.progressPercent = 100;
    
    if (m_logger) {
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            m_statistics.endTime - m_statistics.startTime);
        m_logger->LogFormat(LogLevel::Info, 
                           L"Custom scan completed in %lld ms. Files: %llu, Threats: %llu", 
                           duration.count(), m_statistics.scannedFiles, m_statistics.threatsFound);
    }
    
    return finalResult;
}

bool Scanner::StartScanAsync(ScanType type, const std::vector<std::wstring>& targets) {
    if (m_isScanning.load()) {
        return false; // Already scanning
    }
    
    m_cancelRequested.store(false);
    m_isScanning.store(true);
    
    // Start async scan thread
    if (m_scanThread.joinable()) {
        m_scanThread.join();
    }
    
    m_scanThread = std::thread(&Scanner::AsyncScanThread, this, type, targets);
    
    return true;
}

void Scanner::CancelScan() {
    m_cancelRequested.store(true);
    
    if (m_scanThread.joinable()) {
        m_scanThread.join();
    }
    
    m_isScanning.store(false);
}

ScanResult Scanner::ScanPath(const std::wstring& path, std::vector<ThreatInfo>& threats) {
    if (!Utils::FileExists(path) && !Utils::DirectoryExists(path)) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Warning, L"Path does not exist: %s", path.c_str());
        }
        return ScanResult::Failed;
    }
    
    if (IsExcludedPath(path)) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Debug, L"Skipping excluded path: %s", path.c_str());
        }
        return ScanResult::Success;
    }
    
    try {
        if (std::filesystem::is_regular_file(path)) {
            return ScanSingleFile(path, threats);
        } else if (std::filesystem::is_directory(path)) {
            ScanDirectoryRecursive(path, threats);
            return ScanResult::Success;
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Filesystem error scanning path %s: %S", 
                               path.c_str(), e.what());
        }
        return ScanResult::AccessDenied;
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Error scanning path %s: %S", 
                               path.c_str(), e.what());
        }
        return ScanResult::Failed;
    }
    
    return ScanResult::Success;
}

ScanResult Scanner::ScanSingleFile(const std::wstring& filePath, std::vector<ThreatInfo>& threats) {
    if (m_cancelRequested.load()) {
        return ScanResult::Cancelled;
    }
    
    if (!ShouldScanFile(filePath)) {
        {
            std::lock_guard<std::mutex> lock(m_statisticsMutex);
            m_statistics.skippedFiles++;
        }
        return ScanResult::Success;
    }
    
    try {
        // Update progress callback
        if (m_progressCallback) {
            UpdateProgress();
            m_progressCallback(filePath, m_statistics.progressPercent, m_statistics);
        }
        
        // Scan the file
        ThreatInfo threat;
        bool isThreat = false;
        
        if (m_threatEngine) {
            isThreat = m_threatEngine->ScanFile(filePath, threat);
        }
        
        {
            std::lock_guard<std::mutex> lock(m_statisticsMutex);
            m_statistics.scannedFiles++;
            m_statistics.scannedBytes += Utils::GetFileSize(filePath);
            
            if (isThreat) {
                m_statistics.threatsFound++;
                threats.push_back(threat);
                
                // Call threat callback
                if (m_threatCallback) {
                    m_threatCallback(threat);
                }
            }
        }
        
        return ScanResult::Success;
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Error scanning file %s: %S", 
                               filePath.c_str(), e.what());
        }
        
        {
            std::lock_guard<std::mutex> lock(m_statisticsMutex);
            m_statistics.skippedFiles++;
        }
        
        return ScanResult::Failed;
    }
}

void Scanner::ScanDirectoryRecursive(const std::wstring& dirPath, std::vector<ThreatInfo>& threats) {
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(
            dirPath, std::filesystem::directory_options::skip_permission_denied)) {
            
            if (m_cancelRequested.load()) {
                break;
            }
            
            if (entry.is_regular_file()) {
                const std::wstring filePath = entry.path().wstring();
                
                {
                    std::lock_guard<std::mutex> lock(m_statisticsMutex);
                    m_statistics.totalFiles++;
                    m_statistics.totalBytes += entry.file_size();
                }
                
                ScanSingleFile(filePath, threats);
            }
        }
    }
    catch (const std::filesystem::filesystem_error& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Warning, L"Filesystem error in directory %s: %S", 
                               dirPath.c_str(), e.what());
        }
    }
}

void Scanner::AsyncScanThread(ScanType type, std::vector<std::wstring> targets) {
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Starting async scan thread (type: %d)", static_cast<int>(type));
    }
    
    std::vector<ThreatInfo> threats;
    ScanResult result = ScanResult::Success;
    
    try {
        switch (type) {
        case ScanType::File:
            if (!targets.empty()) {
                result = ScanFile(targets[0], threats);
            }
            break;
        case ScanType::Folder:
            if (!targets.empty()) {
                result = ScanFolder(targets[0], threats);
            }
            break;
        case ScanType::Drive:
            if (!targets.empty()) {
                result = ScanDrive(targets[0], threats);
            }
            break;
        case ScanType::System:
            result = ScanSystem(threats);
            break;
        case ScanType::Quick:
            result = QuickScan(threats);
            break;
        case ScanType::Full:
            result = FullScan(threats);
            break;
        case ScanType::Custom:
            result = CustomScan(targets, threats);
            break;
        }
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Exception in async scan thread: %S", e.what());
        }
        result = ScanResult::Failed;
    }
    
    m_isScanning.store(false);
    
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Async scan thread completed with result: %d", static_cast<int>(result));
    }
}

bool Scanner::ShouldScanFile(const std::wstring& filePath) const {
    // Check file size limit
    uint64_t fileSize = Utils::GetFileSize(filePath);
    if (fileSize > m_options.maxFileSize) {
        return false;
    }
    
    // Check extension filter
    if (!m_options.extensions.empty()) {
        auto ext = std::filesystem::path(filePath).extension().wstring();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
        
        if (!IsAllowedExtension(ext)) {
            return false;
        }
    }
    
    // Check if path is excluded
    return !IsExcludedPath(filePath);
}

bool Scanner::IsExcludedPath(const std::wstring& path) const {
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    
    for (const auto& exclusion : m_options.exclusions) {
        std::wstring lowerExclusion = exclusion;
        std::transform(lowerExclusion.begin(), lowerExclusion.end(), lowerExclusion.begin(), ::towlower);
        
        if (lowerPath.find(lowerExclusion) == 0) {
            return true;
        }
    }
    
    return false;
}

bool Scanner::IsAllowedExtension(const std::wstring& extension) const {
    if (m_options.extensions.empty()) {
        return true; // No filter means allow all
    }
    
    std::wstring lowerExt = extension;
    std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::towlower);
    
    return std::find(m_options.extensions.begin(), m_options.extensions.end(), lowerExt) 
           != m_options.extensions.end();
}

std::vector<std::wstring> Scanner::GetSystemPaths() const {
    return {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        Utils::GetSystemDirectory()
    };
}

std::vector<std::wstring> Scanner::GetQuickScanPaths() const {
    std::vector<std::wstring> quickPaths = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\SysWOW64",
        L"C:\\Program Files",
        L"C:\\Program Files (x86)",
        Utils::GetTempDirectory()
    };
    
    // Add user directories
    try {
        std::wstring userProfile = Utils::GetCurrentUserSID();
        if (!userProfile.empty()) {
            quickPaths.push_back(L"C:\\Users\\" + userProfile + L"\\Desktop");
            quickPaths.push_back(L"C:\\Users\\" + userProfile + L"\\Downloads");
            quickPaths.push_back(L"C:\\Users\\" + userProfile + L"\\Documents");
            quickPaths.push_back(L"C:\\Users\\" + userProfile + L"\\AppData\\Local\\Temp");
        }
    }
    catch (...) {
        // Ignore errors getting user paths
    }
    
    return quickPaths;
}

std::vector<std::wstring> Scanner::GetAvailableDrives() const {
    std::vector<std::wstring> drives;
    
    DWORD driveMask = GetLogicalDrives();
    
    for (int i = 0; i < 26; ++i) {
        if (driveMask & (1 << i)) {
            wchar_t driveLetter = L'A' + i;
            std::wstring drive = std::wstring(1, driveLetter) + L":\\";
            
            // Check if drive is accessible
            UINT driveType = GetDriveType(drive.c_str());
            if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
                drives.push_back(drive);
            }
        }
    }
    
    return drives;
}

void Scanner::UpdateProgress() {
    std::lock_guard<std::mutex> lock(m_statisticsMutex);
    
    if (m_statistics.totalFiles > 0) {
        m_statistics.progressPercent = static_cast<uint32_t>(
            (m_statistics.scannedFiles * 100) / m_statistics.totalFiles);
    }
    
    if (m_statistics.progressPercent > 100) {
        m_statistics.progressPercent = 100;
    }
}

void Scanner::ResetStatistics() {
    std::lock_guard<std::mutex> lock(m_statisticsMutex);
    
    m_statistics = ScanStatistics();
    m_statistics.startTime = std::chrono::steady_clock::now();
}

bool Scanner::ScanArchive(const std::wstring& archivePath, std::vector<ThreatInfo>& threats) {
    // TODO: Implement archive scanning
    // This would require integrating with a library like libzip or 7-Zip
    // For now, just scan the archive file itself
    
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Debug, L"Archive scanning not yet implemented: %s", archivePath.c_str());
    }
    
    return ScanSingleFile(archivePath, threats) == ScanResult::Success;
}
