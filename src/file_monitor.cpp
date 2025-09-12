#include "file_monitor.h"
#include "threat_engine.h"
#include "logger.h"
#include "utils.h"
#include <filesystem>
#include <thread>
#include <chrono>
#include <algorithm>

FileMonitor::FileMonitor(Logger* logger, ThreatEngine* threatEngine)
    : m_logger(logger)
    , m_threatEngine(threatEngine)
    , m_running(false)
    , m_realTimeProtectionEnabled(true)
    , m_maxThreads(4)
    , m_scanDelayMs(100) {
}

FileMonitor::~FileMonitor() {
    Shutdown();
}

bool FileMonitor::Initialize() {
    if (m_running.load()) {
        return true;
    }

    if (m_logger) {
        m_logger->Info(L"Initializing File Monitor...");
    }

    try {
        // Add default watch paths
        AddWatchPath(L"C:\\");
        AddWatchPath(L"D:\\");
        
        // Add user directories
        std::wstring userProfile = Utils::GetCurrentUserSID();
        if (!userProfile.empty()) {
            AddWatchPath(L"C:\\Users\\" + userProfile);
        }

        // Add system directories for critical monitoring
        AddWatchPath(L"C:\\Windows\\System32");
        AddWatchPath(L"C:\\Program Files");
        AddWatchPath(L"C:\\Program Files (x86)");

        m_running.store(true);
        
        // Start monitoring threads
        for (size_t i = 0; i < m_maxThreads; ++i) {
            m_workerThreads.emplace_back(&FileMonitor::WorkerThread, this);
        }

        // Start main monitoring thread
        m_monitorThread = std::thread(&FileMonitor::MonitorThread, this);

        if (m_logger) {
            m_logger->LogFormat(LogLevel::Info, L"File Monitor initialized successfully. Watching %zu paths", 
                               m_watchedPaths.size());
        }

        return true;
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Failed to initialize File Monitor: %S", e.what());
        }
        return false;
    }
}

void FileMonitor::Shutdown() {
    if (!m_running.load()) {
        return;
    }

    if (m_logger) {
        m_logger->Info(L"Shutting down File Monitor...");
    }

    m_running.store(false);

    // Signal all threads to stop
    m_workCondition.notify_all();

    // Join worker threads
    for (auto& thread : m_workerThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_workerThreads.clear();

    // Join monitor thread
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }

    // Clean up watch handles
    for (auto& watch : m_watchHandles) {
        if (watch.second.handle != INVALID_HANDLE_VALUE) {
            CloseHandle(watch.second.handle);
        }
    }
    m_watchHandles.clear();

    m_watchedPaths.clear();

    if (m_logger) {
        m_logger->Info(L"File Monitor shutdown complete");
    }
}

void FileMonitor::AddWatchPath(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_pathsMutex);
    
    if (std::find(m_watchedPaths.begin(), m_watchedPaths.end(), path) != m_watchedPaths.end()) {
        return; // Already watching this path
    }

    if (!Utils::DirectoryExists(path)) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Warning, L"Cannot watch non-existent path: %s", path.c_str());
        }
        return;
    }

    // Create watch handle
    HANDLE handle = CreateFile(
        path.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        nullptr
    );

    if (handle == INVALID_HANDLE_VALUE) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Failed to create watch handle for path: %s (Error: %d)", 
                               path.c_str(), GetLastError());
        }
        return;
    }

    WatchInfo watchInfo;
    watchInfo.handle = handle;
    watchInfo.path = path;
    watchInfo.buffer.resize(64 * 1024); // 64KB buffer
    ZeroMemory(&watchInfo.overlapped, sizeof(watchInfo.overlapped));

    m_watchHandles[path] = std::move(watchInfo);
    m_watchedPaths.push_back(path);

    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Added watch path: %s", path.c_str());
    }
}

void FileMonitor::RemoveWatchPath(const std::wstring& path) {
    std::lock_guard<std::mutex> lock(m_pathsMutex);
    
    auto it = std::find(m_watchedPaths.begin(), m_watchedPaths.end(), path);
    if (it != m_watchedPaths.end()) {
        m_watchedPaths.erase(it);
    }

    auto handleIt = m_watchHandles.find(path);
    if (handleIt != m_watchHandles.end()) {
        if (handleIt->second.handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handleIt->second.handle);
        }
        m_watchHandles.erase(handleIt);
    }

    if (m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Removed watch path: %s", path.c_str());
    }
}

void FileMonitor::SetRealTimeProtection(bool enabled) {
    bool oldValue = m_realTimeProtectionEnabled.exchange(enabled);
    
    if (oldValue != enabled && m_logger) {
        m_logger->LogFormat(LogLevel::Info, L"Real-time protection %s", 
                           enabled ? L"enabled" : L"disabled");
    }
}

void FileMonitor::MonitorThread() {
    if (m_logger) {
        m_logger->Info(L"File Monitor thread started");
    }

    while (m_running.load()) {
        try {
            // Start async read operations for all watched paths
            for (auto& [path, watchInfo] : m_watchHandles) {
                if (!ReadDirectoryChangesW(
                    watchInfo.handle,
                    watchInfo.buffer.data(),
                    static_cast<DWORD>(watchInfo.buffer.size()),
                    TRUE, // Watch subtree
                    FILE_NOTIFY_CHANGE_FILE_NAME | 
                    FILE_NOTIFY_CHANGE_SIZE | 
                    FILE_NOTIFY_CHANGE_LAST_WRITE | 
                    FILE_NOTIFY_CHANGE_CREATION,
                    nullptr,
                    &watchInfo.overlapped,
                    nullptr
                )) {
                    if (m_logger) {
                        m_logger->LogFormat(LogLevel::Error, L"ReadDirectoryChangesW failed for path: %s (Error: %d)", 
                                           path.c_str(), GetLastError());
                    }
                    continue;
                }
            }

            // Wait for events
            std::vector<HANDLE> handles;
            std::vector<std::wstring> paths;
            
            for (const auto& [path, watchInfo] : m_watchHandles) {
                handles.push_back(watchInfo.overlapped.hEvent);
                paths.push_back(path);
            }

            if (handles.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                continue;
            }

            DWORD waitResult = WaitForMultipleObjects(
                static_cast<DWORD>(handles.size()),
                handles.data(),
                FALSE, // Wait for any
                1000   // 1 second timeout
            );

            if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + handles.size()) {
                size_t index = waitResult - WAIT_OBJECT_0;
                ProcessDirectoryChanges(paths[index]);
            }
            else if (waitResult == WAIT_TIMEOUT) {
                // Normal timeout, continue monitoring
                continue;
            }
            else if (waitResult == WAIT_FAILED) {
                if (m_logger) {
                    m_logger->LogFormat(LogLevel::Error, L"WaitForMultipleObjects failed (Error: %d)", GetLastError());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5000));
            }
        }
        catch (const std::exception& e) {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Error, L"Exception in monitor thread: %S", e.what());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(5000));
        }
    }

    if (m_logger) {
        m_logger->Info(L"File Monitor thread stopped");
    }
}

void FileMonitor::ProcessDirectoryChanges(const std::wstring& watchPath) {
    auto it = m_watchHandles.find(watchPath);
    if (it == m_watchHandles.end()) {
        return;
    }

    WatchInfo& watchInfo = it->second;
    DWORD bytesReturned = 0;
    
    if (!GetOverlappedResult(watchInfo.handle, &watchInfo.overlapped, &bytesReturned, FALSE)) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"GetOverlappedResult failed for path: %s (Error: %d)", 
                               watchPath.c_str(), GetLastError());
        }
        return;
    }

    if (bytesReturned == 0) {
        return; // No changes
    }

    // Parse the FILE_NOTIFY_INFORMATION structures
    DWORD offset = 0;
    while (offset < bytesReturned) {
        FILE_NOTIFY_INFORMATION* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(
            watchInfo.buffer.data() + offset);

        // Convert filename to wide string
        std::wstring fileName(info->FileName, info->FileNameLength / sizeof(WCHAR));
        std::wstring fullPath = watchPath + L"\\" + fileName;

        // Process the file event
        ProcessFileEvent(fullPath, info->Action);

        if (info->NextEntryOffset == 0) {
            break;
        }
        offset += info->NextEntryOffset;
    }

    // Reset overlapped structure for next operation
    ZeroMemory(&watchInfo.overlapped, sizeof(watchInfo.overlapped));
    watchInfo.overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
}

void FileMonitor::ProcessFileEvent(const std::wstring& filePath, DWORD action) {
    if (!m_realTimeProtectionEnabled.load()) {
        return;
    }

    // Filter out system and temporary files
    if (ShouldSkipFile(filePath)) {
        return;
    }

    // Only process file creation and modification events
    if (action == FILE_ACTION_ADDED || action == FILE_ACTION_MODIFIED) {
        // Add to scan queue
        ScanRequest request;
        request.filePath = filePath;
        request.priority = DetermineScanPriority(filePath);
        request.timestamp = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(m_queueMutex);
            m_scanQueue.push(request);
        }
        
        m_workCondition.notify_one();

        if (m_logger) {
            m_logger->LogFormat(LogLevel::Debug, L"Queued file for scan: %s", filePath.c_str());
        }
    }
}

void FileMonitor::WorkerThread() {
    while (m_running.load()) {
        ScanRequest request;
        bool hasWork = false;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            m_workCondition.wait(lock, [this] { 
                return !m_scanQueue.empty() || !m_running.load(); 
            });

            if (!m_running.load()) {
                break;
            }

            if (!m_scanQueue.empty()) {
                request = m_scanQueue.top();
                m_scanQueue.pop();
                hasWork = true;
            }
        }

        if (hasWork) {
            ProcessScanRequest(request);
        }
    }
}

void FileMonitor::ProcessScanRequest(const ScanRequest& request) {
    try {
        // Add delay to avoid scanning files that are still being written
        std::this_thread::sleep_for(std::chrono::milliseconds(m_scanDelayMs));

        // Check if file still exists and is accessible
        if (!Utils::FileExists(request.filePath)) {
            return;
        }

        // Scan the file
        ThreatInfo threat;
        if (m_threatEngine && m_threatEngine->ScanFile(request.filePath, threat)) {
            // Threat detected!
            HandleThreatDetection(threat);
        }
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Error processing scan request for %s: %S", 
                               request.filePath.c_str(), e.what());
        }
    }
}

void FileMonitor::HandleThreatDetection(const ThreatInfo& threat) {
    if (m_logger) {
        m_logger->LogFormat(LogLevel::Critical, L"THREAT DETECTED: %s in file %s (Level: %d)", 
                           threat.threat_name.c_str(), threat.file_path.c_str(), threat.threat_level);
    }

    // Automatically quarantine high-severity threats
    if (threat.threat_level >= 8) {
        if (m_threatEngine && m_threatEngine->QuarantineFile(threat.file_path, threat.threat_name)) {
            if (m_logger) {
                m_logger->LogFormat(LogLevel::Info, L"High-severity threat automatically quarantined: %s", 
                                   threat.file_path.c_str());
            }
        }
    }

    // TODO: Send notification to client application
    // This would involve sending a message through the pipe server
}

bool FileMonitor::ShouldSkipFile(const std::wstring& filePath) const {
    // Skip system files and directories
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    // Skip temporary files
    if (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
        lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
        lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos) {
        return true;
    }

    // Skip system directories
    if (lowerPath.find(L"\\windows\\winsxs\\") != std::wstring::npos ||
        lowerPath.find(L"\\windows\\servicing\\") != std::wstring::npos ||
        lowerPath.find(L"\\system volume information\\") != std::wstring::npos) {
        return true;
    }

    // Skip log files and other non-executable files
    auto ext = std::filesystem::path(filePath).extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    
    static const std::vector<std::wstring> skipExtensions = {
        L".log", L".tmp", L".temp", L".swp", L".bak",
        L".txt", L".ini", L".xml", L".json"
    };

    if (std::find(skipExtensions.begin(), skipExtensions.end(), ext) != skipExtensions.end()) {
        return true;
    }

    return false;
}

uint32_t FileMonitor::DetermineScanPriority(const std::wstring& filePath) const {
    auto ext = std::filesystem::path(filePath).extension().wstring();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    // High priority for executables
    if (ext == L".exe" || ext == L".dll" || ext == L".scr" || ext == L".com" || ext == L".pif") {
        return 10;
    }

    // Medium priority for scripts
    if (ext == L".bat" || ext == L".cmd" || ext == L".ps1" || ext == L".vbs" || ext == L".js") {
        return 7;
    }

    // Medium priority for documents (potential macro threats)
    if (ext == L".doc" || ext == L".docx" || ext == L".xls" || ext == L".xlsx" || ext == L".ppt" || ext == L".pptx") {
        return 5;
    }

    // Low priority for archives
    if (ext == L".zip" || ext == L".rar" || ext == L".7z" || ext == L".tar") {
        return 3;
    }

    // Default priority
    return 1;
}
