#include "system_integration.h"
#include "logger.h"
#include <windows.h>
#include <winbase.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <psapi.h>
#include <winternl.h>
#include <ntstatus.h>
#include <thread>
#include <chrono>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

SystemIntegration::SystemIntegration()
    : m_initialized(false)
    , m_running(false)
    , m_registryMonitoringEnabled(false)
    , m_processMonitoringEnabled(false)
    , m_systemEventMonitoringEnabled(false) {
}

SystemIntegration::~SystemIntegration() {
    shutdown();
}

bool SystemIntegration::initialize() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    Logger::log(Logger::Level::INFO, "Initializing system integration");
    
    // Register with Windows Security Center
    if (!registerWithSecurityCenter()) {
        Logger::log(Logger::Level::WARNING, "Failed to register with Windows Security Center");
    }
    
    // Initialize registry monitoring
    if (!initializeRegistryMonitoring()) {
        Logger::log(Logger::Level::WARNING, "Failed to initialize registry monitoring");
    }
    
    // Initialize process monitoring
    if (!initializeProcessMonitoring()) {
        Logger::log(Logger::Level::WARNING, "Failed to initialize process monitoring");
    }
    
    // Initialize system event monitoring
    if (!initializeSystemEventMonitoring()) {
        Logger::log(Logger::Level::WARNING, "Failed to initialize system event monitoring");
    }
    
    m_initialized = true;
    Logger::log(Logger::Level::INFO, "System integration initialized");
    
    return true;
}

void SystemIntegration::shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized) return;
    
    Logger::log(Logger::Level::INFO, "Shutting down system integration");
    
    // Stop all monitoring
    stop();
    
    // Unregister from Windows Security Center
    unregisterFromSecurityCenter();
    
    // Cleanup handles
    for (auto& handle : m_registryKeys) {
        if (handle != nullptr) {
            RegCloseKey(handle);
        }
    }
    m_registryKeys.clear();
    
    for (auto& handle : m_eventHandles) {
        if (handle != nullptr) {
            CloseHandle(handle);
        }
    }
    m_eventHandles.clear();
    
    m_initialized = false;
}

bool SystemIntegration::start() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (!m_initialized || m_running) return false;
    
    Logger::log(Logger::Level::INFO, "Starting system integration monitoring");
    
    m_running = true;
    
    // Start monitoring threads
    if (m_registryMonitoringEnabled) {
        m_registryThread = std::thread(&SystemIntegration::registryMonitoringLoop, this);
    }
    
    if (m_processMonitoringEnabled) {
        m_processThread = std::thread(&SystemIntegration::processMonitoringLoop, this);
    }
    
    if (m_systemEventMonitoringEnabled) {
        m_systemEventThread = std::thread(&SystemIntegration::systemEventMonitoringLoop, this);
    }
    
    Logger::log(Logger::Level::INFO, "System integration monitoring started");
    return true;
}

void SystemIntegration::stop() {
    if (!m_running) return;
    
    Logger::log(Logger::Level::INFO, "Stopping system integration monitoring");
    
    m_running = false;
    
    // Join monitoring threads
    if (m_registryThread.joinable()) {
        m_registryThread.join();
    }
    
    if (m_processThread.joinable()) {
        m_processThread.join();
    }
    
    if (m_systemEventThread.joinable()) {
        m_systemEventThread.join();
    }
    
    Logger::log(Logger::Level::INFO, "System integration monitoring stopped");
}

bool SystemIntegration::registerWithSecurityCenter() {
    Logger::log(Logger::Level::INFO, "Registering with Windows Security Center");
    
    HKEY hKey;
    DWORD dwDisposition;
    
    // Register as antivirus product
    LONG result = RegCreateKeyExW(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Security Center\\Svc\\AntivirusOverride",
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &dwDisposition
    );
    
    if (result == ERROR_SUCCESS) {
        // Set our product as registered antivirus
        DWORD enabled = 1;
        RegSetValueExW(hKey, L"Professional Antivirus", 0, REG_DWORD, 
                      (BYTE*)&enabled, sizeof(DWORD));
        
        RegCloseKey(hKey);
        
        Logger::log(Logger::Level::INFO, "Successfully registered with Security Center");
        return true;
    } else {
        Logger::log(Logger::Level::ERROR, "Failed to register with Security Center: " + std::to_string(result));
        return false;
    }
}

void SystemIntegration::unregisterFromSecurityCenter() {
    Logger::log(Logger::Level::INFO, "Unregistering from Windows Security Center");
    
    // Remove registry entries
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, 
                  L"SOFTWARE\\Microsoft\\Security Center\\Svc\\AntivirusOverride");
    
    // Remove monitoring keys
    RegDeleteValueW(HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Security Center\\Monitoring\\AntivirusService",
                   L"DisableMonitoring");
}

bool SystemIntegration::initializeRegistryMonitoring() {
    Logger::log(Logger::Level::INFO, "Initializing registry monitoring");
    
    // Monitor critical registry keys
    std::vector<std::wstring> keysToMonitor = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"SYSTEM\\CurrentControlSet\\Services",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    };
    
    for (const auto& keyPath : keysToMonitor) {
        HKEY hKey;
        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, 
                                   KEY_NOTIFY | KEY_READ, &hKey);
        
        if (result == ERROR_SUCCESS) {
            m_registryKeys.push_back(hKey);
            m_registryKeyPaths.push_back(keyPath);
            
            // Create event for this key
            HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
            if (hEvent) {
                m_registryEvents.push_back(hEvent);
                
                // Set up notification
                RegNotifyChangeKeyValue(hKey, TRUE, 
                                       REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                       hEvent, TRUE);
            }
        } else {
            Logger::log(Logger::Level::WARNING, "Failed to open registry key for monitoring: " + 
                       std::string(keyPath.begin(), keyPath.end()));
        }
    }
    
    m_registryMonitoringEnabled = !m_registryKeys.empty();
    Logger::log(Logger::Level::INFO, "Registry monitoring initialized for " + 
                std::to_string(m_registryKeys.size()) + " keys");
    
    return m_registryMonitoringEnabled;
}

bool SystemIntegration::initializeProcessMonitoring() {
    Logger::log(Logger::Level::INFO, "Initializing process monitoring");
    
    // Enable process monitoring by default
    m_processMonitoringEnabled = true;
    
    Logger::log(Logger::Level::INFO, "Process monitoring initialized");
    return true;
}

bool SystemIntegration::initializeSystemEventMonitoring() {
    Logger::log(Logger::Level::INFO, "Initializing system event monitoring");
    
    // Monitor system shutdown/startup events
    HANDLE hEvent = CreateEvent(NULL, TRUE, FALSE, L"Global\\AntivirusSystemEvent");
    if (hEvent) {
        m_eventHandles.push_back(hEvent);
    }
    
    m_systemEventMonitoringEnabled = !m_eventHandles.empty();
    
    Logger::log(Logger::Level::INFO, "System event monitoring initialized");
    return m_systemEventMonitoringEnabled;
}

void SystemIntegration::registryMonitoringLoop() {
    Logger::log(Logger::Level::INFO, "Registry monitoring loop started");
    
    while (m_running) {
        try {
            // Wait for registry change events
            DWORD waitResult = WaitForMultipleObjects(
                static_cast<DWORD>(m_registryEvents.size()),
                m_registryEvents.data(),
                FALSE,
                1000  // 1 second timeout
            );
            
            if (waitResult >= WAIT_OBJECT_0 && 
                waitResult < WAIT_OBJECT_0 + m_registryEvents.size()) {
                
                DWORD eventIndex = waitResult - WAIT_OBJECT_0;
                
                Logger::log(Logger::Level::WARNING, 
                           "Registry change detected in: " + 
                           std::string(m_registryKeyPaths[eventIndex].begin(), 
                                     m_registryKeyPaths[eventIndex].end()));
                
                // Process the registry change
                processRegistryChange(eventIndex);
                
                // Reset the event and re-enable notification
                ResetEvent(m_registryEvents[eventIndex]);
                RegNotifyChangeKeyValue(m_registryKeys[eventIndex], TRUE,
                                       REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                                       m_registryEvents[eventIndex], TRUE);
            }
            
            // Small sleep to prevent high CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
        } catch (const std::exception& e) {
            Logger::log(Logger::Level::ERROR, "Exception in registry monitoring loop: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
    
    Logger::log(Logger::Level::INFO, "Registry monitoring loop stopped");
}

void SystemIntegration::processMonitoringLoop() {
    Logger::log(Logger::Level::INFO, "Process monitoring loop started");
    
    std::set<DWORD> previousProcesses;
    
    // Get initial process list
    getRunningProcesses(previousProcesses);
    
    while (m_running) {
        try {
            std::set<DWORD> currentProcesses;
            getRunningProcesses(currentProcesses);
            
            // Find new processes
            std::set<DWORD> newProcesses;
            std::set_difference(currentProcesses.begin(), currentProcesses.end(),
                               previousProcesses.begin(), previousProcesses.end(),
                               std::inserter(newProcesses, newProcesses.begin()));
            
            // Find terminated processes
            std::set<DWORD> terminatedProcesses;
            std::set_difference(previousProcesses.begin(), previousProcesses.end(),
                               currentProcesses.begin(), currentProcesses.end(),
                               std::inserter(terminatedProcesses, terminatedProcesses.begin()));
            
            // Process new processes
            for (DWORD pid : newProcesses) {
                processNewProcess(pid);
            }
            
            // Process terminated processes
            for (DWORD pid : terminatedProcesses) {
                processTerminatedProcess(pid);
            }
            
            previousProcesses = currentProcesses;
            
            // Sleep for monitoring interval
            std::this_thread::sleep_for(std::chrono::seconds(5));
            
        } catch (const std::exception& e) {
            Logger::log(Logger::Level::ERROR, "Exception in process monitoring loop: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }
    
    Logger::log(Logger::Level::INFO, "Process monitoring loop stopped");
}

void SystemIntegration::systemEventMonitoringLoop() {
    Logger::log(Logger::Level::INFO, "System event monitoring loop started");
    
    while (m_running) {
        try {
            // Monitor system events
            // This is a simplified implementation - in practice, you'd use 
            // Windows Event Log APIs or ETW (Event Tracing for Windows)
            
            // Check for system shutdown/restart events
            if (GetSystemMetrics(SM_SHUTTINGDOWN)) {
                Logger::log(Logger::Level::WARNING, "System shutdown detected");
                handleSystemShutdown();
            }
            
            // Check for user session changes
            checkUserSessions();
            
            // Sleep for monitoring interval
            std::this_thread::sleep_for(std::chrono::seconds(10));
            
        } catch (const std::exception& e) {
            Logger::log(Logger::Level::ERROR, "Exception in system event monitoring loop: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }
    
    Logger::log(Logger::Level::INFO, "System event monitoring loop stopped");
}

void SystemIntegration::processRegistryChange(DWORD keyIndex) {
    if (keyIndex >= m_registryKeyPaths.size()) return;
    
    const std::wstring& keyPath = m_registryKeyPaths[keyIndex];
    
    Logger::log(Logger::Level::INFO, "Processing registry change for: " + 
               std::string(keyPath.begin(), keyPath.end()));
    
    // Check for suspicious registry modifications
    if (keyPath.find(L"Run") != std::wstring::npos) {
        checkAutoStartEntries(m_registryKeys[keyIndex], keyPath);
    } else if (keyPath.find(L"Winlogon") != std::wstring::npos) {
        checkWinlogonChanges(m_registryKeys[keyIndex]);
    } else if (keyPath.find(L"Services") != std::wstring::npos) {
        checkServiceChanges(m_registryKeys[keyIndex]);
    }
}

void SystemIntegration::processNewProcess(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return;
    
    char processName[MAX_PATH] = { 0 };
    DWORD size = sizeof(processName);
    
    if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
        Logger::log(Logger::Level::DEBUG, "New process started: " + std::string(processName) + 
                   " (PID: " + std::to_string(processId) + ")");
        
        // Check if this is a suspicious process
        if (isSuspiciousProcess(processName, processId)) {
            Logger::log(Logger::Level::WARNING, "Suspicious process detected: " + std::string(processName));
            // In a full implementation, you might want to scan the process or take action
        }
    }
    
    CloseHandle(hProcess);
}

void SystemIntegration::processTerminatedProcess(DWORD processId) {
    Logger::log(Logger::Level::DEBUG, "Process terminated (PID: " + std::to_string(processId) + ")");
    
    // Remove from any internal tracking
    // In a full implementation, you might track process behavior patterns
}

void SystemIntegration::getRunningProcesses(std::set<DWORD>& processes) {
    processes.clear();
    
    DWORD processIds[4096];
    DWORD bytesReturned;
    
    if (EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        DWORD numProcesses = bytesReturned / sizeof(DWORD);
        
        for (DWORD i = 0; i < numProcesses; i++) {
            if (processIds[i] != 0) {
                processes.insert(processIds[i]);
            }
        }
    }
}

bool SystemIntegration::isSuspiciousProcess(const std::string& processPath, DWORD processId) {
    // Simple heuristics for suspicious processes
    std::string lowerPath = processPath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
    
    // Check for processes in suspicious locations
    if (lowerPath.find("\\temp\\") != std::string::npos ||
        lowerPath.find("\\appdata\\local\\temp\\") != std::string::npos ||
        lowerPath.find("\\users\\public\\") != std::string::npos) {
        return true;
    }
    
    // Check for suspicious process names
    std::vector<std::string> suspiciousNames = {
        "keylogger", "trojan", "backdoor", "miner", "crypter", "injector"
    };
    
    for (const auto& name : suspiciousNames) {
        if (lowerPath.find(name) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

void SystemIntegration::checkAutoStartEntries(HKEY hKey, const std::wstring& keyPath) {
    Logger::log(Logger::Level::DEBUG, "Checking autostart entries");
    
    DWORD index = 0;
    wchar_t valueName[256];
    DWORD valueNameSize = sizeof(valueName) / sizeof(wchar_t);
    wchar_t valueData[1024];
    DWORD valueDataSize = sizeof(valueData);
    DWORD valueType;
    
    while (RegEnumValueW(hKey, index, valueName, &valueNameSize,
                        NULL, &valueType, (BYTE*)valueData, &valueDataSize) == ERROR_SUCCESS) {
        
        std::wstring name(valueName);
        std::wstring data(valueData);
        
        // Check for suspicious autostart entries
        if (isSuspiciousAutoStartEntry(name, data)) {
            Logger::log(Logger::Level::WARNING, "Suspicious autostart entry detected: " + 
                       std::string(name.begin(), name.end()) + " -> " + 
                       std::string(data.begin(), data.end()));
        }
        
        index++;
        valueNameSize = sizeof(valueName) / sizeof(wchar_t);
        valueDataSize = sizeof(valueData);
    }
}

bool SystemIntegration::isSuspiciousAutoStartEntry(const std::wstring& name, const std::wstring& value) {
    std::wstring lowerName = name;
    std::wstring lowerValue = value;
    
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);
    std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
    
    // Check for suspicious paths
    if (lowerValue.find(L"\\temp\\") != std::wstring::npos ||
        lowerValue.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
        lowerValue.find(L"\\users\\public\\") != std::wstring::npos) {
        return true;
    }
    
    // Check for suspicious names
    if (lowerName.find(L"update") != std::wstring::npos && 
        lowerName.find(L"java") == std::wstring::npos &&
        lowerName.find(L"adobe") == std::wstring::npos) {
        return true;
    }
    
    return false;
}

void SystemIntegration::checkWinlogonChanges(HKEY hKey) {
    Logger::log(Logger::Level::DEBUG, "Checking Winlogon changes");
    
    // Check for modifications to critical Winlogon values
    std::vector<std::wstring> criticalValues = {
        L"Shell", L"Userinit", L"Taskman", L"System"
    };
    
    for (const auto& valueName : criticalValues) {
        wchar_t valueData[1024];
        DWORD valueDataSize = sizeof(valueData);
        DWORD valueType;
        
        LONG result = RegQueryValueExW(hKey, valueName.c_str(), NULL, &valueType,
                                      (BYTE*)valueData, &valueDataSize);
        
        if (result == ERROR_SUCCESS) {
            std::wstring data(valueData);
            
            if (isSuspiciousWinlogonValue(valueName, data)) {
                Logger::log(Logger::Level::WARNING, "Suspicious Winlogon modification: " + 
                           std::string(valueName.begin(), valueName.end()) + " -> " + 
                           std::string(data.begin(), data.end()));
            }
        }
    }
}

bool SystemIntegration::isSuspiciousWinlogonValue(const std::wstring& name, const std::wstring& value) {
    std::wstring lowerValue = value;
    std::transform(lowerValue.begin(), lowerValue.end(), lowerValue.begin(), ::tolower);
    
    // Check for suspicious modifications to shell
    if (name == L"Shell") {
        return lowerValue != L"explorer.exe" && 
               lowerValue.find(L"explorer.exe") == std::wstring::npos;
    }
    
    // Check for suspicious userinit modifications
    if (name == L"Userinit") {
        return lowerValue.find(L"userinit.exe") == std::wstring::npos;
    }
    
    return false;
}

void SystemIntegration::checkServiceChanges(HKEY hKey) {
    Logger::log(Logger::Level::DEBUG, "Checking service changes");
    
    // In a full implementation, you'd monitor for new services
    // or modifications to existing services
}

void SystemIntegration::handleSystemShutdown() {
    Logger::log(Logger::Level::INFO, "Handling system shutdown");
    
    // Perform cleanup operations before shutdown
    // Save any pending data, close resources gracefully, etc.
}

void SystemIntegration::checkUserSessions() {
    // Monitor user session changes
    PWTS_SESSION_INFOW pSessionInfo;
    DWORD sessionCount;
    
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        for (DWORD i = 0; i < sessionCount; i++) {
            if (pSessionInfo[i].State == WTSActive) {
                // Active session detected
                // In a full implementation, you might track session changes
            }
        }
        
        WTSFreeMemory(pSessionInfo);
    }
}

SystemIntegrationStats SystemIntegration::getStatistics() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    SystemIntegrationStats stats;
    stats.initialized = m_initialized;
    stats.running = m_running;
    stats.registryMonitoringEnabled = m_registryMonitoringEnabled;
    stats.processMonitoringEnabled = m_processMonitoringEnabled;
    stats.systemEventMonitoringEnabled = m_systemEventMonitoringEnabled;
    stats.monitoredRegistryKeys = m_registryKeys.size();
    stats.systemEventHandles = m_eventHandles.size();
    
    return stats;
}
