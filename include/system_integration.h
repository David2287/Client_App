#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <set>

struct SystemIntegrationStats {
    bool initialized;
    bool running;
    bool registryMonitoringEnabled;
    bool processMonitoringEnabled;
    bool systemEventMonitoringEnabled;
    size_t monitoredRegistryKeys;
    size_t systemEventHandles;
};

class SystemIntegration {
public:
    SystemIntegration();
    ~SystemIntegration();
    
    bool initialize();
    void shutdown();
    
    bool start();
    void stop();
    
    SystemIntegrationStats getStatistics() const;
    
private:
    bool registerWithSecurityCenter();
    void unregisterFromSecurityCenter();
    
    bool initializeRegistryMonitoring();
    bool initializeProcessMonitoring();
    bool initializeSystemEventMonitoring();
    
    void registryMonitoringLoop();
    void processMonitoringLoop();
    void systemEventMonitoringLoop();
    
    void processRegistryChange(DWORD keyIndex);
    void processNewProcess(DWORD processId);
    void processTerminatedProcess(DWORD processId);
    
    void getRunningProcesses(std::set<DWORD>& processes);
    bool isSuspiciousProcess(const std::string& processPath, DWORD processId);
    
    void checkAutoStartEntries(HKEY hKey, const std::wstring& keyPath);
    bool isSuspiciousAutoStartEntry(const std::wstring& name, const std::wstring& value);
    
    void checkWinlogonChanges(HKEY hKey);
    bool isSuspiciousWinlogonValue(const std::wstring& name, const std::wstring& value);
    
    void checkServiceChanges(HKEY hKey);
    
    void handleSystemShutdown();
    void checkUserSessions();
    
private:
    mutable std::mutex m_mutex;
    bool m_initialized;
    bool m_running;
    
    bool m_registryMonitoringEnabled;
    bool m_processMonitoringEnabled;
    bool m_systemEventMonitoringEnabled;
    
    std::thread m_registryThread;
    std::thread m_processThread;
    std::thread m_systemEventThread;
    
    std::vector<HKEY> m_registryKeys;
    std::vector<std::wstring> m_registryKeyPaths;
    std::vector<HANDLE> m_registryEvents;
    std::vector<HANDLE> m_eventHandles;
};
