#pragma once

#include <windows.h>
#include <string>
#include <memory>
#include <atomic>

class PipeServer;
class SessionManager;
class FileMonitor;
class ThreatEngine;
class Logger;

class AntivirusService {
public:
    AntivirusService();
    ~AntivirusService();

    // Service entry points
    static void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
    static void WINAPI ServiceCtrlHandler(DWORD ctrl);

    // Service operations
    bool Install();
    bool Uninstall();
    bool Start();
    bool Stop();
    bool Run();

    // Service management
    void SetServiceStatus(DWORD state, DWORD exitCode = 0, DWORD waitHint = 0);
    void ReportStatus(DWORD currentState, DWORD exitCode, DWORD waitHint);

    // Instance access
    static AntivirusService* GetInstance() { return s_instance; }

private:
    // Service configuration
    static constexpr const wchar_t* SERVICE_NAME = L"AntivirusService";
    static constexpr const wchar_t* SERVICE_DISPLAY_NAME = L"Antivirus Protection Service";
    static constexpr const wchar_t* SERVICE_DESCRIPTION = L"Provides real-time antivirus protection and scanning services";
    
    // Service handles and status
    SERVICE_STATUS_HANDLE m_statusHandle;
    SERVICE_STATUS m_status;
    HANDLE m_stopEvent;
    
    // Components
    std::unique_ptr<Logger> m_logger;
    std::unique_ptr<PipeServer> m_pipeServer;
    std::unique_ptr<SessionManager> m_sessionManager;
    std::unique_ptr<FileMonitor> m_fileMonitor;
    std::unique_ptr<ThreatEngine> m_threatEngine;
    
    // State
    std::atomic<bool> m_running;
    static AntivirusService* s_instance;
    
    // Internal methods
    bool InitializeService();
    void CleanupService();
    void ServiceWorkerThread();
    void HandleSessionChange(DWORD eventType, DWORD sessionId);
    
    // Utility methods
    std::wstring GetServicePath() const;
    bool CreateServiceSecurity(SECURITY_ATTRIBUTES& sa, SECURITY_DESCRIPTOR& sd);
    
    // No copy/move
    AntivirusService(const AntivirusService&) = delete;
    AntivirusService& operator=(const AntivirusService&) = delete;
};
