#pragma once

#include <windows.h>
#include <cstdint>
#include <atomic>
#include <memory>
#include <string>

class PipeServer;
class SessionManager;
class FileMonitor;
class ThreatEngine;
class Logger;

namespace Protocol {
    struct MessageHeader;
    enum class ResultCode : uint32_t;
}

class AntivirusService {
public:
    AntivirusService();
    ~AntivirusService();

    static void WINAPI ServiceMain(DWORD argc, LPTSTR* argv);
    static void WINAPI ServiceCtrlHandler(DWORD ctrl);

    bool Install();
    bool Uninstall();
    bool Start();
    bool Stop();
    bool Run();

    void ReportServiceStatus(DWORD state, DWORD exitCode = 0, DWORD waitHint = 0);
    static AntivirusService* GetInstance() { return s_instance; }

private:
    static constexpr const wchar_t* SERVICE_NAME = L"AntivirusService";
    static constexpr const wchar_t* SERVICE_DISPLAY_NAME = L"Antivirus Protection Service";
    static constexpr const wchar_t* SERVICE_DESC_TEXT = L"Provides real-time antivirus protection and scanning services";

    SERVICE_STATUS_HANDLE m_statusHandle{};
    SERVICE_STATUS        m_status{};
    HANDLE                m_stopEvent{};
    std::atomic<bool>     m_running{false};
    static AntivirusService* s_instance;

    std::unique_ptr<Logger>        m_logger;
    std::unique_ptr<PipeServer>    m_pipeServer;
    std::unique_ptr<SessionManager> m_sessionManager;
    std::unique_ptr<FileMonitor>   m_fileMonitor;
    std::unique_ptr<ThreatEngine>  m_threatEngine;

    bool InitializeService();
    void CleanupService();
    void ServiceWorkerThread();
    void HandleSessionChange(DWORD eventType, DWORD sessionId);

    void HandleClientMessage(const Protocol::MessageHeader* header, size_t size, HANDLE hPipe);
    void HandleStatusRequest (const Protocol::MessageHeader* header, size_t size, HANDLE hPipe);
    void HandleAuthRequest   (const Protocol::MessageHeader* header, size_t size, HANDLE hPipe);
    void HandleScanRequest   (const Protocol::MessageHeader* header, size_t size, HANDLE hPipe);
    void HandleSettingsRequest(const Protocol::MessageHeader* header, size_t size, HANDLE hPipe);
    void SendErrorResponse   (HANDLE hPipe, uint32_t seq, Protocol::ResultCode code);

    std::wstring GetServicePath() const;
    bool CreateServiceSecurity(SECURITY_ATTRIBUTES& sa, SECURITY_DESCRIPTOR& sd);
    void RefreshActiveSessions();

    AntivirusService(const AntivirusService&) = delete;
    AntivirusService& operator=(const AntivirusService&) = delete;
};