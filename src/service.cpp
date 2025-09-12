#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4100)   // argc, argv, sa

#include "service.h"
#include "pipe_server.h"
#include "session_manager.h"
#include "file_monitor.h"
#include "threat_engine.h"
#include "logger.h"
#include "utils.h"
#include "protocol.h"
#include <windows.h>
#include <iostream>
#include <thread>
#include <filesystem>

// Static member initialization
AntivirusService* AntivirusService::s_instance = nullptr;

AntivirusService::AntivirusService()
    : m_statusHandle(nullptr)
    , m_stopEvent(nullptr)
    , m_running(false) {

    // Initialize service status
    ZeroMemory(&m_status, sizeof(m_status));
    m_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    m_status.dwCurrentState = SERVICE_STOPPED;
    m_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    s_instance = this;
}

AntivirusService::~AntivirusService() {
    CleanupService();
    s_instance = nullptr;
}

void WINAPI AntivirusService::ServiceMain(DWORD argc, LPTSTR* argv) {
    if (s_instance) {
        s_instance->Run();
    }
}

void WINAPI AntivirusService::ServiceCtrlHandler(DWORD ctrl) {
    if (!s_instance) return;

    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        s_instance->ReportServiceStatus(SERVICE_STOP_PENDING);
        s_instance->Stop();
        break;
    case SERVICE_CONTROL_INTERROGATE:
        s_instance->ReportServiceStatus(s_instance->m_status.dwCurrentState);
        break;
    default:
        break;
    }
}

bool AntivirusService::Install() {
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        std::wcerr << L"Error: Cannot open Service Control Manager. " << GetLastError() << std::endl;
        return false;
    }

    std::wstring servicePath = GetServicePath();
    if (servicePath.empty()) {
        CloseServiceHandle(scManager);
        std::wcerr << L"Error: Cannot determine service executable path." << std::endl;
        return false;
    }

    SC_HANDLE service = CreateService(
        scManager,
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        servicePath.c_str(),
        nullptr,    // Load ordering group
        nullptr,    // Tag ID
        nullptr,    // Dependencies
        nullptr,    // Service start name (LocalSystem)
        nullptr     // Password
    );

    if (!service) {
        DWORD error = GetLastError();
        CloseServiceHandle(scManager);
        if (error == ERROR_SERVICE_EXISTS) {
            std::wcerr << L"Service already exists." << std::endl;
        } else {
            std::wcerr << L"Error creating service: " << error << std::endl;
        }
        return false;
    }

    SERVICE_DESCRIPTION desc{};
    desc.lpDescription = const_cast<LPWSTR>(SERVICE_DESC_TEXT);
    ChangeServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, &desc);

    // Configure service to restart on failure
    SC_ACTION actions[3];
    actions[0].Type = SC_ACTION_RESTART;
    actions[0].Delay = 30000;  // 30 seconds
    actions[1].Type = SC_ACTION_RESTART;
    actions[1].Delay = 60000;  // 1 minute
    actions[2].Type = SC_ACTION_NONE;
    actions[2].Delay = 0;

    SERVICE_FAILURE_ACTIONS failureActions;
    failureActions.dwResetPeriod = 86400; // Reset after 24 hours
    failureActions.lpRebootMsg = nullptr;
    failureActions.lpCommand = nullptr;
    failureActions.cActions = 3;
    failureActions.lpsaActions = actions;

    ChangeServiceConfig2(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);

    return true;
}

bool AntivirusService::Uninstall() {
    SC_HANDLE scManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) {
        std::wcerr << L"Error: Cannot open Service Control Manager. " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE service = OpenService(scManager, SERVICE_NAME, DELETE);
    if (!service) {
        DWORD error = GetLastError();
        CloseServiceHandle(scManager);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::wcerr << L"Service does not exist." << std::endl;
        } else {
            std::wcerr << L"Error opening service: " << error << std::endl;
        }
        return false;
    }

    // Stop service if running
    SERVICE_STATUS status;
    if (QueryServiceStatus(service, &status) && status.dwCurrentState != SERVICE_STOPPED) {
        std::wcout << L"Stopping service..." << std::endl;
        ControlService(service, SERVICE_CONTROL_STOP, &status);

        // Wait for service to stop
        for (int i = 0; i < 30; ++i) {
            if (!QueryServiceStatus(service, &status) || status.dwCurrentState == SERVICE_STOPPED) {
                break;
            }
            Sleep(1000);
        }
    }

    bool success = DeleteService(service) != FALSE;
    if (!success) {
        std::wcerr << L"Error deleting service: " << GetLastError() << std::endl;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);

    return success;
}

bool AntivirusService::Start() {
    return Run();
}

bool AntivirusService::Stop() {
    m_running.store(false);

    if (m_stopEvent) {
        SetEvent(m_stopEvent);
    }

    ReportServiceStatus(SERVICE_STOP_PENDING);
    return true;
}

bool AntivirusService::Run() {
    // Register service control handler
    m_statusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (!m_statusHandle) {
        return false;
    }

    ReportServiceStatus(SERVICE_START_PENDING);

    // Initialize service
    if (!InitializeService()) {
        ReportServiceStatus(SERVICE_STOPPED);
        return false;
    }

    ReportServiceStatus(SERVICE_RUNNING);
    m_running.store(true);

    // Create stop event
    m_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!m_stopEvent) {
        CleanupService();
        ReportServiceStatus(SERVICE_STOPPED);
        return false;
    }

    // Start service worker thread
    std::thread workerThread(&AntivirusService::ServiceWorkerThread, this);

    // Wait for stop event
    WaitForSingleObject(m_stopEvent, INFINITE);

    // Cleanup
    m_running.store(false);
    if (workerThread.joinable()) {
        workerThread.join();
    }

    CleanupService();
    ReportServiceStatus(SERVICE_STOPPED);

    return true;
}

// service.cpp
void AntivirusService::ReportServiceStatus(DWORD currentState, DWORD exitCode, DWORD waitHint)
{
    static DWORD checkPoint = 1;

    m_status.dwCurrentState  = currentState;
    m_status.dwWin32ExitCode = exitCode;
    m_status.dwWaitHint      = waitHint;

    if (currentState == SERVICE_START_PENDING || currentState == SERVICE_STOP_PENDING) {
        m_status.dwCheckPoint = checkPoint++;
    } else {
        m_status.dwCheckPoint = 0;
    }

    if (m_statusHandle) {
        ::SetServiceStatus(m_statusHandle, &m_status);
    }
}

bool AntivirusService::InitializeService() {
    try {
        // Create logs directory
        std::wstring logDir = L"C:\\ProgramData\\AntivirusService\\Logs";
        std::filesystem::create_directories(logDir);

        // Initialize logger
        m_logger = std::make_unique<Logger>();
        if (!m_logger->Initialize(logDir + L"\\service.log", LogLevel::Info)) {
            return false;
        }

        m_logger->Info(L"Antivirus Service starting...");

        // Initialize threat engine
        m_threatEngine = std::make_unique<ThreatEngine>(m_logger.get());
        if (!m_threatEngine->Initialize()) {
            m_logger->Error(L"Failed to initialize threat engine");
            return false;
        }

        // Initialize file monitor
        m_fileMonitor = std::make_unique<FileMonitor>(m_logger.get(), m_threatEngine.get());
        if (!m_fileMonitor->Initialize()) {
            m_logger->Error(L"Failed to initialize file monitor");
            return false;
        }

        // Initialize session manager
        m_sessionManager = std::make_unique<SessionManager>(m_logger.get());
        if (!m_sessionManager->Initialize()) {
            m_logger->Error(L"Failed to initialize session manager");
            return false;
        }

        // Initialize pipe server
        m_pipeServer = std::make_unique<PipeServer>(m_logger.get());
        m_pipeServer->SetMessageHandler([this](const Protocol::MessageHeader* header, size_t size, HANDLE hPipe) {
            HandleClientMessage(header, size, hPipe);
        });

        if (!m_pipeServer->Start()) {
            m_logger->Error(L"Failed to start pipe server");
            return false;
        }

        m_logger->Info(L"Antivirus Service initialized successfully");
        return true;
    }
    catch (const std::exception& e) {
        if (m_logger) {
            m_logger->LogFormat(LogLevel::Error, L"Exception during service initialization: %S", e.what());
        }
        return false;
    }
}

void AntivirusService::CleanupService() {
    if (m_logger) {
        m_logger->Info(L"Antivirus Service shutting down...");
    }

    if (m_pipeServer) {
        m_pipeServer->Stop();
        m_pipeServer.reset();
    }

    if (m_sessionManager) {
        m_sessionManager->Shutdown();
        m_sessionManager.reset();
    }

    if (m_fileMonitor) {
        m_fileMonitor->Shutdown();
        m_fileMonitor.reset();
    }

    if (m_threatEngine) {
        m_threatEngine->Shutdown();
        m_threatEngine.reset();
    }

    if (m_stopEvent) {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }

    if (m_logger) {
        m_logger->Info(L"Antivirus Service shutdown complete");
        m_logger->Shutdown();
        m_logger.reset();
    }
}

void AntivirusService::ServiceWorkerThread() {
    if (!m_logger) return;

    m_logger->Info(L"Service worker thread started");

    try {
        while (m_running.load()) {
            // Perform periodic tasks
            if (m_sessionManager) {
                m_sessionManager->RefreshActiveSessions();
            }

            // Sleep for a short period
            Sleep(5000); // 5 seconds
        }
    }
    catch (const std::exception& e) {
        m_logger->LogFormat(LogLevel::Error, L"Exception in worker thread: %S", e.what());
    }

    m_logger->Info(L"Service worker thread stopped");
}

void AntivirusService::HandleClientMessage(const Protocol::MessageHeader* header, size_t size, HANDLE hPipe) {
    if (!header || !m_logger) return;

    m_logger->LogFormat(LogLevel::Debug, L"Received message type %d from client", static_cast<int>(header->type));

    // Handle different message types
    switch (header->type) {
    case Protocol::MessageType::STATUS_REQUEST:
        HandleStatusRequest(header, size, hPipe);
        break;
    case Protocol::MessageType::AUTH_REQUEST:
        HandleAuthRequest(header, size, hPipe);
        break;
    case Protocol::MessageType::SCAN_REQUEST:
        HandleScanRequest(header, size, hPipe);
        break;
    case Protocol::MessageType::SETTINGS_GET:
    case Protocol::MessageType::SETTINGS_SET:
        HandleSettingsRequest(header, size, hPipe);
        break;
    default:
        m_logger->LogFormat(LogLevel::Warning, L"Unknown message type: %d", static_cast<int>(header->type));
        SendErrorResponse(hPipe, header->sequence, Protocol::ResultCode::INVALID_REQUEST);
        break;
    }
}

std::wstring AntivirusService::GetServicePath() const {
    wchar_t buffer[MAX_PATH];
    DWORD size = GetModuleFileName(nullptr, buffer, MAX_PATH);
    if (size == 0 || size == MAX_PATH) {
        return L"";
    }
    return std::wstring(buffer);
}

void AntivirusService::HandleStatusRequest (const Protocol::MessageHeader* header,
                                            size_t size, HANDLE hPipe)
{
    if (!header || !m_logger) return;
    m_logger->LogFormat(LogLevel::Debug, L"STATUS_REQUEST stub");
    // TODO: реальный ответ
}

void AntivirusService::HandleAuthRequest   (const Protocol::MessageHeader* header,
                                            size_t size, HANDLE hPipe)
{
    m_logger->LogFormat(LogLevel::Debug, L"AUTH_REQUEST stub");
}

void AntivirusService::HandleScanRequest   (const Protocol::MessageHeader* header,
                                            size_t size, HANDLE hPipe)
{
    m_logger->LogFormat(LogLevel::Debug, L"SCAN_REQUEST stub");
}

void AntivirusService::HandleSettingsRequest(const Protocol::MessageHeader* header,
                                             size_t size, HANDLE hPipe)
{
    m_logger->LogFormat(LogLevel::Debug, L"SETTINGS_REQUEST stub");
}

void AntivirusService::SendErrorResponse   (HANDLE hPipe,
                                            uint32_t seq,
                                            Protocol::ResultCode code)
{
    if (!m_logger) return;
    m_logger->LogFormat(LogLevel::Warning, L"SendErrorResponse: seq=%u code=%u", seq, static_cast<uint32_t>(code));
    // TODO: записать в pipe короткий ответ-ошибку
}