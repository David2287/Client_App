#pragma once

#include <windows.h>
#include <wtsapi32.h>
#include <memory>
#include <unordered_map>
#include <string>
#include <mutex>

class Logger;

class SessionManager {
public:
    SessionManager(Logger* logger);
    ~SessionManager();

    bool Initialize();
    void Shutdown();

    // Session event handling
    void OnSessionLogon(DWORD sessionId);
    void OnSessionLogoff(DWORD sessionId);
    void OnSessionLock(DWORD sessionId);
    void OnSessionUnlock(DWORD sessionId);

    // Client management
    bool LaunchClientForSession(DWORD sessionId);
    bool TerminateClientForSession(DWORD sessionId);
    bool IsClientRunningForSession(DWORD sessionId) const;

    // Session enumeration
    void RefreshActiveSessions();
    std::vector<DWORD> GetActiveSessions() const;

private:
    struct SessionInfo {
        DWORD sessionId;
        std::wstring userName;
        std::wstring domainName;
        WTS_CONNECTSTATE_CLASS state;
        HANDLE clientProcess;
        DWORD clientProcessId;
        bool clientLaunched;

        SessionInfo() : sessionId(0), state(WTSDisconnected), 
                       clientProcess(nullptr), clientProcessId(0), 
                       clientLaunched(false) {}
        
        ~SessionInfo() {
            if (clientProcess && clientProcess != INVALID_HANDLE_VALUE) {
                CloseHandle(clientProcess);
            }
        }
    };

    Logger* m_logger;
    mutable std::mutex m_sessionsMutex;
    std::unordered_map<DWORD, std::unique_ptr<SessionInfo>> m_sessions;
    HWND m_notificationWindow;
    
    // Configuration
    static constexpr const wchar_t* CLIENT_EXECUTABLE = L"antivirus-client.exe";
    static constexpr const wchar_t* NOTIFICATION_WINDOW_CLASS = L"AntivirusSessionNotification";

    // Internal methods
    bool CreateNotificationWindow();
    void DestroyNotificationWindow();
    static LRESULT CALLBACK NotificationWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    bool GetSessionInfo(DWORD sessionId, SessionInfo& info);
    bool CreateClientProcess(DWORD sessionId, const std::wstring& clientPath, HANDLE& process, DWORD& processId);
    std::wstring GetClientExecutablePath() const;
    std::wstring GetUserProfilePath(DWORD sessionId) const;
    
    // Process utilities
    bool IsProcessRunning(HANDLE process) const;
    bool IsProcessRunning(DWORD processId) const;
    bool GetSessionUserToken(DWORD sessionId, HANDLE& userToken) const;
    bool EnableTokenPrivileges(HANDLE token) const;

    // Security
    bool CreateProcessSecurity(SECURITY_ATTRIBUTES& sa, SECURITY_DESCRIPTOR& sd);
    
    // Cleanup
    void CleanupSession(SessionInfo& session);
    void CleanupAllSessions();

    // No copy/move
    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;
};
