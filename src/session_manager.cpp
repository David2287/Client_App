// session_manager.cpp
#include "session_manager.h"
#include "logger.h"
#include <sddl.h>      // ConvertStringSecurityDescriptorToSecurityDescriptorW
#include <sstream>
#include <vector>
#include <userenv.h>
#include <tlhelp32.h>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")

namespace
{
    const wchar_t* WINDOW_CLASS_NAME = L"AntivirusSessionNotification";
}

SessionManager::SessionManager(Logger* logger)
    : m_logger(logger)
    , m_notificationWindow(nullptr)
{
    if (!m_logger)
        throw std::invalid_argument("logger");
}

SessionManager::~SessionManager()
{
    Shutdown();
}

bool SessionManager::Initialize()
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    size_t count = 0;
    m_logger->LogFormat(LogLevel::Info, L"essionManager: initializing", count);

    RefreshActiveSessions();

    if (!CreateNotificationWindow())
    {
        // m_logger->Error(L"SessionManager: failed to create notification window");
        m_logger->LogFormat(LogLevel::Error, L"SessionManager: failed to create notification window");
        return false;
    }

    m_logger->Info(L"SessionManager: initialized");
    return true;
}

void SessionManager::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    // m_logger->Info(L"SessionManager: shutting down");
    m_logger->LogFormat(LogLevel::Info, L"SessionManager: shutting down");

    DestroyNotificationWindow();
    CleanupAllSessions();
}

void SessionManager::OnSessionLogon(DWORD sessionId)
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    // m_logger->Info(L"SessionManager: session %lu logon", sessionId);
    m_logger->LogFormat(LogLevel::Info, L"SessionManager: session %lu logon", sessionId);

    auto& info = m_sessions[sessionId];
    if (!info)
    {
        info = std::make_unique<SessionInfo>();
        info->sessionId = sessionId;
    }

    GetSessionInfo(sessionId, *info);
    LaunchClientForSession(sessionId);
}

void SessionManager::OnSessionLogoff(DWORD sessionId)
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    // m_logger->Info(L"SessionManager: session %lu logoff", sessionId);
    m_logger->LogFormat(LogLevel::Info, L"SessionManager: session %lu logoff", sessionId);

    auto it = m_sessions.find(sessionId);
    if (it != m_sessions.end())
    {
        TerminateClientForSession(sessionId);
        m_sessions.erase(it);
    }
}

void SessionManager::OnSessionLock(DWORD sessionId)
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    // m_logger->Info(L"SessionManager: session %lu lock", sessionId);
    m_logger->LogFormat(LogLevel::Info, L"SessionManager: session %lu lock", sessionId);
}

void SessionManager::OnSessionUnlock(DWORD sessionId)
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    // m_logger->Info(L"SessionManager: session %lu unlock", sessionId);
    m_logger->LogFormat(LogLevel::Info, L"SessionManager: session %lu unlock", sessionId);
}

bool SessionManager::LaunchClientForSession(DWORD sessionId)
{
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end() || it->second->clientLaunched)
        return false;

    std::wstring clientPath = GetClientExecutablePath();
    if (clientPath.empty())
    {
        // m_logger->Error(L"SessionManager: client executable not found");
        m_logger->LogFormat(LogLevel::Error, L"SessionManager: client executable not found");
        return false;
    }

    HANDLE process = nullptr;
    DWORD  processId = 0;
    if (!CreateClientProcess(sessionId, clientPath, process, processId))
    {
        // m_logger->Error(L"SessionManager: failed to create client process for session %lu", sessionId);
        m_logger->LogFormat(LogLevel::Error, L"SessionManager: failed to create client process for session %lu", sessionId);
        return false;
    }

    it->second->clientProcess   = process;
    it->second->clientProcessId = processId;
    it->second->clientLaunched  = true;

    // m_logger->Info(L"SessionManager: launched client for session %lu (PID %lu)", sessionId, processId);
    m_logger->LogFormat(LogLevel::Info, L"SessionManager: launched client for session %lu (PID %lu)", sessionId, processId);
    return true;
}

bool SessionManager::TerminateClientForSession(DWORD sessionId)
{
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end() || !it->second->clientLaunched)
        return false;

    SessionInfo& info = *it->second;
    if (info.clientProcess && info.clientProcess != INVALID_HANDLE_VALUE)
    {
        if (IsProcessRunning(info.clientProcess))
        {
            TerminateProcess(info.clientProcess, 0);
            WaitForSingleObject(info.clientProcess, 5000);
        }
        CloseHandle(info.clientProcess);
        info.clientProcess   = nullptr;
        info.clientProcessId = 0;
    }
    info.clientLaunched = false;
    // m_logger->Info(L"SessionManager: terminated client for session %lu", sessionId);
    m_logger->LogFormat(LogLevel::Info, L"SessionManager: terminated client for session %lu", sessionId);
    return true;
}

bool SessionManager::IsClientRunningForSession(DWORD sessionId) const
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end() || !it->second->clientLaunched)
        return false;
    return IsProcessRunning(it->second->clientProcess);
}

void SessionManager::RefreshActiveSessions()
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    m_sessions.clear();

    PWTS_SESSION_INFO pSessionInfo = nullptr;
    DWORD sessionCount = 0;

    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount))
    {
        for (DWORD i = 0; i < sessionCount; ++i)
        {
            DWORD sessionId = pSessionInfo[i].SessionId;
            auto info = std::make_unique<SessionInfo>();
            info->sessionId = sessionId;
            if (GetSessionInfo(sessionId, *info))
                m_sessions[sessionId] = std::move(info);
        }
        WTSFreeMemory(pSessionInfo);
    }
}

std::vector<DWORD> SessionManager::GetActiveSessions() const
{
    std::lock_guard<std::mutex> lock(m_sessionsMutex);
    std::vector<DWORD> ids;
    ids.reserve(m_sessions.size());
    for (const auto& pair : m_sessions)
        ids.push_back(pair.first);
    return ids;
}

bool SessionManager::CreateNotificationWindow()
{
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = NotificationWndProc;
    wc.hInstance     = GetModuleHandle(nullptr);
    wc.lpszClassName = WINDOW_CLASS_NAME;

    if (!RegisterClassExW(&wc))
    {
        // m_logger->Error(L"SessionManager: RegisterClassEx failed, le=%lu", GetLastError());
        m_logger->LogFormat(LogLevel::Error, L"SessionManager: RegisterClassEx failed, le=%lu", GetLastError());
        return false;
    }

    m_notificationWindow = CreateWindowExW(
        0, WINDOW_CLASS_NAME, L"Antivirus Session Notification",
        0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, this);

    if (!m_notificationWindow)
    {
        // m_logger->Error(L"SessionManager: CreateWindowEx failed, le=%lu", GetLastError());
        m_logger->LogFormat(LogLevel::Error, L"SessionManager: CreateWindowEx failed, le=%lu", GetLastError());
        return false;
    }
    return true;
}

void SessionManager::DestroyNotificationWindow()
{
    if (m_notificationWindow)
    {
        DestroyWindow(m_notificationWindow);
        m_notificationWindow = nullptr;
    }
    UnregisterClassW(WINDOW_CLASS_NAME, GetModuleHandle(nullptr));
}

LRESULT CALLBACK SessionManager::NotificationWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == WM_CREATE)
    {
        auto* cs = reinterpret_cast<CREATESTRUCT*>(lParam);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams));
        return 0;
    }

    auto* mgr = reinterpret_cast<SessionManager*>(GetWindowLongPtr(hwnd, GWLP_USERDATA));
    if (!mgr) return DefWindowProc(hwnd, msg, wParam, lParam);

    switch (msg)
    {
    case WM_WTSSESSION_CHANGE:
    {
        DWORD sessionId = static_cast<DWORD>(lParam);
        switch (wParam)
        {
        case WTS_SESSION_LOGON:  mgr->OnSessionLogon(sessionId);   break;
        case WTS_SESSION_LOGOFF: mgr->OnSessionLogoff(sessionId);  break;
        case WTS_SESSION_LOCK:   mgr->OnSessionLock(sessionId);    break;
        case WTS_SESSION_UNLOCK: mgr->OnSessionUnlock(sessionId);  break;
        }
    }
    return 0;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

bool SessionManager::GetSessionInfo(DWORD sessionId, SessionInfo& info)
{
    info.sessionId = sessionId;

    LPTSTR buffer = nullptr;
    DWORD  bytes = 0;

    if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &buffer, &bytes))
    {
        info.userName = buffer;
        WTSFreeMemory(buffer);
    }

    if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &buffer, &bytes))
    {
        info.domainName = buffer;
        WTSFreeMemory(buffer);
    }

    if (WTSQuerySessionInformation(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSConnectState, &buffer, &bytes))
    {
        info.state = *reinterpret_cast<WTS_CONNECTSTATE_CLASS*>(buffer);
        WTSFreeMemory(buffer);
    }
    return true;
}

bool SessionManager::CreateClientProcess(DWORD sessionId,
                                         const std::wstring& clientPath,
                                         HANDLE& process,
                                         DWORD& processId)
{
    HANDLE userToken = nullptr;
    if (!GetSessionUserToken(sessionId, userToken))
        return false;

    EnableTokenPrivileges(userToken);

    void* env = nullptr;
    if (!CreateEnvironmentBlock(&env, userToken, FALSE))
    {
        CloseHandle(userToken);
        return false;
    }

    std::wstring cmdLine = L"\"" + clientPath + L"\"";
    STARTUPINFOW        si = {};
    PROCESS_INFORMATION pi = {};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    SECURITY_DESCRIPTOR sd{};
    SECURITY_ATTRIBUTES   sa{ sizeof(sa), &sd, FALSE };
    CreateProcessSecurity(sa, sd);

    BOOL r = CreateProcessAsUserW(userToken,
                                  nullptr,
                                  &cmdLine[0],
                                  &sa,
                                  nullptr,
                                  FALSE,
                                  CREATE_UNICODE_ENVIRONMENT,
                                  env,
                                  nullptr,
                                  &si,
                                  &pi);

    DestroyEnvironmentBlock(env);
    CloseHandle(userToken);

    if (!r)
    {
        // m_logger->Error(L"CreateProcessAsUser failed, le=%lu", GetLastError());
        m_logger->LogFormat(LogLevel::Error, L"CreateProcessAsUser failed, le=%lu", GetLastError());
        return false;
    }

    process   = pi.hProcess;
    processId = pi.dwProcessId;
    CloseHandle(pi.hThread);
    return true;
}

std::wstring SessionManager::GetClientExecutablePath() const
{
    wchar_t modulePath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, modulePath, MAX_PATH))
        return {};
    std::wstring dir = modulePath;
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        dir.erase(pos + 1);
    return dir + CLIENT_EXECUTABLE;
}

std::wstring SessionManager::GetUserProfilePath(DWORD sessionId) const
{
    HANDLE token = nullptr;
    if (!GetSessionUserToken(sessionId, token))
        return {};

    wchar_t* path = nullptr;
    if (!GetUserProfileDirectoryW(token, nullptr, 0))
    {
        CloseHandle(token);
        return {};
    }
    DWORD len = 0;
    GetUserProfileDirectoryW(token, nullptr, &len);
    std::wstring profile(len, L'\0');
    if (GetUserProfileDirectoryW(token, &profile[0], &len))
        profile.resize(len - 1);
    else
        profile.clear();
    CloseHandle(token);
    return profile;
}

bool SessionManager::IsProcessRunning(HANDLE process) const
{
    if (!process || process == INVALID_HANDLE_VALUE)
        return false;
    DWORD code = 0;
    return GetExitCodeProcess(process, &code) && code == STILL_ACTIVE;
}

bool SessionManager::IsProcessRunning(DWORD processId) const
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    bool found = false;
    for (BOOL b = Process32FirstW(snap, &pe);
         b;
         b = Process32NextW(snap, &pe))
    {
        if (pe.th32ProcessID == processId)
        {
            found = true;
            break;
        }
    }
    CloseHandle(snap);
    return found;
}

bool SessionManager::GetSessionUserToken(DWORD sessionId, HANDLE& userToken) const
{
    if (WTSQueryUserToken(sessionId, &userToken))
        return true;
    // m_logger->Error(L"WTSQueryUserToken failed for session %lu, le=%lu", sessionId, GetLastError());
    m_logger->LogFormat(LogLevel::Error, L"WTSQueryUserToken failed for session %lu, le=%lu", sessionId, GetLastError());
    return false;
}

bool SessionManager::EnableTokenPrivileges(HANDLE token) const
{
    struct
    {
        DWORD count;
        LUID_AND_ATTRIBUTES privs[3];
    } tp = { 3, {
        { {0}, SE_PRIVILEGE_ENABLED },
        { {0}, SE_PRIVILEGE_ENABLED },
        { {0}, SE_PRIVILEGE_ENABLED }
    }};

    LookupPrivilegeValueW(nullptr, SE_INCREASE_QUOTA_NAME, &tp.privs[0].Luid);
    LookupPrivilegeValueW(nullptr, SE_ASSIGNPRIMARYTOKEN_NAME, &tp.privs[1].Luid);
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &tp.privs[2].Luid);

    return AdjustTokenPrivileges(token, FALSE,
                                 reinterpret_cast<PTOKEN_PRIVILEGES>(&tp),
                                 0, nullptr, nullptr) &&
           GetLastError() == ERROR_SUCCESS;
}

bool SessionManager::CreateProcessSecurity(SECURITY_ATTRIBUTES& sa,
                                           SECURITY_DESCRIPTOR& sd)
{
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        return false;
    return ConvertStringSecurityDescriptorToSecurityDescriptorW(
        L"D:(A;;GA;;;WD)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr) == TRUE;
}

void SessionManager::CleanupSession(SessionInfo& session)
{
    TerminateClientForSession(session.sessionId);
}

void SessionManager::CleanupAllSessions()
{
    for (auto& pair : m_sessions)
        CleanupSession(*pair.second);
}