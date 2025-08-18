#include "utils.h"
#include <windows.h>
#include <sddl.h>
#include <filesystem>
#include <codecvt>
#include <locale>

namespace Utils {

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0);
    if (size_needed == 0) {
        return std::wstring();
    }

    std::wstring wstr(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), &wstr[0], size_needed);
    return wstr;
}

std::string WideToAnsi(const std::wstring& str) {
    if (str.empty()) {
        return std::string();
    }

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), nullptr, 0, nullptr, nullptr);
    if (size_needed == 0) {
        return std::string();
    }

    std::string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), &result[0], size_needed, nullptr, nullptr);
    return result;
}

bool FileExists(const std::wstring& path) {
    try {
        return std::filesystem::exists(path) && std::filesystem::is_regular_file(path);
    }
    catch (...) {
        return false;
    }
}

bool DirectoryExists(const std::wstring& path) {
    try {
        return std::filesystem::exists(path) && std::filesystem::is_directory(path);
    }
    catch (...) {
        return false;
    }
}

uint64_t GetFileSize(const std::wstring& path) {
    try {
        if (!FileExists(path)) {
            return 0;
        }
        return static_cast<uint64_t>(std::filesystem::file_size(path));
    }
    catch (...) {
        return 0;
    }
}

std::wstring GetSystemDirectory() {
    wchar_t buffer[MAX_PATH];
    UINT result = GetSystemDirectory(buffer, MAX_PATH);
    
    if (result == 0 || result > MAX_PATH) {
        return L"C:\\Windows\\System32"; // Fallback
    }
    
    return std::wstring(buffer);
}

std::wstring GetTempDirectory() {
    wchar_t buffer[MAX_PATH];
    DWORD result = GetTempPath(MAX_PATH, buffer);
    
    if (result == 0 || result > MAX_PATH) {
        return L"C:\\Temp"; // Fallback
    }
    
    return std::wstring(buffer);
}

std::wstring GetCurrentUserSID() {
    HANDLE hToken = nullptr;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return std::wstring();
    }
    
    DWORD dwBufferSize = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwBufferSize);
    
    if (dwBufferSize == 0) {
        CloseHandle(hToken);
        return std::wstring();
    }
    
    std::vector<BYTE> buffer(dwBufferSize);
    TOKEN_USER* pTokenUser = reinterpret_cast<TOKEN_USER*>(buffer.data());
    
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
        CloseHandle(hToken);
        return std::wstring();
    }
    
    LPWSTR pszSID = nullptr;
    if (!ConvertSidToStringSid(pTokenUser->User.Sid, &pszSID)) {
        CloseHandle(hToken);
        return std::wstring();
    }
    
    std::wstring userSID(pszSID);
    LocalFree(pszSID);
    CloseHandle(hToken);
    
    return userSID;
}

bool IsUserAdmin() {
    BOOL isAdmin = FALSE;
    PSID pAdminGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(
        &ntAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &pAdminGroup)) {
        
        if (!CheckTokenMembership(nullptr, pAdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        
        FreeSid(pAdminGroup);
    }
    
    return isAdmin != FALSE;
}

bool EnableDebugPrivilege() {
    HANDLE hToken = nullptr;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return false;
    }
    
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    bool result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) != FALSE;
    
    CloseHandle(hToken);
    return result && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

} // namespace Utils
