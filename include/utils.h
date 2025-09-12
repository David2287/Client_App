#pragma once

#include <windows.h>
#include <string>

namespace Utils {
    // String utilities
    std::wstring AnsiToWide(const std::string& str);
    std::string WideToAnsi(const std::wstring& str);
    
    // File utilities
    bool FileExists(const std::wstring& path);
    bool DirectoryExists(const std::wstring& path);
    uint64_t GetFileSize(const std::wstring& path);
    
    // System utilities
    std::wstring GetSystemDirectory();
    std::wstring GetTempDirectory();
    std::wstring GetCurrentUserSID();
    
    // Security utilities
    bool IsUserAdmin();
    bool EnableDebugPrivilege();

    std::wstring GetSystemDirectoryW();   // Wide-версия
}
