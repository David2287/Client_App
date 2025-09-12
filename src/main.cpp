#include <windows.h>
#include <iostream>
#include <memory>
#include <algorithm>
#include "service.h"
#include "logger.h"


void PrintUsage() {
    std::wcout << L"Antivirus Service Usage:\n";
    std::wcout << L"  AntivirusService.exe             - Run as service (default)\n";
    std::wcout << L"  AntivirusService.exe -install    - Install service\n";
    std::wcout << L"  AntivirusService.exe -uninstall  - Uninstall service\n";
    std::wcout << L"  AntivirusService.exe -console    - Run in console mode\n";
    std::wcout << L"  AntivirusService.exe -help       - Show this help\n";
}

int wmain(int argc, wchar_t* argv[]) {
    // Enable console output for service debugging
    if (argc > 1) {
        AllocConsole();
        freopen_s(reinterpret_cast<FILE**>(stdout), "CONOUT$", "w", stdout);
        freopen_s(reinterpret_cast<FILE**>(stderr), "CONOUT$", "w", stderr);
        freopen_s(reinterpret_cast<FILE**>(stdin), "CONIN$", "r", stdin);
        std::wcout.clear();
        std::wcin.clear();
        std::wcerr.clear();
    }

    try {
        auto service = std::make_unique<AntivirusService>();

        // Parse command line arguments
        if (argc == 1) {
            // No arguments - run as service
            SERVICE_TABLE_ENTRY serviceTable[] = {
                { const_cast<LPWSTR>(L"AntivirusService"), AntivirusService::ServiceMain },
                { nullptr, nullptr }
            };

            if (!StartServiceCtrlDispatcher(serviceTable)) {
                DWORD error = GetLastError();
                if (error == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
                    std::wcerr << L"Error: Cannot start service. Use -console to run in console mode.\n";
                    std::wcerr << L"Run with -help for usage information.\n";
                } else {
                    std::wcerr << L"Error starting service dispatcher: " << error << L"\n";
                }
                return 1;
            }
            return 0;
        }

        // Handle command line arguments
        std::wstring arg = argv[1];
        std::transform(arg.begin(), arg.end(), arg.begin(), ::towlower);

        if (arg == L"-install") {
            std::wcout << L"Installing Antivirus Service...\n";
            if (service->Install()) {
                std::wcout << L"Service installed successfully.\n";
                return 0;
            } else {
                std::wcerr << L"Failed to install service.\n";
                return 1;
            }
        }
        else if (arg == L"-uninstall") {
            std::wcout << L"Uninstalling Antivirus Service...\n";
            if (service->Uninstall()) {
                std::wcout << L"Service uninstalled successfully.\n";
                return 0;
            } else {
                std::wcerr << L"Failed to uninstall service.\n";
                return 1;
            }
        }
        else if (arg == L"-console") {
            std::wcout << L"Running Antivirus Service in console mode...\n";
            std::wcout << L"Press Ctrl+C to stop.\n\n";
            
            // Set console control handler
            SetConsoleCtrlHandler([](DWORD dwCtrlType) -> BOOL {
                switch (dwCtrlType) {
                case CTRL_C_EVENT:
                case CTRL_BREAK_EVENT:
                case CTRL_CLOSE_EVENT:
                case CTRL_SHUTDOWN_EVENT:
                    std::wcout << L"\nShutting down service...\n";
                    if (auto* instance = AntivirusService::GetInstance()) {
                        instance->Stop();
                    }
                    return TRUE;
                default:
                    return FALSE;
                }
            }, TRUE);

            // Run service in console mode
            if (service->Run()) {
                std::wcout << L"Service stopped gracefully.\n";
                return 0;
            } else {
                std::wcerr << L"Service encountered an error.\n";
                return 1;
            }
        }
        else if (arg == L"-help" || arg == L"-h" || arg == L"/?") {
            PrintUsage();
            return 0;
        }
        else {
            std::wcerr << L"Unknown argument: " << argv[1] << L"\n\n";
            PrintUsage();
            return 1;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    catch (...) {
        std::wcerr << L"Unknown exception occurred.\n";
        return 1;
    }

    return 0;
}
