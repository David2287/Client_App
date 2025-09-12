#define _CRT_SECURE_NO_WARNINGS          // разрешить _vsnwprintf / localtime

#include "logger.h"
#include <windows.h> 
#include <iostream>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <cstdarg>
#include <ctime>
#include <chrono>

Logger::Logger()
    : m_minLevel(LogLevel::Info)
    , m_currentFileSize(0)
    , m_maxFileSize(DEFAULT_MAX_FILE_SIZE)
    , m_maxFiles(DEFAULT_MAX_FILES)
    , m_currentFileIndex(0) {
}

Logger::~Logger() {
    Shutdown();
}

bool Logger::Initialize(const std::wstring& logPath, LogLevel minLevel) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_logPath = logPath;
    m_logDir = std::filesystem::path(logPath).parent_path();
    m_minLevel = minLevel;
    
    try {
        // Create log directory if it doesn't exist
        if (!std::filesystem::exists(m_logDir)) {
            std::filesystem::create_directories(m_logDir);
        }
        
        // Open log file
        if (!OpenLogFile()) {
            return false;
        }
        
        // Log initialization message
        Log(LogLevel::Info, L"Logger initialized");
        
        return true;
    }
    catch (const std::exception& e) {
        std::wcerr << L"Failed to initialize logger: " << e.what() << std::endl;
        return false;
    }
}

void Logger::Shutdown() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_logFile.is_open()) {
        Log(LogLevel::Info, L"Logger shutting down");
        CloseLogFile();
    }
}

void Logger::Log(LogLevel level, const std::wstring& message) {
    if (level < m_minLevel) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::wstring logMessage = GetTimestamp() + L" [" + LogLevelToString(level) + L"] " + message;
    
    WriteToFile(logMessage);
    
    // Also output to console in debug builds or for critical messages
#ifdef _DEBUG
    std::wcout << logMessage << std::endl;
#else
    if (level >= LogLevel::Error) {
        std::wcout << logMessage << std::endl;
    }
#endif
}

void Logger::LogFormat(LogLevel level, const wchar_t* format, ...) {
    if (level < m_minLevel) {
        return;
    }
    
    va_list args;
    va_start(args, format);
    
    // Calculate required buffer size
    int size = _vsnwprintf(nullptr, 0, format, args);
    va_end(args);
    
    if (size < 0) {
        Log(level, L"[FORMAT ERROR]");
        return;
    }
    
    // Format the string
    std::wstring buffer(size + 1, L'\0');
    va_start(args, format);
    _vsnwprintf(&buffer[0], size + 1, format, args);
    va_end(args);
    
    buffer.resize(size); // Remove null terminator
    Log(level, buffer);
}

void Logger::LogWin32Error(const std::wstring& operation, DWORD error) {
    LPWSTR messageBuffer = nullptr;
    
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        nullptr
    );
    
    std::wstring errorMessage = operation + L" failed with error " + std::to_wstring(error);
    if (messageBuffer) {
        errorMessage += L": " + std::wstring(messageBuffer);
        LocalFree(messageBuffer);
    }
    
    Log(LogLevel::Error, errorMessage);
}

bool Logger::OpenLogFile() {
    CloseLogFile();
    
    std::wstring fileName = GetLogFileName(m_currentFileIndex);
    m_logFile.open(fileName, std::ios::app);
    
    if (!m_logFile.is_open()) {
        return false;
    }
    
    // Set UTF-8 encoding
    m_logFile.imbue(std::locale(""));
    
    // Get current file size
    try {
        if (std::filesystem::exists(fileName)) {
            m_currentFileSize = std::filesystem::file_size(fileName);
        } else {
            m_currentFileSize = 0;
        }
    }
    catch (...) {
        m_currentFileSize = 0;
    }
    
    return true;
}

void Logger::CloseLogFile() {
    if (m_logFile.is_open()) {
        m_logFile.close();
    }
}

bool Logger::RotateLogFile() {
    CloseLogFile();
    
    // Move to next file
    m_currentFileIndex = (m_currentFileIndex + 1) % m_maxFiles;
    m_currentFileSize = 0;
    
    // Clean up old logs if necessary
    CleanupOldLogs();
    
    return OpenLogFile();
}

std::wstring Logger::GetLogFileName(int index) const {
    std::filesystem::path logPath(m_logPath);
    std::wstring baseName = logPath.stem().wstring();
    std::wstring extension = logPath.extension().wstring();
    
    if (index == 0) {
        return m_logPath;
    } else {
        return (logPath.parent_path() / (baseName + L"." + std::to_wstring(index) + extension)).wstring();
    }
}

// std::wstring Logger::GetTimestamp() const {
//     auto now = std::chrono::system_clock::now();
//     auto time_t = std::chrono::system_clock::to_time_t(now);
//     auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
//         now.time_since_epoch()) % 1000;
    
//     std::tm timeBuf{};
//     localtime_s(&timeBuf, &time_t);        // C11-вариант
//     ss << std::put_time(&timeBuf, L"%Y-%m-%d %H:%M:%S");
    
//     return ss.str();
// }

std::wstring Logger::GetTimestamp() const
{
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                  now.time_since_epoch()) % 1000;

    std::tm timeBuf{};
#if defined(_MSC_VER)
    localtime_s(&timeBuf, &time_t);
#else
    localtime_r(&time_t, &timeBuf);
#endif

    std::wstringstream ss;   // <-- добавить
    ss << std::put_time(&timeBuf, L"%Y-%m-%d %H:%M:%S");
    ss << L'.' << std::setfill(L'0') << std::setw(3) << ms.count();
    return ss.str();
}

std::wstring Logger::LogLevelToString(LogLevel level) const {
    switch (level) {
    case LogLevel::Debug:
        return L"DEBUG";
    case LogLevel::Info:
        return L"INFO ";
    case LogLevel::Warning:
        return L"WARN ";
    case LogLevel::Error:
        return L"ERROR";
    case LogLevel::Critical:
        return L"CRIT ";
    default:
        return L"UNKN ";
    }
}

void Logger::WriteToFile(const std::wstring& message) {
    if (!m_logFile.is_open()) {
        return;
    }
    
    // Check if we need to rotate the log file
    size_t messageSize = message.length() * sizeof(wchar_t);
    if (m_currentFileSize + messageSize > m_maxFileSize) {
        RotateLogFile();
    }
    
    // Write the message
    m_logFile << message << std::endl;
    m_logFile.flush();
    
    m_currentFileSize += messageSize + sizeof(wchar_t); // +1 for newline
}

void Logger::CleanupOldLogs() {
    try {
        for (int i = 0; i < m_maxFiles; ++i) {
            if (i == m_currentFileIndex) {
                continue; // Don't delete the current log file
            }
            
            std::wstring fileName = GetLogFileName(i);
            if (std::filesystem::exists(fileName)) {
                // Keep the most recent files, delete older ones
                auto lastWrite = std::filesystem::last_write_time(fileName);
                auto now = std::filesystem::file_time_type::clock::now();
                auto age = std::chrono::duration_cast<std::chrono::hours>(now - lastWrite);
                
                // Delete files older than 7 days
                if (age.count() > 24 * 7) {
                    std::filesystem::remove(fileName);
                }
            }
        }
    }
    catch (...) {
        // Ignore cleanup errors
    }
}
