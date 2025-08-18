#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <memory>

enum class LogLevel {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    Critical = 4
};

class Logger {
public:
    Logger();
    ~Logger();

    bool Initialize(const std::wstring& logPath, LogLevel minLevel = LogLevel::Info);
    void Shutdown();

    // Logging methods
    void Log(LogLevel level, const std::wstring& message);
    void LogFormat(LogLevel level, const wchar_t* format, ...);

    // Convenience methods
    void Debug(const std::wstring& message) { Log(LogLevel::Debug, message); }
    void Info(const std::wstring& message) { Log(LogLevel::Info, message); }
    void Warning(const std::wstring& message) { Log(LogLevel::Warning, message); }
    void Error(const std::wstring& message) { Log(LogLevel::Error, message); }
    void Critical(const std::wstring& message) { Log(LogLevel::Critical, message); }

    // Windows error logging
    void LogWin32Error(const std::wstring& operation, DWORD error = GetLastError());
    
    // Configuration
    void SetLogLevel(LogLevel level) { m_minLevel = level; }
    void SetMaxFileSize(size_t maxSize) { m_maxFileSize = maxSize; }
    void SetMaxFiles(int maxFiles) { m_maxFiles = maxFiles; }

private:
    std::mutex m_mutex;
    std::wofstream m_logFile;
    std::wstring m_logPath;
    std::wstring m_logDir;
    LogLevel m_minLevel;
    size_t m_currentFileSize;
    size_t m_maxFileSize;
    int m_maxFiles;
    int m_currentFileIndex;

    // Internal methods
    bool OpenLogFile();
    void CloseLogFile();
    bool RotateLogFile();
    std::wstring GetLogFileName(int index = 0) const;
    std::wstring GetTimestamp() const;
    std::wstring LogLevelToString(LogLevel level) const;
    void WriteToFile(const std::wstring& message);
    void CleanupOldLogs();

    // Default configuration
    static constexpr size_t DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
    static constexpr int DEFAULT_MAX_FILES = 5;

    // No copy/move
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
};
