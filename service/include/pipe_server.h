#pragma once

#include <windows.h>
#include <memory>
#include <atomic>
#include <thread>
#include <vector>
#include <mutex>
#include <functional>
#include "protocol.h"

class Logger;

class PipeServer {
public:
    using MessageHandler = std::function<void(const Protocol::MessageHeader*, size_t, HANDLE)>;

    PipeServer(Logger* logger);
    ~PipeServer();

    bool Start();
    void Stop();
    bool IsRunning() const { return m_running.load(); }

    // Message handlers
    void SetMessageHandler(MessageHandler handler) { m_messageHandler = handler; }

    // Send response to client
    bool SendMessage(HANDLE hPipe, const void* message, size_t size);

private:
    // Configuration
    static constexpr DWORD PIPE_BUFFER_SIZE = 64 * 1024; // 64KB
    static constexpr DWORD MAX_PIPE_INSTANCES = 10;
    static constexpr DWORD PIPE_TIMEOUT = 5000; // 5 seconds

    // Pipe instance structure
    struct PipeInstance {
        HANDLE hPipe;
        OVERLAPPED overlapped;
        std::vector<char> buffer;
        DWORD bytesRead;
        bool connected;
        std::thread workerThread;

        PipeInstance() : hPipe(INVALID_HANDLE_VALUE), bytesRead(0), connected(false) {
            ZeroMemory(&overlapped, sizeof(overlapped));
            buffer.resize(PIPE_BUFFER_SIZE);
            overlapped.hEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
        }

        ~PipeInstance() {
            if (overlapped.hEvent != nullptr) {
                CloseHandle(overlapped.hEvent);
            }
            if (hPipe != INVALID_HANDLE_VALUE) {
                CloseHandle(hPipe);
            }
            if (workerThread.joinable()) {
                workerThread.join();
            }
        }
    };

    Logger* m_logger;
    std::atomic<bool> m_running;
    std::vector<std::unique_ptr<PipeInstance>> m_pipes;
    std::mutex m_pipesMutex;
    std::thread m_acceptThread;
    MessageHandler m_messageHandler;

    // Internal methods
    bool CreatePipeInstance(std::unique_ptr<PipeInstance>& instance);
    void AcceptConnections();
    void HandleClient(PipeInstance* instance);
    bool ProcessMessage(PipeInstance* instance, const char* data, size_t size);
    void DisconnectClient(PipeInstance* instance);

    // Security
    bool CreatePipeSecurity(SECURITY_ATTRIBUTES& sa, SECURITY_DESCRIPTOR& sd);
    bool SetPipeDACL(SECURITY_DESCRIPTOR& sd);

    // Utility
    std::wstring GetPipeName() const;
    bool ValidateMessage(const Protocol::MessageHeader* header, size_t dataSize) const;

    // No copy/move
    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;
};
