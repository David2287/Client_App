#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4100)   // argc, argv, sa

#include "protocol.h"   // Protocol::MESSAGE_MAGIC, MessageHeader::size
#include "pipe_server.h"
#include "logger.h"
#include <sddl.h>          // SDDL_REVISION_1
#include <sstream>
#include <algorithm>
#include <sstream>
#include <vector>
#include <chrono>
#include <thread>

#pragma comment(lib, "Advapi32.lib")

namespace
{
    const wchar_t PIPE_NAME_PATTERN[] = L"\\\\.\\pipe\\MyServicePipe";
}

// DWORD dw = GetLastError();

//------------------------------------------------------------------------------
PipeServer::PipeServer(Logger* logger)
    : m_logger(logger), m_running(false)
{
    if (!m_logger) throw std::invalid_argument("logger");
}
PipeServer::~PipeServer() { Stop(); }

//------------------------------------------------------------------------------
bool PipeServer::Start()
{
    DWORD dw = GetLastError();

    std::lock_guard<std::mutex> lock(m_pipesMutex);
    if (m_running.exchange(true)) return true;

    // m_logger->Info(L"PipeServer: starting");
    m_logger->LogFormat(LogLevel::Info, L"PipeServer: starting");

    for (DWORD i = 0; i < MAX_PIPE_INSTANCES; ++i)
    {
        auto inst = std::make_unique<PipeInstance>();
        if (!CreatePipeInstance(inst)) { m_running = false; return false; }
        m_pipes.emplace_back(std::move(inst));
    }
    m_acceptThread = std::thread(&PipeServer::AcceptConnections, this);
    return true;
}
void PipeServer::Stop()
{
    if (!m_running.exchange(false)) return;
    // m_logger->Info(L"PipeServer: stopping");
    m_logger->LogFormat(LogLevel::Info, L"PipeServer: stopping");

    {   // disconnect every live pipe
        std::lock_guard<std::mutex> lock(m_pipesMutex);
        for (auto& p : m_pipes)
            if (p->connected && p->hPipe != INVALID_HANDLE_VALUE)
                DisconnectNamedPipe(p->hPipe);
    }
    if (m_acceptThread.joinable()) m_acceptThread.join();

    std::lock_guard<std::mutex> lock(m_pipesMutex);
    m_pipes.clear();
}
bool PipeServer::SendMessage(HANDLE hPipe, const void* msg, size_t sz)
{
    if (hPipe == INVALID_HANDLE_VALUE || !msg || !sz) return false;
    DWORD written = 0;
    if (!WriteFile(hPipe, msg, static_cast<DWORD>(sz), &written, nullptr) ||
        written != sz)
    {
        // m_logger->Error(L"SendMessage: WriteFile failed, le=%lu", GetLastError());
        m_logger->LogFormat(LogLevel::Error, L"SendMessage: WriteFile failed, le=%lu", GetLastError());
        return false;
    }
    return true;
}

//------------------------------------------------------------------------------
bool PipeServer::CreatePipeInstance(std::unique_ptr<PipeInstance>& inst)
{
    SECURITY_DESCRIPTOR sd{};
    SECURITY_ATTRIBUTES  sa{ sizeof(sa), &sd, FALSE };
    if (!CreatePipeSecurity(sa, sd)) return false;

    inst->hPipe = CreateNamedPipeW(
        GetPipeName().c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        MAX_PIPE_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        PIPE_TIMEOUT,
        &sa);

    if (inst->hPipe == INVALID_HANDLE_VALUE)
    {
        // m_logger->Error(L"CreateNamedPipe failed, le=%lu", GetLastError());
        m_logger->LogFormat(LogLevel::Error, L"CreateNamedPipe failed, le=%lu", GetLastError());
        return false;
    }
    return true;
}

//------------------------------------------------------------------------------
void PipeServer::AcceptConnections()
{
    while (m_running)
    {
        std::unique_ptr<PipeInstance> free_inst;
        {   // grab an unused slot
            std::lock_guard<std::mutex> lock(m_pipesMutex);
            auto it = std::find_if(m_pipes.begin(), m_pipes.end(),
                                   [](auto& p) { return !p->connected; });
            if (it == m_pipes.end())
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            free_inst.swap(*it);
            m_pipes.erase(it);          // temporarily remove from pool
        }

        BOOL ok = ConnectNamedPipe(free_inst->hPipe, &free_inst->overlapped);
        if (!ok && GetLastError() != ERROR_IO_PENDING)
        {
            // m_logger->Error(L"ConnectNamedPipe failed, le=%lu", GetLastError());
            m_logger->LogFormat(LogLevel::Error, L"ConnectNamedPipe failed, le=%lu", GetLastError());
            DisconnectClient(free_inst.get());
            std::lock_guard<std::mutex> lock(m_pipesMutex);
            m_pipes.emplace_back(std::move(free_inst));
            continue;
        }
        DWORD dummy = 0;
        ok = GetOverlappedResult(free_inst->hPipe, &free_inst->overlapped,
                                 &dummy, TRUE);
        if (!ok || !m_running)
        {
            DisconnectClient(free_inst.get());
            std::lock_guard<std::mutex> lock(m_pipesMutex);
            m_pipes.emplace_back(std::move(free_inst));
            continue;
        }
        free_inst->connected = true;
        free_inst->workerThread = std::thread(&PipeServer::HandleClient,
                                              this, free_inst.get());
        std::lock_guard<std::mutex> lock(m_pipesMutex);
        m_pipes.emplace_back(std::move(free_inst));
    }
}

//------------------------------------------------------------------------------
void PipeServer::HandleClient(PipeInstance* instance)
{
    // m_logger->Info(L"HandleClient: new client on pipe %p", instance->hPipe);
    m_logger->LogFormat(LogLevel::Info, L"HandleClient: new client on pipe %p", instance->hPipe);
    while (m_running && instance->connected)
    {
        DWORD read = 0;
        BOOL  ok   = ReadFile(instance->hPipe,
                              instance->buffer.data(),
                              static_cast<DWORD>(instance->buffer.size()),
                              &read,
                              &instance->overlapped);
        if (!ok && GetLastError() == ERROR_IO_PENDING)
        {
            DWORD transferred = 0;
            ok = GetOverlappedResult(instance->hPipe, &instance->overlapped,
                                     &transferred, TRUE);
            read = transferred;
        }
        if (!ok || read == 0) break;
        if (!ProcessMessage(instance, instance->buffer.data(), read)) break;
    }
    DisconnectClient(instance);
}
bool PipeServer::ProcessMessage(PipeInstance* instance,
                                const char*   data,
                                size_t        size)
{
    if (size < sizeof(Protocol::MessageHeader)) return false;
    const auto* header = reinterpret_cast<const Protocol::MessageHeader*>(data);
    if (!ValidateMessage(header, size))
    {
        // m_logger->Error(L"ProcessMessage: invalid header");
        m_logger->LogFormat(LogLevel::Error, L"ProcessMessage: invalid header");
        return false;
    }
    if (m_messageHandler) m_messageHandler(header, size, instance->hPipe);
    return true;
}
void PipeServer::DisconnectClient(PipeInstance* instance)
{
    if (!instance->connected) return;
    // m_logger->Info(L"DisconnectClient: %p", instance->hPipe);
    m_logger->LogFormat(LogLevel::Info, L"DisconnectClient: %p", instance->hPipe);
    if (instance->hPipe != INVALID_HANDLE_VALUE)
    {
        FlushFileBuffers(instance->hPipe);
        DisconnectNamedPipe(instance->hPipe);
    }
    instance->connected = false;
}

//------------------------------------------------------------------------------
bool PipeServer::CreatePipeSecurity(SECURITY_ATTRIBUTES& sa,
                                    SECURITY_DESCRIPTOR& sd)
{
    if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
        return false;
    return SetPipeDACL(sd);
}
bool PipeServer::SetPipeDACL(SECURITY_DESCRIPTOR& sd)
{
    // SDDL that gives “Everyone” GENERIC_READ | GENERIC_WRITE
    LPCWSTR sddl = L"D:(A;;GRGW;;;WD)";
    PSECURITY_DESCRIPTOR tmpSD = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &tmpSD, nullptr))
    {
        // m_logger->Error(L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
        m_logger->LogFormat(LogLevel::Error, L"ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
        return false;
    }
    BOOL daclPresent = FALSE, defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(tmpSD, &daclPresent, &dacl, &defaulted);
    BOOL ok = daclPresent && SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE);;
    LocalFree(tmpSD);
    return ok;
}

//------------------------------------------------------------------------------
std::wstring PipeServer::GetPipeName() const
{
    return PIPE_NAME_PATTERN;
}
bool PipeServer::ValidateMessage(const Protocol::MessageHeader* header, size_t dataSize) const {
    if (!header || header->magic != Protocol::MESSAGE_MAGIC) return false;
    if (header->size > dataSize) return false;
    return true;
}