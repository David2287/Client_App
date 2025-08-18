cmake_minimum_required(VERSION 3.20)
project(AntivirusService)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Set output directory
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/../shared/include)

# Source files
set(SOURCES
    src/main.cpp
    src/service.cpp
    src/pipe_server.cpp
    src/session_manager.cpp
    src/scanner.cpp
    src/threat_engine.cpp
    src/file_monitor.cpp
    src/scheduled_scanner.cpp
    src/logger.cpp
    src/utils.cpp
)

# Header files
set(HEADERS
    include/service.h
    include/pipe_server.h
    include/session_manager.h
    include/scanner.h
    include/threat_engine.h
    include/file_monitor.h
    include/scheduled_scanner.h
    include/logger.h
    include/utils.h
    ../shared/include/protocol.h
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    advapi32    # Service API
    kernel32    # Win32 API
    user32      # User32 API
    wtsapi32    # Terminal Services API
    shlwapi     # Shell API
    version     # Version API
    crypt32     # Crypto API
    wininet     # Internet API
)

# Compiler specific options
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
    target_compile_definitions(${PROJECT_NAME} PRIVATE 
        _WIN32_WINNT=0x0A00  # Windows 10
        UNICODE
        _UNICODE
    )
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -pedantic)
endif()

# Release optimizations
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_definitions(${PROJECT_NAME} PRIVATE NDEBUG)
endif()

# Create include directory
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/include)
file(MAKE_DIRECTORY ${CMAKE_SOURCE_DIR}/src)
