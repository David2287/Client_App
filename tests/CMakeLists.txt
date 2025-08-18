cmake_minimum_required(VERSION 3.20)
project(AntivirusTests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable testing
enable_testing()

# Find Google Test
find_package(GTest QUIET)

if(NOT GTest_FOUND)
    # Download and build Google Test
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50f33f9142fd2f43c07a8f6b4b7d1e.zip
    )
    
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/../service/include)
include_directories(${CMAKE_SOURCE_DIR}/../shared/include)
include_directories(${CMAKE_SOURCE_DIR}/mocks)

# Compiler definitions
add_compile_definitions(
    _WIN32_WINNT=0x0A00
    UNICODE
    _UNICODE
    TESTING_BUILD
)

# Source files from the main project (excluding main.cpp)
set(SERVICE_SOURCES
    ../service/src/threat_engine.cpp
    ../service/src/file_monitor.cpp
    ../service/src/scanner.cpp
    ../service/src/scheduled_scanner.cpp
    ../service/src/logger.cpp
    ../service/src/utils.cpp
    ../service/src/service.cpp
    ../service/src/pipe_server.cpp
    ../service/src/session_manager.cpp
)

# Mock sources
set(MOCK_SOURCES
    mocks/mock_logger.cpp
    mocks/mock_threat_engine.cpp
    mocks/mock_file_system.cpp
    mocks/test_utilities.cpp
)

# Test sources
set(UNIT_TEST_SOURCES
    unit/test_threat_engine.cpp
    unit/test_scanner.cpp
    unit/test_file_monitor.cpp
    unit/test_scheduled_scanner.cpp
    unit/test_logger.cpp
    unit/test_utils.cpp
)

set(INTEGRATION_TEST_SOURCES
    integration/test_service_integration.cpp
    integration/test_pipe_communication.cpp
    integration/test_scanning_workflow.cpp
)

set(SYSTEM_TEST_SOURCES
    system/test_full_system.cpp
    system/test_performance.cpp
    system/test_security.cpp
)

# Create test executables
add_executable(unit_tests 
    ${UNIT_TEST_SOURCES} 
    ${SERVICE_SOURCES} 
    ${MOCK_SOURCES}
    main_test.cpp
)

add_executable(integration_tests 
    ${INTEGRATION_TEST_SOURCES} 
    ${SERVICE_SOURCES} 
    ${MOCK_SOURCES}
    main_test.cpp
)

add_executable(system_tests 
    ${SYSTEM_TEST_SOURCES} 
    ${SERVICE_SOURCES} 
    ${MOCK_SOURCES}
    main_test.cpp
)

# Link libraries
set(TEST_LIBRARIES
    gtest
    gtest_main
    advapi32
    kernel32
    user32
    wtsapi32
    shlwapi
    version
    crypt32
    wininet
)

target_link_libraries(unit_tests ${TEST_LIBRARIES})
target_link_libraries(integration_tests ${TEST_LIBRARIES})
target_link_libraries(system_tests ${TEST_LIBRARIES})

# Compiler options
if(MSVC)
    target_compile_options(unit_tests PRIVATE /W4)
    target_compile_options(integration_tests PRIVATE /W4)
    target_compile_options(system_tests PRIVATE /W4)
else()
    target_compile_options(unit_tests PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(integration_tests PRIVATE -Wall -Wextra -pedantic)
    target_compile_options(system_tests PRIVATE -Wall -Wextra -pedantic)
endif()

# Register tests with CTest
add_test(NAME UnitTests COMMAND unit_tests)
add_test(NAME IntegrationTests COMMAND integration_tests)
add_test(NAME SystemTests COMMAND system_tests)

# Set test properties
set_tests_properties(UnitTests PROPERTIES TIMEOUT 300)  # 5 minutes
set_tests_properties(IntegrationTests PROPERTIES TIMEOUT 600)  # 10 minutes
set_tests_properties(SystemTests PROPERTIES TIMEOUT 1800)  # 30 minutes

# Test data files
configure_file(${CMAKE_SOURCE_DIR}/data/test_signatures.db ${CMAKE_BINARY_DIR}/test_signatures.db COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/data/clean_test_file.txt ${CMAKE_BINARY_DIR}/clean_test_file.txt COPYONLY)
configure_file(${CMAKE_SOURCE_DIR}/data/malware_test_file.bin ${CMAKE_BINARY_DIR}/malware_test_file.bin COPYONLY)
