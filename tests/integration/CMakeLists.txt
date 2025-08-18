# Integration Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.15)

# Find required packages
find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

# Include directories
include_directories(../../src)
include_directories(../../src/core)
include_directories(../../src/service)
include_directories(../../src/utils)

# Integration test executable
add_executable(integration_tests
    test_integration.cpp
    test_service_integration.cpp
    ../../src/core/threat_engine.cpp
    ../../src/core/file_monitor.cpp
    ../../src/service/antivirus_service.cpp
    ../../src/utils/logger.cpp
    ../../src/utils/file_utils.cpp
)

# Link libraries
target_link_libraries(integration_tests
    GTest::gtest
    GTest::gtest_main
    Threads::Threads
)

# Compiler flags
target_compile_features(integration_tests PRIVATE cxx_std_17)

if(WIN32)
    target_link_libraries(integration_tests
        advapi32
        kernel32
        user32
    )
endif()

# Add test to CTest
add_test(NAME IntegrationTests COMMAND integration_tests)

# Set test properties
set_tests_properties(IntegrationTests PROPERTIES
    TIMEOUT 300  # 5 minutes timeout
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# Copy test files to build directory if needed
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/test_config.ini 
               ${CMAKE_CURRENT_BINARY_DIR}/test_config.ini COPYONLY)

# Create test output directory
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/test_output)

# Custom target for running integration tests
add_custom_target(run_integration_tests
    COMMAND ${CMAKE_COMMAND} -E echo "Running Integration Tests..."
    COMMAND integration_tests --gtest_output=xml:test_output/integration_results.xml
    DEPENDS integration_tests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
