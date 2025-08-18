#include <gtest/gtest.h>
#include <windows.h>
#include <iostream>
#include <filesystem>

class TestEnvironment : public ::testing::Environment {
public:
    void SetUp() override {
        // Initialize test environment
        std::wcout << L"Setting up test environment..." << std::endl;
        
        // Create test directories
        std::filesystem::create_directories("test_data");
        std::filesystem::create_directories("test_quarantine");
        std::filesystem::create_directories("test_logs");
        
        // Set up test data paths
        SetEnvironmentVariable(L"ANTIVIRUS_TEST_MODE", L"1");
        SetEnvironmentVariable(L"ANTIVIRUS_TEST_DATA", L"test_data");
        SetEnvironmentVariable(L"ANTIVIRUS_TEST_QUARANTINE", L"test_quarantine");
        SetEnvironmentVariable(L"ANTIVIRUS_TEST_LOGS", L"test_logs");
        
        std::wcout << L"Test environment setup complete." << std::endl;
    }
    
    void TearDown() override {
        // Cleanup test environment
        std::wcout << L"Cleaning up test environment..." << std::endl;
        
        try {
            // Clean up test directories
            if (std::filesystem::exists("test_data")) {
                std::filesystem::remove_all("test_data");
            }
            if (std::filesystem::exists("test_quarantine")) {
                std::filesystem::remove_all("test_quarantine");
            }
            if (std::filesystem::exists("test_logs")) {
                std::filesystem::remove_all("test_logs");
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error cleaning up test environment: " << e.what() << std::endl;
        }
        
        std::wcout << L"Test environment cleanup complete." << std::endl;
    }
};

int main(int argc, char** argv) {
    // Initialize Google Test
    ::testing::InitGoogleTest(&argc, argv);
    
    // Add global test environment
    ::testing::AddGlobalTestEnvironment(new TestEnvironment);
    
    // Configure test output
    ::testing::FLAGS_gtest_print_time = true;
    ::testing::FLAGS_gtest_print_utf8 = true;
    
    std::cout << "Starting Antivirus Test Suite..." << std::endl;
    std::cout << "=================================" << std::endl;
    
    // Run all tests
    int result = RUN_ALL_TESTS();
    
    std::cout << "=================================" << std::endl;
    std::cout << "Test Suite Complete. Result: " << (result == 0 ? "PASSED" : "FAILED") << std::endl;
    
    return result;
}
