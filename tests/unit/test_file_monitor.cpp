#include <gtest/gtest.h>
#include "file_monitor.h"
#include "threat_engine.h"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

class FileMonitorTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directories
        std::filesystem::create_directories("test_monitor");
        std::filesystem::create_directories("test_quarantine");
        
        // Create test signature database
        createTestSignatureDatabase();
        
        // Initialize threat engine and file monitor
        threat_engine = std::make_unique<ThreatEngine>("test_signatures.db", "test_quarantine");
        file_monitor = std::make_unique<FileMonitor>(threat_engine.get());
    }
    
    void TearDown() override {
        // Stop monitoring before cleanup
        if (file_monitor) {
            file_monitor->stopMonitoring();
        }
        
        // Cleanup
        file_monitor.reset();
        threat_engine.reset();
        
        try {
            if (std::filesystem::exists("test_monitor")) {
                std::filesystem::remove_all("test_monitor");
            }
            if (std::filesystem::exists("test_quarantine")) {
                std::filesystem::remove_all("test_quarantine");
            }
            if (std::filesystem::exists("test_signatures.db")) {
                std::filesystem::remove("test_signatures.db");
            }
        }
        catch (...) {
            // Ignore cleanup errors in tests
        }
    }
    
    void createTestSignatureDatabase() {
        std::ofstream db("test_signatures.db");
        db << "EICAR-STANDARD-ANTIVIRUS-TEST-FILE,TestVirus\n";
        db << "malware_signature_test,Trojan.TestMonitor\n";
        db << "virus_pattern_monitor,Virus.Monitor\n";
        db.close();
    }
    
    void createTestFile(const std::string& filename, const std::string& content) {
        std::ofstream file("test_monitor/" + filename);
        file << content;
        file.close();
    }
    
    std::unique_ptr<ThreatEngine> threat_engine;
    std::unique_ptr<FileMonitor> file_monitor;
};

// Test adding monitoring directory
TEST_F(FileMonitorTest, AddMonitoringDirectory) {
    bool added = file_monitor->addDirectory("test_monitor");
    EXPECT_TRUE(added);
    
    // Try adding the same directory again
    bool added_again = file_monitor->addDirectory("test_monitor");
    EXPECT_TRUE(added_again); // Should handle gracefully
}

// Test adding invalid directory
TEST_F(FileMonitorTest, AddInvalidDirectory) {
    bool added = file_monitor->addDirectory("nonexistent_directory");
    EXPECT_FALSE(added);
}

// Test removing monitoring directory
TEST_F(FileMonitorTest, RemoveMonitoringDirectory) {
    file_monitor->addDirectory("test_monitor");
    bool removed = file_monitor->removeDirectory("test_monitor");
    EXPECT_TRUE(removed);
    
    // Try removing non-existent directory
    bool removed_again = file_monitor->removeDirectory("nonexistent");
    EXPECT_FALSE(removed_again);
}

// Test starting and stopping real-time protection
TEST_F(FileMonitorTest, RealTimeProtectionControl) {
    file_monitor->addDirectory("test_monitor");
    
    // Start monitoring
    bool started = file_monitor->startMonitoring();
    EXPECT_TRUE(started);
    
    // Check if monitoring is active
    EXPECT_TRUE(file_monitor->isMonitoring());
    
    // Stop monitoring
    file_monitor->stopMonitoring();
    EXPECT_FALSE(file_monitor->isMonitoring());
}

// Test file creation detection
TEST_F(FileMonitorTest, DetectFileCreation) {
    file_monitor->addDirectory("test_monitor");
    file_monitor->startMonitoring();
    
    // Allow monitor to start up
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create a clean file
    createTestFile("new_clean_file.txt", "This is a clean file");
    
    // Allow time for detection and processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // File should exist (not quarantined)
    EXPECT_TRUE(std::filesystem::exists("test_monitor/new_clean_file.txt"));
    
    file_monitor->stopMonitoring();
}

// Test malware detection and quarantine during monitoring
TEST_F(FileMonitorTest, DetectAndQuarantineMalware) {
    file_monitor->addDirectory("test_monitor");
    file_monitor->startMonitoring();
    
    // Allow monitor to start up
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create a malware file
    std::string malware_path = "test_monitor/malware_file.txt";
    createTestFile("malware_file.txt", "Content with malware_signature_test in it");
    
    // Allow time for detection and quarantine
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // File should be quarantined (removed from original location)
    EXPECT_FALSE(std::filesystem::exists(malware_path));
    
    // Check that something was quarantined
    bool found_quarantined = false;
    if (std::filesystem::exists("test_quarantine")) {
        for (const auto& entry : std::filesystem::directory_iterator("test_quarantine")) {
            if (entry.is_regular_file()) {
                found_quarantined = true;
                break;
            }
        }
    }
    EXPECT_TRUE(found_quarantined);
    
    file_monitor->stopMonitoring();
}

// Test file modification detection
TEST_F(FileMonitorTest, DetectFileModification) {
    // Create initial clean file
    createTestFile("modify_test.txt", "Initial clean content");
    
    file_monitor->addDirectory("test_monitor");
    file_monitor->startMonitoring();
    
    // Allow monitor to start up
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Modify file to contain malware
    std::ofstream file("test_monitor/modify_test.txt", std::ios::trunc);
    file << "Modified content with malware_signature_test";
    file.close();
    
    // Allow time for detection
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // File should be quarantined
    EXPECT_FALSE(std::filesystem::exists("test_monitor/modify_test.txt"));
    
    file_monitor->stopMonitoring();
}

// Test filtering of system files
TEST_F(FileMonitorTest, FilterSystemFiles) {
    file_monitor->addDirectory("test_monitor");
    file_monitor->startMonitoring();
    
    // Allow monitor to start up
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create system/temp files that should be filtered
    createTestFile("Thumbs.db", "System file content");
    createTestFile("desktop.ini", "System file content");
    createTestFile("temp.tmp", "Temporary file content");
    
    // Allow time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // These files should still exist (not scanned/quarantined)
    EXPECT_TRUE(std::filesystem::exists("test_monitor/Thumbs.db"));
    EXPECT_TRUE(std::filesystem::exists("test_monitor/desktop.ini"));
    EXPECT_TRUE(std::filesystem::exists("test_monitor/temp.tmp"));
    
    file_monitor->stopMonitoring();
}

// Test multiple directory monitoring
TEST_F(FileMonitorTest, MonitorMultipleDirectories) {
    std::filesystem::create_directories("test_monitor2");
    
    file_monitor->addDirectory("test_monitor");
    file_monitor->addDirectory("test_monitor2");
    file_monitor->startMonitoring();
    
    // Allow monitor to start up
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Create files in both directories
    createTestFile("file1.txt", "Clean content in dir1");
    
    std::ofstream file2("test_monitor2/file2.txt");
    file2 << "Content with malware_signature_test in dir2";
    file2.close();
    
    // Allow time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Clean file should remain
    EXPECT_TRUE(std::filesystem::exists("test_monitor/file1.txt"));
    
    // Malware file should be quarantined
    EXPECT_FALSE(std::filesystem::exists("test_monitor2/file2.txt"));
    
    file_monitor->stopMonitoring();
    std::filesystem::remove_all("test_monitor2");
}

// Test monitor restart capability
TEST_F(FileMonitorTest, RestartMonitoring) {
    file_monitor->addDirectory("test_monitor");
    
    // Start monitoring
    EXPECT_TRUE(file_monitor->startMonitoring());
    EXPECT_TRUE(file_monitor->isMonitoring());
    
    // Stop monitoring
    file_monitor->stopMonitoring();
    EXPECT_FALSE(file_monitor->isMonitoring());
    
    // Restart monitoring
    EXPECT_TRUE(file_monitor->startMonitoring());
    EXPECT_TRUE(file_monitor->isMonitoring());
    
    file_monitor->stopMonitoring();
}

// Test thread safety of monitor operations
TEST_F(FileMonitorTest, ThreadSafetyBasic) {
    std::vector<std::thread> threads;
    
    // Multiple threads trying to add directories
    for (int i = 0; i < 5; i++) {
        threads.emplace_back([&]() {
            file_monitor->addDirectory("test_monitor");
        });
    }
    
    // Start and stop monitoring from different threads
    threads.emplace_back([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        file_monitor->startMonitoring();
    });
    
    threads.emplace_back([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        file_monitor->stopMonitoring();
    });
    
    for (auto& t : threads) {
        t.join();
    }
    
    // Should not crash and should be in a valid state
    EXPECT_FALSE(file_monitor->isMonitoring());
}

// Test resource cleanup
TEST_F(FileMonitorTest, ResourceCleanup) {
    file_monitor->addDirectory("test_monitor");
    file_monitor->startMonitoring();
    
    // Allow some time for threads to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Create multiple files to ensure threads are working
    for (int i = 0; i < 5; i++) {
        createTestFile("file" + std::to_string(i) + ".txt", "Clean content " + std::to_string(i));
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Stop monitoring - should properly clean up resources
    file_monitor->stopMonitoring();
    
    // Should be able to restart without issues
    EXPECT_TRUE(file_monitor->startMonitoring());
    file_monitor->stopMonitoring();
}
