#include <gtest/gtest.h>
#include "antivirus_service.h"
#include "threat_engine.h"
#include "file_monitor.h"
#include "logger.h"
#include <windows.h>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>

class ServiceIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize logging for tests
        Logger::initialize(Logger::Level::DEBUG, "service_integration_test.log");
        
        // Create test directories
        std::filesystem::create_directories("service_test_scan");
        std::filesystem::create_directories("service_test_quarantine");
        std::filesystem::create_directories("service_test_monitor");
        
        // Create test signature database
        createTestSignatures();
        
        // Initialize service components (but don't start as Windows Service)
        antivirus_service = std::make_unique<AntivirusService>();
    }
    
    void TearDown() override {
        // Stop service if running
        if (antivirus_service) {
            antivirus_service->stop();
        }
        
        antivirus_service.reset();
        
        // Cleanup test directories
        try {
            std::filesystem::remove_all("service_test_scan");
            std::filesystem::remove_all("service_test_quarantine");
            std::filesystem::remove_all("service_test_monitor");
            std::filesystem::remove("service_test_signatures.db");
            std::filesystem::remove("service_integration_test.log");
        }
        catch (...) {
            // Ignore cleanup errors
        }
    }
    
    void createTestSignatures() {
        std::ofstream db("service_test_signatures.db");
        db << "EICAR-STANDARD-ANTIVIRUS-TEST-FILE,EICAR-Test-File\n";
        db << "service_test_malware,Service.Test.Malware\n";
        db << "integration_virus_pattern,Integration.Virus\n";
        db << "trojan_service_test,Trojan.ServiceTest\n";
        db.close();
    }
    
    void createTestFile(const std::string& path, const std::string& content) {
        std::ofstream file(path);
        file << content;
        file.close();
    }
    
    std::unique_ptr<AntivirusService> antivirus_service;
};

// Test service initialization and configuration
TEST_F(ServiceIntegrationTest, ServiceInitialization_Complete) {
    // Initialize service configuration
    bool initialized = antivirus_service->initialize(
        "service_test_signatures.db",
        "service_test_quarantine"
    );
    
    EXPECT_TRUE(initialized);
    
    // Verify components are properly initialized
    EXPECT_TRUE(antivirus_service->isThreatEngineReady());
    EXPECT_TRUE(antivirus_service->isFileMonitorReady());
    
    // Test configuration update
    bool config_updated = antivirus_service->updateConfiguration({
        {"real_time_protection", "true"},
        {"scan_archives", "true"},
        {"quarantine_enabled", "true"},
        {"max_file_size", "104857600"} // 100MB
    });
    
    EXPECT_TRUE(config_updated);
}

// Test service start/stop lifecycle
TEST_F(ServiceIntegrationTest, ServiceLifecycle_StartStop) {
    // Initialize service
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    
    // Start service
    bool started = antivirus_service->start();
    EXPECT_TRUE(started);
    
    // Allow service to fully start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Verify service is running
    EXPECT_TRUE(antivirus_service->isRunning());
    EXPECT_TRUE(antivirus_service->isRealTimeProtectionActive());
    
    // Stop service
    antivirus_service->stop();
    
    // Allow service to fully stop
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Verify service is stopped
    EXPECT_FALSE(antivirus_service->isRunning());
    EXPECT_FALSE(antivirus_service->isRealTimeProtectionActive());
}

// Test service with real-time monitoring
TEST_F(ServiceIntegrationTest, ServiceRealTimeProtection_Integration) {
    // Initialize and start service
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    antivirus_service->addMonitorDirectory("service_test_monitor");
    antivirus_service->start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    ASSERT_TRUE(antivirus_service->isRealTimeProtectionActive());
    
    // Create clean files - should not be quarantined
    createTestFile("service_test_monitor/clean_doc.txt", "Clean document content");
    createTestFile("service_test_monitor/safe_file.txt", "Safe file content");
    
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    
    // Clean files should still exist
    EXPECT_TRUE(std::filesystem::exists("service_test_monitor/clean_doc.txt"));
    EXPECT_TRUE(std::filesystem::exists("service_test_monitor/safe_file.txt"));
    
    // Create malware files - should be quarantined
    createTestFile("service_test_monitor/malware.txt", "Content with service_test_malware signature");
    createTestFile("service_test_monitor/virus.txt", "File with integration_virus_pattern inside");
    
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Malware files should be quarantined
    EXPECT_FALSE(std::filesystem::exists("service_test_monitor/malware.txt"));
    EXPECT_FALSE(std::filesystem::exists("service_test_monitor/virus.txt"));
    
    // Check quarantine directory
    int quarantined_files = 0;
    for (const auto& entry : std::filesystem::directory_iterator("service_test_quarantine")) {
        if (entry.is_regular_file()) {
            quarantined_files++;
        }
    }
    EXPECT_GE(quarantined_files, 2);
    
    antivirus_service->stop();
}

// Test service manual scanning capabilities
TEST_F(ServiceIntegrationTest, ServiceManualScanning_Integration) {
    // Initialize service
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    antivirus_service->start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Create test files for scanning
    createTestFile("service_test_scan/document1.txt", "Normal document content");
    createTestFile("service_test_scan/document2.txt", "Another normal file");
    createTestFile("service_test_scan/infected1.txt", "File containing service_test_malware");
    createTestFile("service_test_scan/infected2.txt", "Content with trojan_service_test pattern");
    
    // Perform manual scan
    auto scan_results = antivirus_service->scanPath("service_test_scan");
    
    EXPECT_EQ(scan_results.size(), 4);
    
    // Analyze results
    int clean_files = 0, infected_files = 0;
    for (const auto& result : scan_results) {
        if (result.threat_level == ThreatLevel::CLEAN) {
            clean_files++;
        } else if (result.threat_level >= ThreatLevel::HIGH) {
            infected_files++;
        }
    }
    
    EXPECT_EQ(clean_files, 2);
    EXPECT_EQ(infected_files, 2);
    
    // Test quarantine action
    for (const auto& result : scan_results) {
        if (result.threat_level >= ThreatLevel::HIGH) {
            bool quarantined = antivirus_service->quarantineFile(result.file_path, result.threat_name);
            EXPECT_TRUE(quarantined);
            EXPECT_FALSE(std::filesystem::exists(result.file_path));
        }
    }
    
    antivirus_service->stop();
}

// Test service statistics and monitoring
TEST_F(ServiceIntegrationTest, ServiceStatistics_Tracking) {
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    antivirus_service->start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Get initial statistics
    auto initial_stats = antivirus_service->getStatistics();
    EXPECT_EQ(initial_stats.files_scanned, 0);
    EXPECT_EQ(initial_stats.threats_detected, 0);
    EXPECT_EQ(initial_stats.files_quarantined, 0);
    
    // Perform some scanning to generate statistics
    createTestFile("service_test_scan/clean1.txt", "Clean content 1");
    createTestFile("service_test_scan/clean2.txt", "Clean content 2");
    createTestFile("service_test_scan/malware1.txt", "Content with service_test_malware");
    createTestFile("service_test_scan/malware2.txt", "File with integration_virus_pattern");
    
    auto scan_results = antivirus_service->scanPath("service_test_scan");
    
    // Quarantine detected threats
    for (const auto& result : scan_results) {
        if (result.threat_level >= ThreatLevel::HIGH) {
            antivirus_service->quarantineFile(result.file_path, result.threat_name);
        }
    }
    
    // Check updated statistics
    auto updated_stats = antivirus_service->getStatistics();
    EXPECT_EQ(updated_stats.files_scanned, 4);
    EXPECT_EQ(updated_stats.threats_detected, 2);
    EXPECT_EQ(updated_stats.files_quarantined, 2);
    EXPECT_GT(updated_stats.uptime_seconds, 0);
    
    antivirus_service->stop();
}

// Test service error handling and recovery
TEST_F(ServiceIntegrationTest, ServiceErrorHandling_Recovery) {
    // Test initialization with invalid paths
    bool init_result = antivirus_service->initialize("invalid_path/signatures.db", "invalid_quarantine");
    EXPECT_FALSE(init_result);
    
    // Test proper initialization
    init_result = antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    EXPECT_TRUE(init_result);
    
    // Test starting without proper initialization
    antivirus_service.reset();
    antivirus_service = std::make_unique<AntivirusService>();
    
    bool start_result = antivirus_service->start();
    EXPECT_FALSE(start_result);
    
    // Test proper sequence
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    start_result = antivirus_service->start();
    EXPECT_TRUE(start_result);
    
    // Test scanning non-existent directory
    auto scan_results = antivirus_service->scanPath("non_existent_directory");
    EXPECT_TRUE(scan_results.empty());
    
    // Test multiple stops
    antivirus_service->stop();
    antivirus_service->stop(); // Should not crash
    
    EXPECT_FALSE(antivirus_service->isRunning());
}

// Test service configuration updates during runtime
TEST_F(ServiceIntegrationTest, ServiceConfigurationUpdate_Runtime) {
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    antivirus_service->start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    ASSERT_TRUE(antivirus_service->isRunning());
    
    // Test disabling real-time protection
    bool config_updated = antivirus_service->updateConfiguration({
        {"real_time_protection", "false"}
    });
    EXPECT_TRUE(config_updated);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Real-time protection should be disabled
    EXPECT_FALSE(antivirus_service->isRealTimeProtectionActive());
    
    // Test re-enabling real-time protection
    config_updated = antivirus_service->updateConfiguration({
        {"real_time_protection", "true"}
    });
    EXPECT_TRUE(config_updated);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Real-time protection should be active again
    EXPECT_TRUE(antivirus_service->isRealTimeProtectionActive());
    
    // Test updating scan settings
    config_updated = antivirus_service->updateConfiguration({
        {"max_file_size", "52428800"}, // 50MB
        {"scan_archives", "false"}
    });
    EXPECT_TRUE(config_updated);
    
    antivirus_service->stop();
}

// Test service quarantine management
TEST_F(ServiceIntegrationTest, ServiceQuarantineManagement_Complete) {
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    antivirus_service->start();
    
    // Create and scan infected file
    createTestFile("service_test_scan/infected_document.txt", "Document with service_test_malware signature");
    auto scan_results = antivirus_service->scanPath("service_test_scan");
    
    ASSERT_EQ(scan_results.size(), 1);
    ASSERT_GE(scan_results[0].threat_level, ThreatLevel::HIGH);
    
    // Quarantine the file
    bool quarantined = antivirus_service->quarantineFile(
        scan_results[0].file_path, 
        scan_results[0].threat_name
    );
    EXPECT_TRUE(quarantined);
    EXPECT_FALSE(std::filesystem::exists("service_test_scan/infected_document.txt"));
    
    // Get quarantine information
    auto quarantine_info = antivirus_service->getQuarantineInfo();
    EXPECT_EQ(quarantine_info.size(), 1);
    
    std::string quarantine_id = quarantine_info[0].id;
    EXPECT_FALSE(quarantine_id.empty());
    EXPECT_EQ(quarantine_info[0].threat_name, scan_results[0].threat_name);
    
    // Restore from quarantine
    std::string restore_path = "service_test_scan/restored_document.txt";
    bool restored = antivirus_service->restoreFromQuarantine(quarantine_id, restore_path);
    
    EXPECT_TRUE(restored);
    EXPECT_TRUE(std::filesystem::exists(restore_path));
    
    // Verify restored content
    std::ifstream restored_file(restore_path);
    std::string content((std::istreambuf_iterator<char>(restored_file)),
                       std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("service_test_malware"), std::string::npos);
    
    // Delete from quarantine
    bool deleted = antivirus_service->deleteFromQuarantine(quarantine_id);
    EXPECT_TRUE(deleted);
    
    // Verify quarantine is empty
    auto updated_quarantine_info = antivirus_service->getQuarantineInfo();
    EXPECT_TRUE(updated_quarantine_info.empty());
    
    antivirus_service->stop();
}

// Test service performance under load
TEST_F(ServiceIntegrationTest, ServicePerformance_LoadTest) {
    antivirus_service->initialize("service_test_signatures.db", "service_test_quarantine");
    antivirus_service->start();
    
    const int num_files = 100;
    
    // Create many test files
    for (int i = 0; i < num_files; i++) {
        std::string filename = "service_test_scan/file_" + std::to_string(i) + ".txt";
        if (i % 20 == 0) {
            // Every 20th file is infected
            createTestFile(filename, "Content with service_test_malware " + std::to_string(i));
        } else {
            createTestFile(filename, "Clean content for file " + std::to_string(i));
        }
    }
    
    // Measure scan performance
    auto start_time = std::chrono::high_resolution_clock::now();
    auto scan_results = antivirus_service->scanPath("service_test_scan");
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_EQ(scan_results.size(), num_files);
    
    // Verify detection accuracy
    int threats_detected = 0;
    for (const auto& result : scan_results) {
        if (result.threat_level >= ThreatLevel::HIGH) {
            threats_detected++;
        }
    }
    
    EXPECT_EQ(threats_detected, 5); // 5 infected files (every 20th file)
    
    // Performance should be reasonable (less than 30 seconds for 100 files)
    EXPECT_LT(duration.count(), 30000);
    
    // Check service statistics
    auto stats = antivirus_service->getStatistics();
    EXPECT_EQ(stats.files_scanned, num_files);
    EXPECT_EQ(stats.threats_detected, threats_detected);
    
    std::cout << "Service scanned " << num_files << " files in " 
              << duration.count() << "ms" << std::endl;
    
    antivirus_service->stop();
}
