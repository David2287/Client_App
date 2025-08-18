#include <gtest/gtest.h>
#include "threat_engine.h"
#include "file_monitor.h"
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>

class IntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directories
        std::filesystem::create_directories("integration_test");
        std::filesystem::create_directories("integration_quarantine");
        std::filesystem::create_directories("integration_scan");
        
        // Create comprehensive signature database
        createSignatureDatabase();
        
        // Initialize components
        threat_engine = std::make_unique<ThreatEngine>("integration_signatures.db", "integration_quarantine");
        file_monitor = std::make_unique<FileMonitor>(threat_engine.get());
    }
    
    void TearDown() override {
        // Stop monitoring
        if (file_monitor) {
            file_monitor->stopMonitoring();
        }
        
        // Cleanup
        file_monitor.reset();
        threat_engine.reset();
        
        try {
            std::filesystem::remove_all("integration_test");
            std::filesystem::remove_all("integration_quarantine");
            std::filesystem::remove_all("integration_scan");
            std::filesystem::remove("integration_signatures.db");
        }
        catch (...) {
            // Ignore cleanup errors
        }
    }
    
    void createSignatureDatabase() {
        std::ofstream db("integration_signatures.db");
        db << "EICAR-STANDARD-ANTIVIRUS-TEST-FILE,EICAR-Test-File\n";
        db << "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR,EICAR\n";
        db << "trojan_signature_123,Trojan.Generic\n";
        db << "virus_pattern_xyz,Virus.TestVirus\n";
        db << "malware_string_abc,Malware.Suspicious\n";
        db << "rootkit_pattern_456,Rootkit.Hidden\n";
        db.close();
    }
    
    void createTestFile(const std::string& path, const std::string& content) {
        std::ofstream file(path);
        file << content;
        file.close();
    }
    
    std::unique_ptr<ThreatEngine> threat_engine;
    std::unique_ptr<FileMonitor> file_monitor;
};

// Test complete malware detection workflow
TEST_F(IntegrationTest, CompleteWorkflow_MalwareDetectionAndQuarantine) {
    // Create test files with different threat levels
    createTestFile("integration_test/clean_file.txt", "This is a clean file with normal content.");
    createTestFile("integration_test/malware_file.txt", "File containing trojan_signature_123 pattern.");
    createTestFile("integration_test/virus_file.txt", "Content with virus_pattern_xyz inside.");
    
    // Scan directory
    std::vector<ScanResult> results = threat_engine->scanDirectory("integration_test");
    
    ASSERT_EQ(results.size(), 3);
    
    // Verify results
    int clean_count = 0, threat_count = 0;
    for (const auto& result : results) {
        if (result.threat_level == ThreatLevel::CLEAN) {
            clean_count++;
        } else if (result.threat_level >= ThreatLevel::MEDIUM) {
            threat_count++;
        }
    }
    
    EXPECT_EQ(clean_count, 1);  // One clean file
    EXPECT_EQ(threat_count, 2); // Two threat files
    
    // Quarantine detected threats
    for (const auto& result : results) {
        if (result.threat_level >= ThreatLevel::HIGH) {
            bool quarantined = threat_engine->quarantineFile(result.file_path, result.threat_name);
            EXPECT_TRUE(quarantined);
            EXPECT_FALSE(std::filesystem::exists(result.file_path));
        }
    }
    
    // Verify quarantine directory has files
    int quarantined_count = 0;
    for (const auto& entry : std::filesystem::directory_iterator("integration_quarantine")) {
        if (entry.is_regular_file()) {
            quarantined_count++;
        }
    }
    EXPECT_GT(quarantined_count, 0);
}

// Test real-time monitoring integration
TEST_F(IntegrationTest, RealTimeMonitoring_EndToEnd) {
    // Set up monitoring
    file_monitor->addDirectory("integration_test");
    bool started = file_monitor->startMonitoring();
    ASSERT_TRUE(started);
    
    // Allow monitoring to start
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    // Create clean files - should not be quarantined
    createTestFile("integration_test/document1.txt", "Normal document content");
    createTestFile("integration_test/document2.txt", "Another clean document");
    
    // Allow processing time
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Clean files should exist
    EXPECT_TRUE(std::filesystem::exists("integration_test/document1.txt"));
    EXPECT_TRUE(std::filesystem::exists("integration_test/document2.txt"));
    
    // Create malware files - should be quarantined
    createTestFile("integration_test/malware1.txt", "Content with trojan_signature_123");
    createTestFile("integration_test/malware2.txt", "File with virus_pattern_xyz content");
    
    // Allow processing and quarantine time
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    
    // Malware files should be quarantined (removed from original location)
    EXPECT_FALSE(std::filesystem::exists("integration_test/malware1.txt"));
    EXPECT_FALSE(std::filesystem::exists("integration_test/malware2.txt"));
    
    // Verify quarantine
    int quarantined_files = 0;
    for (const auto& entry : std::filesystem::directory_iterator("integration_quarantine")) {
        if (entry.is_regular_file()) {
            quarantined_files++;
        }
    }
    EXPECT_GE(quarantined_files, 2);
    
    file_monitor->stopMonitoring();
}

// Test mixed file types and extensions
TEST_F(IntegrationTest, MixedFileTypes_Scanning) {
    // Create files with various extensions
    createTestFile("integration_scan/document.doc", "Clean document content");
    createTestFile("integration_scan/script.js", "function clean() { return true; }");
    createTestFile("integration_scan/executable.exe", "Clean executable content");
    createTestFile("integration_scan/malicious.pdf", "PDF with trojan_signature_123 embedded");
    createTestFile("integration_scan/infected.dll", "DLL containing virus_pattern_xyz");
    
    // Scan all files
    std::vector<ScanResult> results = threat_engine->scanDirectory("integration_scan");
    
    EXPECT_EQ(results.size(), 5);
    
    // Check specific results
    bool found_pdf_threat = false, found_dll_threat = false;
    int clean_files = 0;
    
    for (const auto& result : results) {
        if (result.file_path.find("malicious.pdf") != std::string::npos && 
            result.threat_level >= ThreatLevel::HIGH) {
            found_pdf_threat = true;
        }
        if (result.file_path.find("infected.dll") != std::string::npos && 
            result.threat_level >= ThreatLevel::HIGH) {
            found_dll_threat = true;
        }
        if (result.threat_level == ThreatLevel::CLEAN) {
            clean_files++;
        }
    }
    
    EXPECT_TRUE(found_pdf_threat);
    EXPECT_TRUE(found_dll_threat);
    EXPECT_EQ(clean_files, 3);
}

// Test quarantine and restore workflow
TEST_F(IntegrationTest, QuarantineRestore_Workflow) {
    // Create test files
    std::string safe_file = "integration_test/safe_backup.txt";
    std::string infected_file = "integration_test/infected_file.txt";
    
    createTestFile(safe_file, "Important backup data");
    createTestFile(infected_file, "Data with malware_string_abc pattern");
    
    // Scan files
    ScanResult safe_result = threat_engine->scanFile(safe_file);
    ScanResult infected_result = threat_engine->scanFile(infected_file);
    
    EXPECT_EQ(safe_result.threat_level, ThreatLevel::CLEAN);
    EXPECT_GE(infected_result.threat_level, ThreatLevel::MEDIUM);
    
    // Quarantine infected file
    bool quarantined = threat_engine->quarantineFile(infected_file, infected_result.threat_name);
    ASSERT_TRUE(quarantined);
    EXPECT_FALSE(std::filesystem::exists(infected_file));
    
    // Find quarantine ID
    std::string quarantine_id;
    for (const auto& entry : std::filesystem::directory_iterator("integration_quarantine")) {
        if (entry.is_regular_file() && entry.path().extension() == ".dat") {
            quarantine_id = entry.path().stem().string();
            break;
        }
    }
    ASSERT_FALSE(quarantine_id.empty());
    
    // Restore file (simulating user decision that it's a false positive)
    std::string restore_path = "integration_test/restored_file.txt";
    bool restored = threat_engine->restoreFromQuarantine(quarantine_id, restore_path);
    
    EXPECT_TRUE(restored);
    EXPECT_TRUE(std::filesystem::exists(restore_path));
    
    // Verify restored content
    std::ifstream restored_file(restore_path);
    std::string content((std::istreambuf_iterator<char>(restored_file)),
                       std::istreambuf_iterator<char>());
    EXPECT_NE(content.find("malware_string_abc"), std::string::npos);
}

// Test concurrent operations
TEST_F(IntegrationTest, ConcurrentOperations_Stability) {
    // Start monitoring
    file_monitor->addDirectory("integration_test");
    file_monitor->startMonitoring();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::vector<std::thread> threads;
    std::atomic<int> files_created{0};
    std::atomic<int> scans_completed{0};
    
    // Thread 1: Create clean files
    threads.emplace_back([&]() {
        for (int i = 0; i < 10; i++) {
            createTestFile("integration_test/clean_" + std::to_string(i) + ".txt", 
                          "Clean content " + std::to_string(i));
            files_created++;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    });
    
    // Thread 2: Create malware files
    threads.emplace_back([&]() {
        for (int i = 0; i < 5; i++) {
            createTestFile("integration_test/malware_" + std::to_string(i) + ".txt", 
                          "Content with trojan_signature_123 " + std::to_string(i));
            files_created++;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    
    // Thread 3: Perform manual scans
    threads.emplace_back([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        for (int i = 0; i < 5; i++) {
            std::string test_file = "integration_test/scan_test_" + std::to_string(i) + ".txt";
            createTestFile(test_file, "Manual scan test " + std::to_string(i));
            threat_engine->scanFile(test_file);
            scans_completed++;
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }
    });
    
    // Wait for all threads
    for (auto& t : threads) {
        t.join();
    }
    
    // Allow final processing
    std::this_thread::sleep_for(std::chrono::milliseconds(2000));
    
    file_monitor->stopMonitoring();
    
    // Verify system stability
    EXPECT_EQ(files_created.load(), 20);
    EXPECT_EQ(scans_completed.load(), 5);
    
    // Check quarantine has malware files
    int quarantined = 0;
    if (std::filesystem::exists("integration_quarantine")) {
        for (const auto& entry : std::filesystem::directory_iterator("integration_quarantine")) {
            if (entry.is_regular_file()) {
                quarantined++;
            }
        }
    }
    EXPECT_GT(quarantined, 0);
}

// Test EICAR test file handling
TEST_F(IntegrationTest, EICAR_TestFile_Handling) {
    std::string eicar_content = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    
    // Test manual scanning
    createTestFile("integration_test/eicar_test.txt", eicar_content);
    ScanResult result = threat_engine->scanFile("integration_test/eicar_test.txt");
    
    EXPECT_EQ(result.threat_level, ThreatLevel::HIGH);
    EXPECT_EQ(result.threat_name, "EICAR");
    
    // Test real-time detection
    file_monitor->addDirectory("integration_test");
    file_monitor->startMonitoring();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    createTestFile("integration_test/eicar_realtime.txt", eicar_content);
    
    // Allow time for detection and quarantine
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    
    // Should be quarantined
    EXPECT_FALSE(std::filesystem::exists("integration_test/eicar_realtime.txt"));
    
    file_monitor->stopMonitoring();
}

// Test performance with large number of files
TEST_F(IntegrationTest, Performance_ManyFiles) {
    const int num_files = 50;
    
    // Create many files (mix of clean and infected)
    for (int i = 0; i < num_files; i++) {
        std::string filename = "integration_test/file_" + std::to_string(i) + ".txt";
        if (i % 10 == 0) {
            // Every 10th file is infected
            createTestFile(filename, "Content with trojan_signature_123 " + std::to_string(i));
        } else {
            createTestFile(filename, "Clean content for file " + std::to_string(i));
        }
    }
    
    // Measure scan time
    auto start_time = std::chrono::high_resolution_clock::now();
    std::vector<ScanResult> results = threat_engine->scanDirectory("integration_test");
    auto end_time = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
    
    EXPECT_EQ(results.size(), num_files);
    
    // Verify detection accuracy
    int threats_detected = 0;
    for (const auto& result : results) {
        if (result.threat_level >= ThreatLevel::HIGH) {
            threats_detected++;
        }
    }
    
    EXPECT_EQ(threats_detected, 5); // 5 infected files (every 10th file)
    
    // Performance should be reasonable (less than 10 seconds for 50 files)
    EXPECT_LT(duration.count(), 10000);
    
    std::cout << "Scanned " << num_files << " files in " << duration.count() << "ms" << std::endl;
}
