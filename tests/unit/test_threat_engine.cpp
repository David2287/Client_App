#include <gtest/gtest.h>
#include "threat_engine.h"
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>

class ThreatEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Create test directories
        std::filesystem::create_directories("test_data");
        std::filesystem::create_directories("test_quarantine");
        
        // Create test signature database
        createTestSignatureDatabase();
        
        // Initialize threat engine
        threat_engine = std::make_unique<ThreatEngine>("test_signatures.db", "test_quarantine");
    }
    
    void TearDown() override {
        // Cleanup
        threat_engine.reset();
        
        try {
            if (std::filesystem::exists("test_data")) {
                std::filesystem::remove_all("test_data");
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
        db << "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR,EICAR\n";
        db << "malware_signature_1,Trojan.Test\n";
        db << "virus_pattern_abc,Virus.TestA\n";
        db.close();
    }
    
    void createTestFile(const std::string& filename, const std::string& content) {
        std::ofstream file("test_data/" + filename);
        file << content;
        file.close();
    }
    
    std::unique_ptr<ThreatEngine> threat_engine;
};

// Test signature database loading
TEST_F(ThreatEngineTest, LoadSignatureDatabase) {
    ASSERT_TRUE(threat_engine != nullptr);
    
    // Database should load successfully
    // We can't directly test private members, but we can test functionality
    // that depends on loaded signatures
}

// Test clean file scanning
TEST_F(ThreatEngineTest, ScanCleanFile) {
    createTestFile("clean.txt", "This is a clean file with normal content.");
    
    ScanResult result = threat_engine->scanFile("test_data/clean.txt");
    
    EXPECT_EQ(result.threat_level, ThreatLevel::CLEAN);
    EXPECT_TRUE(result.threat_name.empty());
    EXPECT_FALSE(result.quarantined);
}

// Test malware detection by signature
TEST_F(ThreatEngineTest, DetectMalwareBySignature) {
    createTestFile("malware.txt", "Some content with malware_signature_1 in it.");
    
    ScanResult result = threat_engine->scanFile("test_data/malware.txt");
    
    EXPECT_EQ(result.threat_level, ThreatLevel::HIGH);
    EXPECT_EQ(result.threat_name, "Trojan.Test");
    EXPECT_FALSE(result.quarantined); // Not auto-quarantined in scan
}

// Test EICAR test file detection
TEST_F(ThreatEngineTest, DetectEICARFile) {
    createTestFile("eicar.txt", "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
    
    ScanResult result = threat_engine->scanFile("test_data/eicar.txt");
    
    EXPECT_EQ(result.threat_level, ThreatLevel::HIGH);
    EXPECT_EQ(result.threat_name, "EICAR");
}

// Test heuristic detection
TEST_F(ThreatEngineTest, HeuristicDetection) {
    // Create file with suspicious content (high entropy + suspicious strings)
    std::string suspicious_content = "CreateProcess DeleteFile RegOpenKey ";
    for (int i = 0; i < 100; i++) {
        suspicious_content += std::to_string(rand()) + " ";
    }
    
    createTestFile("suspicious.txt", suspicious_content);
    
    ScanResult result = threat_engine->scanFile("test_data/suspicious.txt");
    
    // Should be detected as at least medium threat due to heuristics
    EXPECT_GE(result.threat_level, ThreatLevel::MEDIUM);
}

// Test directory scanning
TEST_F(ThreatEngineTest, ScanDirectory) {
    createTestFile("clean1.txt", "Clean file 1");
    createTestFile("clean2.txt", "Clean file 2");
    createTestFile("malware.txt", "File with malware_signature_1");
    
    std::vector<ScanResult> results = threat_engine->scanDirectory("test_data");
    
    EXPECT_EQ(results.size(), 3);
    
    // Check that malware was detected
    bool malware_found = false;
    for (const auto& result : results) {
        if (result.threat_level == ThreatLevel::HIGH && result.threat_name == "Trojan.Test") {
            malware_found = true;
            break;
        }
    }
    EXPECT_TRUE(malware_found);
}

// Test quarantine functionality
TEST_F(ThreatEngineTest, QuarantineFile) {
    createTestFile("malware_to_quarantine.txt", "Content with malware_signature_1");
    std::string file_path = "test_data/malware_to_quarantine.txt";
    
    bool quarantined = threat_engine->quarantineFile(file_path, "Trojan.Test");
    
    EXPECT_TRUE(quarantined);
    EXPECT_FALSE(std::filesystem::exists(file_path)); // Original should be removed
    
    // Check quarantine directory has the file
    bool found_in_quarantine = false;
    for (const auto& entry : std::filesystem::directory_iterator("test_quarantine")) {
        if (entry.is_regular_file()) {
            found_in_quarantine = true;
            break;
        }
    }
    EXPECT_TRUE(found_in_quarantine);
}

// Test restore from quarantine
TEST_F(ThreatEngineTest, RestoreFromQuarantine) {
    // First quarantine a file
    createTestFile("test_restore.txt", "Test content");
    std::string original_path = "test_data/test_restore.txt";
    
    threat_engine->quarantineFile(original_path, "TestThreat");
    EXPECT_FALSE(std::filesystem::exists(original_path));
    
    // Find the quarantined file
    std::string quarantine_id;
    for (const auto& entry : std::filesystem::directory_iterator("test_quarantine")) {
        if (entry.is_regular_file() && entry.path().extension() == ".dat") {
            quarantine_id = entry.path().stem().string();
            break;
        }
    }
    
    ASSERT_FALSE(quarantine_id.empty());
    
    // Restore the file
    bool restored = threat_engine->restoreFromQuarantine(quarantine_id, original_path);
    
    EXPECT_TRUE(restored);
    EXPECT_TRUE(std::filesystem::exists(original_path));
}

// Test entropy calculation
TEST_F(ThreatEngineTest, EntropyCalculation) {
    // Low entropy content
    createTestFile("low_entropy.txt", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    ScanResult low_result = threat_engine->scanFile("test_data/low_entropy.txt");
    
    // High entropy content
    std::string high_entropy_content;
    for (int i = 0; i < 1000; i++) {
        high_entropy_content += static_cast<char>(rand() % 256);
    }
    createTestFile("high_entropy.bin", high_entropy_content);
    ScanResult high_result = threat_engine->scanFile("test_data/high_entropy.bin");
    
    // High entropy file should have higher threat level
    EXPECT_GE(high_result.threat_level, low_result.threat_level);
}

// Test file size limits
TEST_F(ThreatEngineTest, LargeFileHandling) {
    // Create a very small file
    createTestFile("tiny.txt", "small");
    ScanResult tiny_result = threat_engine->scanFile("test_data/tiny.txt");
    EXPECT_EQ(tiny_result.threat_level, ThreatLevel::CLEAN);
    
    // Test with moderately sized file
    std::string medium_content(10000, 'a');
    createTestFile("medium.txt", medium_content);
    ScanResult medium_result = threat_engine->scanFile("test_data/medium.txt");
    EXPECT_EQ(medium_result.threat_level, ThreatLevel::CLEAN);
}

// Test invalid file paths
TEST_F(ThreatEngineTest, InvalidFilePaths) {
    ScanResult result = threat_engine->scanFile("nonexistent/file.txt");
    
    EXPECT_EQ(result.threat_level, ThreatLevel::CLEAN);
    EXPECT_TRUE(result.threat_name.empty());
}

// Test concurrent scanning (basic thread safety)
TEST_F(ThreatEngineTest, ConcurrentScanning) {
    createTestFile("concurrent1.txt", "Clean content 1");
    createTestFile("concurrent2.txt", "Clean content 2");
    createTestFile("concurrent3.txt", "Content with malware_signature_1");
    
    std::vector<std::thread> threads;
    std::vector<ScanResult> results(3);
    
    threads.emplace_back([&]() {
        results[0] = threat_engine->scanFile("test_data/concurrent1.txt");
    });
    threads.emplace_back([&]() {
        results[1] = threat_engine->scanFile("test_data/concurrent2.txt");
    });
    threads.emplace_back([&]() {
        results[2] = threat_engine->scanFile("test_data/concurrent3.txt");
    });
    
    for (auto& t : threads) {
        t.join();
    }
    
    EXPECT_EQ(results[0].threat_level, ThreatLevel::CLEAN);
    EXPECT_EQ(results[1].threat_level, ThreatLevel::CLEAN);
    EXPECT_EQ(results[2].threat_level, ThreatLevel::HIGH);
}
