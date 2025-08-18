#include <gtest/gtest.h>
#include <benchmark/benchmark.h>
#include "threat_engine.h"
#include "file_monitor.h"
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

class BenchmarkFixture : public ::benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State& state) {
        // Create benchmark directories
        std::filesystem::create_directories("benchmark_files");
        std::filesystem::create_directories("benchmark_quarantine");
        
        // Create signature database
        createSignatureDatabase();
        
        // Initialize threat engine
        threat_engine = std::make_unique<ThreatEngine>("benchmark_signatures.db", "benchmark_quarantine");
        
        // Create test files if not exists
        if (test_files_created == false) {
            createBenchmarkFiles(static_cast<int>(state.range(0)));
            test_files_created = true;
        }
    }
    
    void TearDown(const ::benchmark::State& state) {
        // Cleanup per iteration if needed
    }
    
    static void TearDownStatic() {
        // Final cleanup
        std::filesystem::remove_all("benchmark_files");
        std::filesystem::remove_all("benchmark_quarantine");
        std::filesystem::remove("benchmark_signatures.db");
    }

private:
    void createSignatureDatabase() {
        std::ofstream db("benchmark_signatures.db");
        db << "benchmark_malware_pattern,Benchmark.Malware\n";
        db << "performance_test_virus,Performance.Virus\n";
        db << "speed_test_trojan,Speed.Trojan\n";
        db << "load_test_signature,Load.Test\n";
        db << "EICAR-STANDARD-ANTIVIRUS-TEST-FILE,EICAR\n";
        db.close();
    }
    
    void createBenchmarkFiles(int num_files) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> size_dist(1024, 102400); // 1KB to 100KB
        std::uniform_int_distribution<> infected_dist(1, 100);
        
        for (int i = 0; i < num_files; ++i) {
            std::string filename = "benchmark_files/file_" + std::to_string(i) + ".txt";
            int file_size = size_dist(gen);
            
            std::ofstream file(filename);
            
            // 5% chance of infection
            if (infected_dist(gen) <= 5) {
                file << "Content with benchmark_malware_pattern signature ";
                file_size -= 50;
            }
            
            // Fill with random content
            for (int j = 0; j < file_size; ++j) {
                file << static_cast<char>('A' + (j % 26));
            }
            
            file.close();
        }
    }

protected:
    std::unique_ptr<ThreatEngine> threat_engine;
    static bool test_files_created;
};

bool BenchmarkFixture::test_files_created = false;

// Benchmark file scanning performance
BENCHMARK_DEFINE_F(BenchmarkFixture, FileScanPerformance)(benchmark::State& state) {
    for (auto _ : state) {
        auto results = threat_engine->scanDirectory("benchmark_files");
        benchmark::DoNotOptimize(results);
    }
    
    state.SetItemsProcessed(state.iterations() * state.range(0));
}

// Benchmark single file scanning
BENCHMARK_DEFINE_F(BenchmarkFixture, SingleFileScan)(benchmark::State& state) {
    std::string test_file = "benchmark_files/file_0.txt";
    
    for (auto _ : state) {
        auto result = threat_engine->scanFile(test_file);
        benchmark::DoNotOptimize(result);
    }
}

// Benchmark signature loading
BENCHMARK_DEFINE_F(BenchmarkFixture, SignatureLoading)(benchmark::State& state) {
    for (auto _ : state) {
        ThreatEngine engine("benchmark_signatures.db", "benchmark_quarantine");
        benchmark::DoNotOptimize(engine);
    }
}

// Benchmark quarantine operations
BENCHMARK_DEFINE_F(BenchmarkFixture, QuarantineOperations)(benchmark::State& state) {
    std::string test_file = "benchmark_files/quarantine_test.txt";
    
    for (auto _ : state) {
        // Create file
        std::ofstream file(test_file);
        file << "Test content for quarantine benchmark";
        file.close();
        
        // Quarantine
        bool quarantined = threat_engine->quarantineFile(test_file, "BenchmarkThreat");
        benchmark::DoNotOptimize(quarantined);
        
        if (quarantined) {
            // Find and restore to clean up
            for (const auto& entry : std::filesystem::directory_iterator("benchmark_quarantine")) {
                if (entry.is_regular_file() && entry.path().extension() == ".dat") {
                    std::string id = entry.path().stem().string();
                    threat_engine->restoreFromQuarantine(id, test_file + "_restored");
                    std::filesystem::remove(test_file + "_restored");
                    break;
                }
            }
        }
    }
}

// Register benchmarks with different file counts
BENCHMARK_REGISTER_F(BenchmarkFixture, FileScanPerformance)
    ->Args({10})
    ->Args({50})
    ->Args({100})
    ->Args({500})
    ->Unit(benchmark::kMillisecond);

BENCHMARK_REGISTER_F(BenchmarkFixture, SingleFileScan)
    ->Args({1})
    ->Iterations(1000)
    ->Unit(benchmark::kMicrosecond);

BENCHMARK_REGISTER_F(BenchmarkFixture, SignatureLoading)
    ->Args({1})
    ->Iterations(100)
    ->Unit(benchmark::kMillisecond);

BENCHMARK_REGISTER_F(BenchmarkFixture, QuarantineOperations)
    ->Args({1})
    ->Iterations(50)
    ->Unit(benchmark::kMillisecond);

// Memory usage benchmark
static void BM_MemoryUsage(benchmark::State& state) {
    std::filesystem::create_directories("memory_test");
    
    // Create large files
    for (int i = 0; i < state.range(0); ++i) {
        std::string filename = "memory_test/large_file_" + std::to_string(i) + ".txt";
        std::ofstream file(filename);
        
        // Create 1MB file
        for (int j = 0; j < 1024 * 1024; ++j) {
            file << 'X';
        }
        file.close();
    }
    
    // Create signature database
    std::ofstream db("memory_signatures.db");
    db << "memory_test_pattern,Memory.Test\n";
    db.close();
    
    for (auto _ : state) {
        ThreatEngine engine("memory_signatures.db", "memory_quarantine");
        auto results = engine.scanDirectory("memory_test");
        benchmark::DoNotOptimize(results);
    }
    
    // Cleanup
    std::filesystem::remove_all("memory_test");
    std::filesystem::remove_all("memory_quarantine");
    std::filesystem::remove("memory_signatures.db");
    
    state.SetBytesProcessed(state.iterations() * state.range(0) * 1024 * 1024);
}

BENCHMARK(BM_MemoryUsage)
    ->Args({1})
    ->Args({5})
    ->Args({10})
    ->Unit(benchmark::kMillisecond);

// Concurrent scanning benchmark
static void BM_ConcurrentScanning(benchmark::State& state) {
    std::filesystem::create_directories("concurrent_test");
    
    // Create test files
    for (int i = 0; i < 100; ++i) {
        std::string filename = "concurrent_test/file_" + std::to_string(i) + ".txt";
        std::ofstream file(filename);
        file << "Test content " << i;
        if (i % 10 == 0) {
            file << " with concurrent_malware_pattern";
        }
        file.close();
    }
    
    std::ofstream db("concurrent_signatures.db");
    db << "concurrent_malware_pattern,Concurrent.Test\n";
    db.close();
    
    for (auto _ : state) {
        ThreatEngine engine("concurrent_signatures.db", "concurrent_quarantine");
        
        std::vector<std::thread> threads;
        std::atomic<int> completed{0};
        
        // Launch multiple scanning threads
        for (int i = 0; i < state.range(0); ++i) {
            threads.emplace_back([&engine, &completed, i]() {
                std::string file = "concurrent_test/file_" + std::to_string(i % 100) + ".txt";
                auto result = engine.scanFile(file);
                completed++;
            });
        }
        
        for (auto& t : threads) {
            t.join();
        }
        
        benchmark::DoNotOptimize(completed.load());
    }
    
    // Cleanup
    std::filesystem::remove_all("concurrent_test");
    std::filesystem::remove_all("concurrent_quarantine");
    std::filesystem::remove("concurrent_signatures.db");
}

BENCHMARK(BM_ConcurrentScanning)
    ->Args({1})
    ->Args({4})
    ->Args({8})
    ->Args({16})
    ->Unit(benchmark::kMillisecond);

// File monitor performance benchmark
static void BM_FileMonitorSetup(benchmark::State& state) {
    std::filesystem::create_directories("monitor_benchmark");
    
    std::ofstream db("monitor_signatures.db");
    db << "monitor_test_pattern,Monitor.Test\n";
    db.close();
    
    for (auto _ : state) {
        ThreatEngine engine("monitor_signatures.db", "monitor_quarantine");
        FileMonitor monitor(&engine);
        
        // Add directories to monitor
        for (int i = 0; i < state.range(0); ++i) {
            std::string dir = "monitor_benchmark/dir_" + std::to_string(i);
            std::filesystem::create_directories(dir);
            monitor.addDirectory(dir);
        }
        
        // Start and stop monitoring
        monitor.startMonitoring();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        monitor.stopMonitoring();
        
        benchmark::DoNotOptimize(monitor);
    }
    
    // Cleanup
    std::filesystem::remove_all("monitor_benchmark");
    std::filesystem::remove_all("monitor_quarantine");
    std::filesystem::remove("monitor_signatures.db");
}

BENCHMARK(BM_FileMonitorSetup)
    ->Args({1})
    ->Args({5})
    ->Args({10})
    ->Args({20})
    ->Unit(benchmark::kMillisecond);

// Custom main function for benchmark
int main(int argc, char** argv) {
    // Initialize Google Test
    ::testing::InitGoogleTest(&argc, argv);
    
    // Initialize Benchmark
    ::benchmark::Initialize(&argc, argv);
    
    if (::benchmark::ReportUnrecognizedArguments(argc, argv)) return 1;
    
    // Run benchmarks
    ::benchmark::RunSpecifiedBenchmarks();
    
    // Cleanup
    BenchmarkFixture::TearDownStatic();
    
    // Run any remaining tests
    return RUN_ALL_TESTS();
}
