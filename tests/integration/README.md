# Integration Tests

This directory contains comprehensive integration tests for the antivirus service that validate end-to-end functionality by combining multiple components.

## Test Structure

### 1. Core Integration Tests (`test_integration.cpp`)
Tests the interaction between `ThreatEngine` and `FileMonitor` components:

- **Complete Workflow Tests**: Full malware detection and quarantine workflow
- **Real-time Monitoring**: End-to-end file system monitoring and threat response
- **Mixed File Types**: Scanning various file formats and extensions
- **Quarantine & Restore**: Complete quarantine lifecycle including restoration
- **Concurrent Operations**: Multi-threaded stability testing
- **EICAR Handling**: Standard antivirus test file detection
- **Performance Tests**: Large-scale file scanning performance

### 2. Service Integration Tests (`test_service_integration.cpp`)
Tests the Windows Service functionality and service lifecycle:

- **Service Initialization**: Configuration and component setup
- **Service Lifecycle**: Start/stop operations and state management
- **Real-time Protection**: Service-level monitoring integration
- **Manual Scanning**: Service-controlled scanning operations
- **Statistics Tracking**: Performance and activity monitoring
- **Error Handling**: Recovery from various error conditions
- **Configuration Updates**: Runtime configuration changes
- **Quarantine Management**: Service-level quarantine operations
- **Performance Load Testing**: Service performance under heavy load

### 3. Benchmark Tests (`test_benchmark.cpp`)
Performance benchmarking using Google Benchmark:

- **File Scanning Performance**: Measures scanning speed with various file counts
- **Single File Scanning**: Microsecond-level single file scan timing
- **Signature Loading**: Database initialization performance
- **Quarantine Operations**: Quarantine/restore operation timing
- **Memory Usage**: Memory consumption under different loads
- **Concurrent Scanning**: Multi-threaded scanning performance
- **File Monitor Setup**: Real-time monitoring initialization performance

## Configuration

The tests use `test_config.ini` for configuration parameters:

```ini
[General]
test_mode=true
log_level=DEBUG

[ThreatEngine]
signature_db_path=test_signatures.db
quarantine_path=test_quarantine
max_file_size=104857600

[FileMonitor]
real_time_protection=true
worker_threads=4

[Performance]
max_memory_usage=536870912
thread_pool_size=8
```

## Running the Tests

### Prerequisites
- Google Test (gtest) library
- Google Benchmark library (for benchmark tests)
- CMake 3.15 or higher
- C++17 compatible compiler

### Build and Run
```bash
# From the build directory
cmake --build . --target integration_tests
ctest -R IntegrationTests

# Or run directly
./tests/integration/integration_tests

# Run with specific output format
./integration_tests --gtest_output=xml:results.xml

# Run benchmark tests
./integration_tests --benchmark_format=json
```

### Using CMake Targets
```bash
# Run integration tests specifically
cmake --build . --target run_integration_tests

# This will:
# 1. Build the integration test executable
# 2. Run tests with XML output
# 3. Generate results in test_output/ directory
```

## Test Environment

The integration tests create temporary directories and files:

- `integration_test/` - Main test file directory
- `integration_quarantine/` - Quarantine storage
- `integration_scan/` - Mixed file type testing
- `service_test_*` - Service-specific test directories
- `benchmark_*` - Performance test directories

All test artifacts are automatically cleaned up after test completion.

## Test Data

### Signature Database
Tests use a comprehensive signature database with patterns for:
- EICAR standard test file
- Generic malware patterns
- Trojan signatures
- Virus patterns
- Rootkit signatures

### Test Files
Integration tests create various file types:
- Clean text documents
- Infected files with known signatures
- Binary executables
- Archive files
- Large files for performance testing
- Concurrent access test files

## Expected Results

### Performance Benchmarks
Typical performance expectations:
- Single file scan: < 1ms per file
- Directory scan (100 files): < 10 seconds
- Quarantine operation: < 100ms
- Service startup: < 2 seconds
- Memory usage: < 512MB for 100 files

### Functionality Tests
All integration tests should pass with:
- 100% threat detection accuracy for known signatures
- Zero false positives on clean files
- Successful quarantine and restore operations
- Stable multi-threaded operations
- Proper service lifecycle management

## Troubleshooting

### Common Issues
1. **Permission Errors**: Ensure write access to test directories
2. **File Locks**: Check that no antivirus is scanning test files
3. **Timing Issues**: Real-time tests may need adjustment for slow systems
4. **Memory Limits**: Large performance tests may require sufficient RAM

### Debug Information
Enable debug logging by setting:
```ini
log_level=DEBUG
```

Logs are written to `service_integration_test.log` during test execution.

## Integration with CI/CD

These tests are designed for continuous integration:

```yaml
# Example CI configuration
test:
  script:
    - mkdir build && cd build
    - cmake .. -DBUILD_TESTS=ON
    - cmake --build . --target integration_tests
    - ctest -R IntegrationTests --output-on-failure
  artifacts:
    reports:
      junit: build/test_output/integration_results.xml
```

## Contributing

When adding new integration tests:

1. Follow the existing test structure and naming conventions
2. Include both positive and negative test cases
3. Add appropriate cleanup in `TearDown()` methods
4. Update this README with new test descriptions
5. Ensure tests are deterministic and don't rely on external resources

## Performance Considerations

Integration tests are designed to:
- Complete within 5 minutes total runtime
- Use minimal system resources during testing
- Clean up all temporary files and directories
- Provide meaningful performance metrics
- Scale appropriately with available hardware

For performance-critical changes, always run benchmark tests to ensure no regressions.
