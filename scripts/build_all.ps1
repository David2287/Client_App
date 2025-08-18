# Comprehensive Build Script for Professional Antivirus Application
# This script builds all components: Service, Client, Installer, and Tests

param(
    [string]$Configuration = "Release",
    [string]$Platform = "x64",
    [switch]$Clean,
    [switch]$BuildTests,
    [switch]$RunTests,
    [switch]$BuildInstaller,
    [switch]$Verbose
)

# Set error handling
$ErrorActionPreference = "Stop"

# Script configuration
$ScriptDir = $PSScriptRoot
$RootDir = Split-Path $ScriptDir -Parent
$BuildDir = Join-Path $RootDir "build"
$ServiceDir = Join-Path $RootDir "service"
$ClientDir = Join-Path $RootDir "client"
$InstallerDir = Join-Path $RootDir "installer"
$TestsDir = Join-Path $RootDir "tests"

# Build tools paths
$MSBuild = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
$CMake = "cmake"
$Cargo = "cargo"
$WixToolset = "${env:ProgramFiles(x86)}\WiX Toolset v3.11\bin"

# Logging function
function Write-BuildLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARN" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-Prerequisites {
    Write-BuildLog "Checking build prerequisites..."
    
    # Check Visual Studio/MSBuild
    if (-not (Test-Path $MSBuild)) {
        $MSBuild = "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
        if (-not (Test-Path $MSBuild)) {
            throw "MSBuild not found. Please install Visual Studio 2022 or Build Tools."
        }
    }
    
    # Check CMake
    try {
        & $CMake --version | Out-Null
    }
    catch {
        throw "CMake not found. Please install CMake and add to PATH."
    }
    
    # Check Rust/Cargo
    try {
        & $Cargo --version | Out-Null
    }
    catch {
        throw "Cargo not found. Please install Rust toolchain."
    }
    
    # Check Node.js (for Tauri client)
    try {
        & node --version | Out-Null
        & npm --version | Out-Null
    }
    catch {
        throw "Node.js/NPM not found. Please install Node.js."
    }
    
    # Check WiX Toolset (if building installer)
    if ($BuildInstaller) {
        if (-not (Test-Path $WixToolset)) {
            Write-BuildLog "WiX Toolset not found. Installer build will be skipped." "WARN"
            $script:BuildInstaller = $false
        }
    }
    
    Write-BuildLog "Prerequisites check completed successfully." "SUCCESS"
}

function Initialize-BuildEnvironment {
    Write-BuildLog "Initializing build environment..."
    
    # Create build directory
    if ($Clean -and (Test-Path $BuildDir)) {
        Write-BuildLog "Cleaning build directory..."
        Remove-Item $BuildDir -Recurse -Force
    }
    
    if (-not (Test-Path $BuildDir)) {
        New-Item -ItemType Directory -Path $BuildDir | Out-Null
    }
    
    # Set environment variables
    $env:ANTIVIRUS_ROOT = $RootDir
    $env:ANTIVIRUS_BUILD = $BuildDir
    $env:ANTIVIRUS_CONFIG = $Configuration
    $env:ANTIVIRUS_PLATFORM = $Platform
    
    Write-BuildLog "Build environment initialized." "SUCCESS"
}

function Build-ServiceComponents {
    Write-BuildLog "Building C++ Service Components..."
    
    $ServiceBuildDir = Join-Path $BuildDir "service"
    if (-not (Test-Path $ServiceBuildDir)) {
        New-Item -ItemType Directory -Path $ServiceBuildDir | Out-Null
    }
    
    Push-Location $ServiceBuildDir
    try {
        # Configure with CMake
        Write-BuildLog "Configuring service build with CMake..."
        & $CMake $ServiceDir -G "Visual Studio 17 2022" -A $Platform `
            -DCMAKE_BUILD_TYPE=$Configuration `
            -DBUILD_TESTS=$BuildTests.ToString().ToLower() `
            -DBUILD_SHARED_LIBS=OFF `
            -DCMAKE_INSTALL_PREFIX="$BuildDir\install\service"
        
        if ($LASTEXITCODE -ne 0) {
            throw "CMake configuration failed"
        }
        
        # Build
        Write-BuildLog "Building service components..."
        & $CMake --build . --config $Configuration --parallel
        
        if ($LASTEXITCODE -ne 0) {
            throw "Service build failed"
        }
        
        # Install
        Write-BuildLog "Installing service components..."
        & $CMake --install . --config $Configuration
        
        if ($LASTEXITCODE -ne 0) {
            throw "Service installation failed"
        }
        
        Write-BuildLog "Service components built successfully." "SUCCESS"
    }
    finally {
        Pop-Location
    }
}

function Build-ClientApplication {
    Write-BuildLog "Building Tauri Client Application..."
    
    Push-Location $ClientDir
    try {
        # Install Node.js dependencies
        Write-BuildLog "Installing Node.js dependencies..."
        & npm install
        
        if ($LASTEXITCODE -ne 0) {
            throw "npm install failed"
        }
        
        # Build Tauri application
        Write-BuildLog "Building Tauri application..."
        
        $tauriCmd = if ($Configuration -eq "Release") { "build" } else { "build --debug" }
        & cargo tauri $tauriCmd.Split(' ')
        
        if ($LASTEXITCODE -ne 0) {
            throw "Tauri build failed"
        }
        
        # Copy built application to install directory
        $ClientInstallDir = Join-Path $BuildDir "install\client"
        if (-not (Test-Path $ClientInstallDir)) {
            New-Item -ItemType Directory -Path $ClientInstallDir -Recurse | Out-Null
        }
        
        $BuiltApp = Join-Path $ClientDir "src-tauri\target\$Configuration\antivirus-client.exe"
        if (Test-Path $BuiltApp) {
            Copy-Item $BuiltApp $ClientInstallDir -Force
        }
        
        Write-BuildLog "Client application built successfully." "SUCCESS"
    }
    finally {
        Pop-Location
    }
}

function Build-Tests {
    if (-not $BuildTests) {
        Write-BuildLog "Test building skipped."
        return
    }
    
    Write-BuildLog "Building test suites..."
    
    # Build unit tests
    $UnitTestDir = Join-Path $TestsDir "unit"
    $UnitTestBuildDir = Join-Path $BuildDir "tests\unit"
    
    if (-not (Test-Path $UnitTestBuildDir)) {
        New-Item -ItemType Directory -Path $UnitTestBuildDir -Recurse | Out-Null
    }
    
    Push-Location $UnitTestBuildDir
    try {
        & $CMake $UnitTestDir -G "Visual Studio 17 2022" -A $Platform `
            -DCMAKE_BUILD_TYPE=$Configuration `
            -DGTEST_ROOT="${env:VCPKG_ROOT}\installed\x64-windows"
        
        if ($LASTEXITCODE -ne 0) {
            throw "Unit tests CMake configuration failed"
        }
        
        & $CMake --build . --config $Configuration
        
        if ($LASTEXITCODE -ne 0) {
            throw "Unit tests build failed"
        }
    }
    finally {
        Pop-Location
    }
    
    # Build integration tests
    $IntegrationTestDir = Join-Path $TestsDir "integration"
    $IntegrationTestBuildDir = Join-Path $BuildDir "tests\integration"
    
    if (-not (Test-Path $IntegrationTestBuildDir)) {
        New-Item -ItemType Directory -Path $IntegrationTestBuildDir -Recurse | Out-Null
    }
    
    Push-Location $IntegrationTestBuildDir
    try {
        & $CMake $IntegrationTestDir -G "Visual Studio 17 2022" -A $Platform `
            -DCMAKE_BUILD_TYPE=$Configuration
        
        if ($LASTEXITCODE -ne 0) {
            throw "Integration tests CMake configuration failed"
        }
        
        & $CMake --build . --config $Configuration
        
        if ($LASTEXITCODE -ne 0) {
            throw "Integration tests build failed"
        }
    }
    finally {
        Pop-Location
    }
    
    Write-BuildLog "Test suites built successfully." "SUCCESS"
}

function Run-Tests {
    if (-not $RunTests -or -not $BuildTests) {
        Write-BuildLog "Test execution skipped."
        return
    }
    
    Write-BuildLog "Running test suites..."
    
    $TestResultsDir = Join-Path $BuildDir "test-results"
    if (-not (Test-Path $TestResultsDir)) {
        New-Item -ItemType Directory -Path $TestResultsDir | Out-Null
    }
    
    # Run unit tests
    $UnitTestExe = Join-Path $BuildDir "tests\unit\$Configuration\unit_tests.exe"
    if (Test-Path $UnitTestExe) {
        Write-BuildLog "Running unit tests..."
        & $UnitTestExe --gtest_output="xml:$TestResultsDir\unit_test_results.xml"
        
        if ($LASTEXITCODE -ne 0) {
            Write-BuildLog "Some unit tests failed." "WARN"
        } else {
            Write-BuildLog "Unit tests passed." "SUCCESS"
        }
    }
    
    # Run integration tests
    $IntegrationTestExe = Join-Path $BuildDir "tests\integration\$Configuration\integration_tests.exe"
    if (Test-Path $IntegrationTestExe) {
        Write-BuildLog "Running integration tests..."
        & $IntegrationTestExe --gtest_output="xml:$TestResultsDir\integration_test_results.xml"
        
        if ($LASTEXITCODE -ne 0) {
            Write-BuildLog "Some integration tests failed." "WARN"
        } else {
            Write-BuildLog "Integration tests passed." "SUCCESS"
        }
    }
}

function Build-Installer {
    if (-not $BuildInstaller) {
        Write-BuildLog "Installer build skipped."
        return
    }
    
    Write-BuildLog "Building MSI Installer..."
    
    # Build custom actions DLL first
    $CustomActionsDir = Join-Path $InstallerDir "CustomActions"
    $CustomActionsBuildDir = Join-Path $BuildDir "installer\customactions"
    
    if (-not (Test-Path $CustomActionsBuildDir)) {
        New-Item -ItemType Directory -Path $CustomActionsBuildDir -Recurse | Out-Null
    }
    
    Push-Location $CustomActionsBuildDir
    try {
        & $CMake $CustomActionsDir -G "Visual Studio 17 2022" -A $Platform `
            -DCMAKE_BUILD_TYPE=$Configuration
        
        if ($LASTEXITCODE -ne 0) {
            throw "Custom actions CMake configuration failed"
        }
        
        & $CMake --build . --config $Configuration
        
        if ($LASTEXITCODE -ne 0) {
            throw "Custom actions build failed"
        }
    }
    finally {
        Pop-Location
    }
    
    # Build WiX installer
    Push-Location $InstallerDir
    try {
        $WixCandle = Join-Path $WixToolset "candle.exe"
        $WixLight = Join-Path $WixToolset "light.exe"
        
        # Compile WiX source
        Write-BuildLog "Compiling WiX sources..."
        & $WixCandle -ext WixUtilExtension -ext WixFirewallExtension `
            -dConfiguration=$Configuration `
            -dPlatform=$Platform `
            -dServicePath="$BuildDir\install\service\AntivirusService.exe" `
            -dClientPath="$BuildDir\install\client\antivirus-client.exe" `
            -dCustomActionsPath="$CustomActionsBuildDir\$Configuration\CustomActions.CA.dll" `
            -out "$BuildDir\installer\" `
            Product.wxs
        
        if ($LASTEXITCODE -ne 0) {
            throw "WiX compilation failed"
        }
        
        # Link installer
        Write-BuildLog "Linking MSI installer..."
        & $WixLight -ext WixUIExtension -ext WixUtilExtension -ext WixFirewallExtension `
            -out "$BuildDir\installer\ProfessionalAntivirus.msi" `
            "$BuildDir\installer\Product.wixobj"
        
        if ($LASTEXITCODE -ne 0) {
            throw "WiX linking failed"
        }
        
        Write-BuildLog "MSI Installer built successfully." "SUCCESS"
    }
    finally {
        Pop-Location
    }
}

function Create-DeploymentPackage {
    Write-BuildLog "Creating deployment package..."
    
    $DeployDir = Join-Path $BuildDir "deploy"
    if (Test-Path $DeployDir) {
        Remove-Item $DeployDir -Recurse -Force
    }
    New-Item -ItemType Directory -Path $DeployDir | Out-Null
    
    # Copy service components
    $ServiceInstallDir = Join-Path $BuildDir "install\service"
    if (Test-Path $ServiceInstallDir) {
        Copy-Item $ServiceInstallDir (Join-Path $DeployDir "Service") -Recurse -Force
    }
    
    # Copy client application
    $ClientInstallDir = Join-Path $BuildDir "install\client"
    if (Test-Path $ClientInstallDir) {
        Copy-Item $ClientInstallDir (Join-Path $DeployDir "Client") -Recurse -Force
    }
    
    # Copy installer
    $InstallerFile = Join-Path $BuildDir "installer\ProfessionalAntivirus.msi"
    if (Test-Path $InstallerFile) {
        Copy-Item $InstallerFile $DeployDir -Force
    }
    
    # Copy documentation
    $DocsDir = Join-Path $RootDir "docs"
    if (Test-Path $DocsDir) {
        Copy-Item $DocsDir (Join-Path $DeployDir "Documentation") -Recurse -Force
    }
    
    # Copy configuration files
    $ConfigFiles = @(
        "service_config.xml",
        "client_config.json",
        "signatures.db",
        "heuristics.xml"
    )
    
    foreach ($configFile in $ConfigFiles) {
        $sourcePath = Join-Path $RootDir "config\$configFile"
        if (Test-Path $sourcePath) {
            Copy-Item $sourcePath $DeployDir -Force
        }
    }
    
    # Create deployment info file
    $deploymentInfo = @{
        BuildDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Configuration = $Configuration
        Platform = $Platform
        Version = "1.0.0"
        Components = @{
            Service = Test-Path (Join-Path $DeployDir "Service")
            Client = Test-Path (Join-Path $DeployDir "Client")
            Installer = Test-Path (Join-Path $DeployDir "ProfessionalAntivirus.msi")
        }
    } | ConvertTo-Json -Depth 3
    
    $deploymentInfo | Out-File (Join-Path $DeployDir "deployment-info.json") -Encoding UTF8
    
    Write-BuildLog "Deployment package created successfully." "SUCCESS"
}

function Show-BuildSummary {
    Write-BuildLog "=== BUILD SUMMARY ===" "SUCCESS"
    Write-BuildLog "Configuration: $Configuration" "INFO"
    Write-BuildLog "Platform: $Platform" "INFO"
    Write-BuildLog "Build Directory: $BuildDir" "INFO"
    
    $components = @()
    
    if (Test-Path (Join-Path $BuildDir "install\service\AntivirusService.exe")) {
        $components += "✓ Service Components"
    } else {
        $components += "✗ Service Components"
    }
    
    if (Test-Path (Join-Path $BuildDir "install\client\antivirus-client.exe")) {
        $components += "✓ Client Application"
    } else {
        $components += "✗ Client Application"
    }
    
    if ($BuildTests) {
        if (Test-Path (Join-Path $BuildDir "tests\unit\$Configuration\unit_tests.exe")) {
            $components += "✓ Unit Tests"
        } else {
            $components += "✗ Unit Tests"
        }
        
        if (Test-Path (Join-Path $BuildDir "tests\integration\$Configuration\integration_tests.exe")) {
            $components += "✓ Integration Tests"
        } else {
            $components += "✗ Integration Tests"
        }
    }
    
    if ($BuildInstaller) {
        if (Test-Path (Join-Path $BuildDir "installer\ProfessionalAntivirus.msi")) {
            $components += "✓ MSI Installer"
        } else {
            $components += "✗ MSI Installer"
        }
    }
    
    foreach ($component in $components) {
        Write-BuildLog $component "INFO"
    }
    
    if (Test-Path (Join-Path $BuildDir "deploy")) {
        Write-BuildLog "✓ Deployment Package" "SUCCESS"
    }
    
    Write-BuildLog "Build completed successfully!" "SUCCESS"
}

# Main execution
try {
    Write-BuildLog "Starting Professional Antivirus build process..." "SUCCESS"
    Write-BuildLog "Configuration: $Configuration, Platform: $Platform"
    
    Test-Prerequisites
    Initialize-BuildEnvironment
    
    Build-ServiceComponents
    Build-ClientApplication
    
    if ($BuildTests) {
        Build-Tests
        
        if ($RunTests) {
            Run-Tests
        }
    }
    
    if ($BuildInstaller) {
        Build-Installer
    }
    
    Create-DeploymentPackage
    Show-BuildSummary
    
    Write-BuildLog "All build operations completed successfully!" "SUCCESS"
}
catch {
    Write-BuildLog "Build failed: $($_.Exception.Message)" "ERROR"
    exit 1
}
