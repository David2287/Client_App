# Build Instructions

## Prerequisites

### Development Tools
1. **Visual Studio 2022** with C++ workload
   - Windows 10 SDK
   - CMake tools for Visual Studio
   - MSVC v143 - VS 2022 C++ x64/x86 build tools

2. **Rust (latest stable)**
   ```bash
   # Install Rust from https://rustup.rs/
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

3. **Node.js 18+**
   ```bash
   # Download from https://nodejs.org/
   # Verify installation
   node --version
   npm --version
   ```

4. **Tauri CLI 2.0 Beta**
   ```bash
   cargo install tauri-cli@2.0.0-beta
   ```

### System Requirements
- Windows 10/11 (x64)
- Administrator privileges for service installation
- At least 4GB RAM
- 1GB free disk space

## Building the Application

### 1. Clone and Setup
```bash
cd C:\Users\WhySkyDie\antivirus-app
```

### 2. Build the Windows Service

```bash
cd service
mkdir build
cd build

# Configure with CMake
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release
```

The service executable will be created at:
`service/build/bin/Release/AntivirusService.exe`

### 3. Build the Tauri Client

```bash
cd ../../client

# Install dependencies
npm install

# Build for production
cargo tauri build
```

The client executable will be created at:
`client/src-tauri/target/release/antivirus-client.exe`

## Installation and Testing

### 1. Install the Service (Run as Administrator)

```cmd
cd service\build\bin\Release
AntivirusService.exe -install
```

### 2. Start the Service

```cmd
net start AntivirusService
```
Or use Services.msc to start "Antivirus Protection Service"

### 3. Run the Client

```cmd
cd client\src-tauri\target\release
antivirus-client.exe
```

### 4. Testing in Development Mode

For development and testing:

#### Run Service in Console Mode
```cmd
cd service\build\bin\Release
AntivirusService.exe -console
```

#### Run Client in Development Mode
```bash
cd client
npm run tauri dev
```

## Configuration

### Service Configuration
The service creates configuration and logs in:
- `C:\ProgramData\AntivirusService\`
- `C:\ProgramData\AntivirusService\Logs\`

### Client Configuration
Client settings are stored in:
- `%APPDATA%\AntivirusClient\`

## Troubleshooting

### Service Won't Start
1. Check Windows Event Viewer for errors
2. Verify service permissions
3. Run as Administrator
4. Check log files in `C:\ProgramData\AntivirusService\Logs\`

### Client Can't Connect to Service
1. Verify service is running: `sc query AntivirusService`
2. Check named pipe permissions
3. Verify Windows firewall settings
4. Run both service and client as Administrator

### Build Errors

#### C++ Service Build Issues
- Ensure Visual Studio C++ workload is installed
- Verify Windows SDK version
- Check CMake version (3.20+)
- Run `cmake --version` to verify installation

#### Rust/Tauri Build Issues
- Update Rust: `rustup update`
- Clear cargo cache: `cargo clean`
- Reinstall Tauri CLI: `cargo install tauri-cli@2.0.0-beta --force`

#### Node.js Issues
- Clear npm cache: `npm cache clean --force`
- Delete node_modules and reinstall: `rm -rf node_modules && npm install`
- Use Node.js LTS version

## Development Workflow

### 1. Service Development
```bash
# Build and test service
cd service/build
cmake --build . --config Debug
.\bin\Debug\AntivirusService.exe -console
```

### 2. Client Development
```bash
# Start development server
cd client
npm run tauri dev
```

### 3. Full Integration Testing
1. Build service in Release mode
2. Install and start service
3. Build and run client
4. Test all features

## Distribution

### Creating Distribution Package
1. Build both components in Release mode
2. Copy executables to distribution folder
3. Include installation scripts
4. Create installer package (see INSTALLER.md)

### Files to Distribute
```
antivirus-app/
├── AntivirusService.exe
├── antivirus-client.exe
├── install.bat
├── uninstall.bat
└── README.txt
```

## Security Considerations

1. **Code Signing**: Sign both executables for production
2. **Permissions**: Service runs as LocalSystem, client as user
3. **Communication**: Named pipes use DACL security
4. **Updates**: Implement secure update mechanism
5. **Logging**: Ensure logs don't contain sensitive data

## Performance Optimization

### Service Optimization
- Use release builds for production
- Enable compiler optimizations
- Profile memory usage
- Monitor CPU impact

### Client Optimization
- Minimize bundle size
- Optimize asset loading
- Use efficient state management
- Profile render performance

## Maintenance

### Log Rotation
Implement log rotation to prevent disk space issues:
- Service logs: Max 10MB, keep 5 files
- Client logs: Max 5MB, keep 3 files

### Database Updates
Plan for signature database updates:
- Automatic update checking
- Secure download mechanism
- Rollback capability
- Update verification

### Monitoring
Monitor application health:
- Service uptime
- Memory usage
- Error rates
- Performance metrics
