# Antivirus Application

A modern antivirus solution built with C++ Windows Service backend and Tauri 2.0 frontend.

## Architecture

- **Service Component**: C++ Windows Service for core antivirus functionality
- **Client Component**: Tauri 2.0 GUI for user interaction
- **Communication**: Named Pipes with DACL security
- **Licensing**: Built-in activation and authentication system

## Components

### Service (C++)
- Windows Service with auto-start capability
- Real-time file system monitoring
- Threat detection and quarantine
- Scheduled scanning
- Named pipe server for client communication

### Client (Tauri 2.0)
- Hidden startup with system tray
- Modern web-based UI
- License activation and authentication
- Real-time status updates
- Settings and configuration management

### Shared
- Common data structures and protocols
- Signature database format
- Communication protocols

## Building

### Prerequisites
- Visual Studio 2022 with C++ workload
- Rust (latest stable)
- Node.js 18+
- Tauri CLI: `cargo install tauri-cli@2.0.0-beta`

### Build Instructions

1. Build the Windows Service:
```cmd
cd service
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022"
cmake --build . --config Release
```

2. Build the Tauri Client:
```cmd
cd client
npm install
cargo tauri build
```

3. Create Installer:
```cmd
cd installer
# Instructions for WiX Toolset setup
```

## Installation

Run the installer as Administrator to:
- Install and register the Windows Service
- Deploy the client application
- Configure system permissions
- Setup automatic startup

## Security Features

- DACL-secured named pipes
- Service runs with appropriate privileges
- Encrypted communication between components
- Secure signature verification
- Protected quarantine storage

## License

Proprietary software with activation system.
