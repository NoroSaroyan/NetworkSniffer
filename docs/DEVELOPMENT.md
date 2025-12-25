# Development Guide - NetworkSniffer

Guide for developers and contributors working on the NetworkSniffer project. Covers development setup, build system, code organization, testing approach, and contribution guidelines.

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Project Structure](#project-structure)
3. [Build System](#build-system)
4. [Development Workflow](#development-workflow)
5. [Code Organization](#code-organization)
6. [Testing Approach](#testing-approach)
7. [Performance Profiling](#performance-profiling)
8. [Contributing](#contributing)
9. [Debugging](#debugging)

---

## Development Environment Setup

### Prerequisites

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install build tools
brew install cmake ninja

# Install Qt (for GUI development)
brew install qt@6  # or qt@5

# Install debugging tools
brew install lldb gdb

# Install code analysis tools
brew install clang-format
```

### IDE Setup

#### CLion (Recommended for C++)

1. Open project: `File → Open → /path/to/NetworkSniffer`
2. Configure CMake: `Settings → Build, Execution, Deployment → CMake`
3. Set build directory: `build`
4. Enable Qt plugin: `Settings → Plugins → Qt`

#### VS Code

```bash
# Install extensions
# - C/C++ (Microsoft)
# - CMake Tools (Microsoft)
# - Qt Tools (Qt Company)

# Create .vscode/settings.json
{
  "C_Cpp.defaultIncludePathIntelliSense": ["${workspaceFolder}/src"],
  "C_Cpp.cStandard": "c17",
  "C_Cpp.cppStandard": "c++17"
}
```

#### XCode

1. Generate XCode project: `cmake -G Xcode -B build`
2. Open: `open build/NetworkSniffer.xcodeproj`

---

## Project Structure

```
NetworkSniffer/
├── src/
│   ├── sniffer/                    # Packet capture component
│   │   ├── main.cpp               # Sniffer entry point
│   │   ├── Sniffer.h/.cpp        # BPF device management
│   │   └── PacketParser.h/.cpp   # Protocol parsing
│   │
│   ├── server/                     # Central server component
│   │   └── server.cpp             # TCP server implementation
│   │
│   ├── client/                     # GUI client component
│   │   ├── qt_main.cpp           # Qt application entry
│   │   ├── MainWindow.h/.cpp     # Main UI window
│   │   ├── SnifferClient.h/.cpp  # Server communication
│   │   ├── StatsWidget.h/.cpp    # Statistics display
│   │   └── ModernStyle.h         # UI styling
│   │
│   ├── logging/                    # Logging system
│   │   ├── Logger.h/.cpp         # Centralized logging
│   │   └── LogLevel.h            # Log severity levels
│   │
│   └── Protocol.h                  # Distributed protocol definitions
│
├── docs/                           # Documentation
│   ├── README.md                   # Project overview
│   ├── ARCHITECTURE.md            # System design
│   ├── API_REFERENCE.md           # Code documentation
│   ├── USAGE.md                   # User guide
│   ├── PROTOCOL.md                # Network protocol spec
│   ├── BPF_GUIDE.md               # BPF technical reference
│   └── DEVELOPMENT.md             # This file
│
├── CMakeLists.txt                  # Main CMake build config
├── Makefile                        # Legacy Makefile for sniffer
├── build/                          # Build output directory
│   ├── CMakeCache.txt
│   └── [compiled binaries]
│
└── tests/ (future)                 # Unit tests
    └── CMakeLists.txt
```

### File Naming Conventions

- **Headers**: `.h` extension with guard `#ifndef CLASSNAME_H`
- **Implementation**: `.cpp` for C++ files
- **Classes**: `CapitalizedName` (e.g., `Sniffer`, `PacketParser`)
- **Functions**: `camelCase` (e.g., `parsePacket()`)
- **Members**: `snake_case_` with trailing underscore for private members
- **Constants**: `UPPER_CASE` (e.g., `BUFFER_SIZE`)

---

## Build System

### Makefile (Legacy - Sniffer Only)

```bash
# Build sniffer
make

# Clean build artifacts
make clean

# Verbose output
make VERBOSE=1

# Specify compiler
make CXX=clang++
```

**Makefile Targets**:
- `all` - Build sniffer binary
- `clean` - Remove build artifacts
- `install` - Install binary (optional)

### CMake (Modern - All Components)

```bash
# Configure build
cmake -B build

# Build all targets
cmake --build build

# Build specific target
cmake --build build --target SnifferServer
cmake --build build --target SnifferGUI

# Release build (optimized)
cmake -DCMAKE_BUILD_TYPE=Release -B build
cmake --build build

# Debug build (with symbols)
cmake -DCMAKE_BUILD_TYPE=Debug -B build
cmake --build build

# Build with verbose output
cmake --build build -- VERBOSE=1

# Parallel build (8 jobs)
cmake --build build -j 8
```

### CMakeLists.txt Organization

```cmake
# Top-level: CMakeLists.txt
cmake_minimum_required(VERSION 3.16)
project(NetworkSniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
add_compile_options(-Wall -Wextra -O2)

# Find packages (Qt, etc.)
find_package(Qt6 COMPONENTS ...)

# Add subdirectories
add_executable(sniffer ...)
add_executable(SnifferServer ...)
add_executable(SnifferGUI ...)
```

### Incremental Development Build

```bash
# Quick rebuild during development
cd build
make -j 4         # On macOS/Linux with make

# Or with CMake
cmake --build . -j 4

# Automatic rebuild on file change (requires extra tools)
# Option 1: Use IDE built-in watch
# Option 2: Use external tool like entr or fswatch
find ../src -name "*.cpp" -o -name "*.h" | entr make -C .
```

---

## Development Workflow

### Creating a Feature Branch

```bash
# Create and switch to feature branch
git checkout -b feature/my-new-feature

# Make commits
git add .
git commit -m "feat: implement new feature"

# Keep branch updated
git fetch origin
git rebase origin/main

# Push branch
git push origin feature/my-new-feature
```

### Code Style and Formatting

```bash
# Check code style
clang-format --style=LLVM -i src/**/*.cpp src/**/*.h

# Automatic formatting with Git hook
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
clang-format -i $(git diff --cached --name-only | grep '\.(cpp|h)$')
git add $(git diff --cached --name-only)
EOF
chmod +x .git/hooks/pre-commit
```

### Testing Changes

```bash
# Build clean
rm -rf build && mkdir build && cd build
cmake .. && make

# Test sniffer locally
sudo ./sniffer en0

# Test server
./SnifferServer 9090

# Test distributed setup
# Terminal 1: server
./SnifferServer 9090
# Terminal 2: sniffer
sudo ./sniffer en0 127.0.0.1 9090
# Terminal 3: traffic
ping 8.8.8.8
```

---

## Code Organization

### Design Patterns Used

#### RAII (Resource Acquisition Is Initialization)

```cpp
class Sniffer {
public:
    explicit Sniffer(const std::string& iface) {
        // Acquire resources in constructor
        fd_ = openBpfDevice();  // May throw
        configureInterface();   // May throw
    }

    ~Sniffer() {
        // Cleanup in destructor (guaranteed)
        if (fd_ != -1) close(fd_);
    }

private:
    int fd_ = -1;  // File descriptor
};
```

**Benefit**: Exception-safe resource cleanup

#### Thread-per-Client

```cpp
// Server handles multiple clients concurrently
void acceptConnections() {
    while (accepting) {
        int client_fd = accept(...);
        std::thread handler(handleClient, client_fd);
        handler.detach();  // Background thread
    }
}
```

**Benefit**: Scalable to multiple sniffers and GUI clients

#### Static Utility Classes

```cpp
class PacketParser {
public:
    // Only static methods - no instantiation needed
    static void parseAndPrint(...);

private:
    static void parseEthernet(...);
    static void parseIPv4(...);
};
```

**Benefit**: Zero instantiation overhead, inherent thread safety

### Memory Management

**Approach**: Stack-based allocation with STL containers

```cpp
// Good - automatic cleanup
std::string iface("en0");
std::vector<unsigned char> buffer(4096);

// Avoid - manual memory management
unsigned char* buffer = new unsigned char[4096];
delete[] buffer;  // Easy to forget
```

**RAII Guidelines**:
- Use `std::string` for strings
- Use `std::vector` for dynamic arrays
- Use smart pointers (`std::unique_ptr`, `std::shared_ptr`) for complex objects
- Avoid raw `new`/`delete`

### Exception Handling

```cpp
// Prefer specific exceptions
if (ioctl(fd_, BIOCSETIF, &ifr) == -1) {
    throw std::runtime_error("Failed to bind interface: " + std::string(strerror(errno)));
}

// Never ignore errors
// Bad:
ioctl(fd_, BIOCSETIF, &ifr);  // Error ignored!

// Good:
if (ioctl(fd_, BIOCSETIF, &ifr) == -1) {
    throw std::runtime_error(...);
}
```

---

## Testing Approach

### Manual Testing

```bash
# 1. Test sniffer locally
sudo ./sniffer en0

# 2. Test with traffic generation
ping 8.8.8.8              # ICMP
curl https://example.com  # TCP
dig @8.8.8.8 google.com  # UDP

# 3. Test distributed mode
sudo ./sniffer en0 127.0.0.1 9090  # Connect to server

# 4. Test GUI
./SnifferGUI               # Should connect to server
```

### Protocol Testing

```bash
# Verify binary frame format
# Write raw bytes to server
echo -ne '\x01\x01\x00\x10{"hostname":"test"}' | nc 127.0.0.1 9090

# Capture and inspect
tcpdump -i lo -A 'port 9090'
```

### Performance Testing

```bash
# Stress test
for i in {1..1000}; do
    ping -c 1 8.8.8.8 > /dev/null &
done
wait

# Monitor sniffer
time sudo ./sniffer en0

# Check resource usage
# In Activity Monitor: CPU%, Memory
```

### Future Test Infrastructure

```bash
# Unit test structure (to be implemented)
tests/
├── CMakeLists.txt
├── test_packet_parser.cpp
├── test_sniffer.cpp
├── test_protocol.cpp
└── fixtures/
    ├── sample_packets.pcap
    └── mock_bpf_device.h
```

---

## Performance Profiling

### CPU Profiling

```bash
# Using Instruments (Xcode)
xcrun xctrace record --template 'System Trace' --launch ./sniffer en0

# Using clang profiling
clang++ -fprofile-instr-generate -fcoverage-mapping \
    src/main.cpp src/Sniffer.cpp src/PacketParser.cpp -o sniffer
LLVM_PROFILE_FILE="profile-%p.profraw" ./sniffer en0
llvm-profdata merge -o profile.profdata profile-*.profraw
llvm-cov report ./sniffer -instr-profile=profile.profdata
```

### Memory Profiling

```bash
# Valgrind (if available on macOS)
brew install valgrind  # Not officially supported on M1/M2

# macOS leaks tool
leaks -atExit -- ./sniffer en0

# Xcode Instruments
Instruments.app → Memory Leaks template
```

### Benchmarking

```cpp
// Micro-benchmark packet parsing
#include <chrono>

auto start = std::chrono::high_resolution_clock::now();
PacketParser::parseAndPrint(packet_data, caplen, timestamp);
auto end = std::chrono::high_resolution_clock::now();
auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
std::cout << "Parse time: " << duration.count() << " µs" << std::endl;
```

---

## Contributing

### Contribution Guidelines

1. **Fork** the repository (if external contributor)
2. **Create** feature branch: `git checkout -b feature/description`
3. **Code** following style guidelines
4. **Test** thoroughly with manual testing
5. **Document** changes in code comments and relevant docs
6. **Commit** with clear messages: `git commit -m "feat: description"`
7. **Push** to branch: `git push origin feature/description`
8. **Submit** pull request with description

### Code Review Checklist

- [ ] Follows C++17 standards
- [ ] Compiles without warnings (`-Wall -Wextra`)
- [ ] No memory leaks (RAII properly used)
- [ ] Exception-safe (no raw `new`/`delete`)
- [ ] Defensive programming (bounds checking, etc.)
- [ ] Documented (comments, function signatures)
- [ ] Tested (manual testing completed)
- [ ] Updated documentation if applicable

### Commit Message Format

```
feat: add new feature
Description of what this commit does

fix: resolve bug in packet parsing
- Fixed bounds checking in IPv4 header
- Added test case for edge case

docs: update API reference
- Added documentation for new classes
- Clarified protocol section

refactor: improve code organization
- Extracted common pattern into helper function
```

---

## Debugging

### GDB Debugging

```bash
# Build with debug symbols
cmake -DCMAKE_BUILD_TYPE=Debug -B build
cmake --build build

# Run with gdb
gdb ./build/sniffer

# Common gdb commands
(gdb) run en0              # Start program with arguments
(gdb) break main           # Set breakpoint
(gdb) c                    # Continue execution
(gdb) n                    # Next line
(gdb) s                    # Step into function
(gdb) p variable           # Print variable
(gdb) bt                   # Print backtrace
(gdb) quit                 # Exit gdb
```

### LLDB Debugging (Xcode's debugger)

```bash
# Run with lldb
lldb ./build/sniffer

# Common lldb commands
(lldb) run en0
(lldb) breakpoint set --name main
(lldb) continue
(lldb) gui  # Interactive GUI
(lldb) bt   # Backtrace
```

### Logging Debug Messages

```cpp
#include <iostream>
#include <sstream>

// Debug output
#ifndef NDEBUG
  std::cerr << "DEBUG: packet size = " << caplen << std::endl;
#endif

// Or use debug functions
void debug_print(const char* fmt, ...) {
#ifndef NDEBUG
    std::cerr << "[DEBUG] " << ...;
#endif
}
```

### Common Debugging Scenarios

#### Sniffer crashes on startup

```bash
# Build with debug info
cmake -DCMAKE_BUILD_TYPE=Debug -B build
cmake --build build

# Run with debugger
gdb --args ./build/sniffer en0
(gdb) run
# Should show backtrace on crash
```

#### Memory corruption

```bash
# Use AddressSanitizer
cmake -DSANITIZE_ADDRESS=ON -B build
cmake --build build
./build/sniffer en0  # Will report memory errors
```

#### Performance issues

```bash
# Profile with time
time ./sniffer en0 < traffic_file

# Use Instruments
xcrun xctrace record --template 'System Trace' -- ./sniffer en0
```

---

## Future Development

### Planned Enhancements

1. **IPv6 Support**
   - Extend PacketParser for IPv6 headers
   - Add IPv6 test cases
   - Location: `src/sniffer/PacketParser.cpp`

2. **BPF Filtering**
   - Implement kernel-level packet filters
   - Reduce CPU overhead
   - Add filter syntax parser

3. **PCAP Export**
   - Write captured traffic to `.pcap` files
   - Compatible with Wireshark
   - New component: `src/sniffer/PcapWriter.h/cpp`

4. **Advanced Statistics**
   - Per-protocol statistics
   - Bandwidth tracking
   - Connection flow analysis

5. **Unit Test Suite**
   - Mock BPF device
   - Test packet parsing
   - Verify protocol handling

### Contribution Areas

Looking for contributions in:
- Protocol support (IPv6, VLAN, etc.)
- Performance optimizations
- Cross-platform compatibility
- Documentation improvements
- Testing and bug fixes

---

## Reference Documentation

- [C++ Standard Reference](https://en.cppreference.com/)
- [CMake Documentation](https://cmake.org/documentation/)
- [macOS Berkeley Packet Filter](https://www.freebsd.org/cgi/man.cgi?query=bpf)
- [Qt Documentation](https://doc.qt.io/)
- [TCP/IP Illustrated](https://en.wikipedia.org/wiki/TCP/IP_Illustrated)

---

For questions or issues, refer to:
- [ARCHITECTURE.md](ARCHITECTURE.md) - System design
- [API_REFERENCE.md](API_REFERENCE.md) - Code documentation
- [BPF_GUIDE.md](BPF_GUIDE.md) - BPF technical details
