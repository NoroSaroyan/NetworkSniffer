# Testing Guide

## Overview

This directory contains automated testing scripts for the Network Sniffer project. The scripts have been updated to use environment variables for secure credential management.

## Security Setup

### 1. Environment Configuration

Create a `.env` file in the project root (one level up from this directory) with your sudo password:

```bash
# From the tests directory
cd ..
touch .env
chmod 600 .env  # Restrict access to owner only
```

Add the following content to `.env`:

```bash
# Required: Sudo password for automated testing
SUDO_PASSWORD=your_actual_password

# Optional: Default network interface (defaults to en0)
DEFAULT_INTERFACE=en0

# Optional: Test configuration (defaults provided)
TEST_DURATION=10
PACKET_LIMIT=20
```

### 2. Security Best Practices

**File Permissions**: Set `.env` to 600 (owner read/write only)
```bash
chmod 600 ../.env
```

**Git Ignore**: The `.env` file is automatically ignored by git
**No Hardcoded Passwords**: Scripts no longer contain passwords
**Environment Validation**: Scripts validate required variables are set

## Available Tests

### 1. Quick Test (`quick_test.sh`)

**Purpose**: Fast verification that the sniffer works correctly

**Usage**:
```bash
cd tests
./quick_test.sh
```

**What it does**:
- Loads configuration from `.env`
- Verifies sniffer executable exists
- Runs sniffer for 5 seconds while generating test traffic
- Shows real-time packet capture output

**Requirements**:
- `.env` file with `SUDO_PASSWORD`
- Built sniffer executable (`../sniffer`)
- Network interface specified in `.env` (or defaults to en0)

### 2. Comprehensive Test (`automated_test_macos.sh`)

**Purpose**: Complete validation against tcpdump with detailed analysis

**Usage**:
```bash
cd tests
./automated_test_macos.sh
```

**What it does**:
- Loads configuration from `.env`
- Runs both tcpdump and our sniffer simultaneously
- Generates various types of network traffic (ICMP, UDP, TCP)
- Compares packet capture results
- Generates detailed analysis reports
- Saves all output to timestamped files in `test_results/`

**Output Files**:
- `test_log_TIMESTAMP.txt` - Main test summary and analysis
- `tcpdump_output_TIMESTAMP.txt` - Reference tcpdump capture
- `sniffer_output_TIMESTAMP.txt` - Our sniffer capture results
- `traffic_log_TIMESTAMP.txt` - Generated test traffic log

## Running Tests

### Prerequisites

1. **Build the sniffer**:
```bash
cd ..
make
```

2. **Configure environment**:
```bash
# Create .env file with your sudo password
echo "SUDO_PASSWORD=your_password" > .env
chmod 600 .env
```

3. **Verify setup**:
```bash
cd tests
ls -la ../.env      # Should show 600 permissions
ls -la ../sniffer  # Should exist and be executable
```

### Quick Validation

```bash
cd tests
./quick_test.sh
```

### Comprehensive Testing

```bash
cd tests
./automated_test_macos.sh
```

## Troubleshooting

### Common Issues

#### 1. "SUDO_PASSWORD not set"
```bash
# Solution: Create or update .env file
echo "SUDO_PASSWORD=your_password" > ../.env
chmod 600 ../.env
```

#### 2. "sniffer executable not found"
```bash
# Solution: Build the project
cd ..
make
```

#### 3. "Permission denied"
```bash
# Solution: Verify .env file has correct password
cat ../.env
# Update if necessary
```

#### 4. "Interface not found"
```bash
# Solution: Check available interfaces
ifconfig | grep -E "^[a-z]" | cut -d: -f1
# Update DEFAULT_INTERFACE in .env if needed
```

### Debugging

#### Enable Verbose Output
Add debugging to test scripts:
```bash
# Add to beginning of script after source .env
set -x  # Enable command tracing
```

#### Check BPF Device Access
```bash
# Test BPF access manually
sudo ls -la /dev/bpf*
```

#### Verify Network Traffic
```bash
# Test with system tcpdump
sudo tcpdump -i en0 -c 5
```

## Test Output Analysis

### Expected Results

When tests run successfully, you should see:

#### Quick Test Success:
```
Loaded configuration from ../.env
Sniffer executable found
Starting our sniffer for 5 seconds...
Generating test traffic...
2025-11-01 HH:MM:SS.UUUUUU src_ip:port -> dst_ip:port PROTOCOL len=X
...
Test completed!
```

#### Comprehensive Test Success:
```
tcpdump captured packets: 20
Our sniffer captured packets: 100+
No errors in sniffer output
Testing complete!
```

### Validation Criteria

**Packet Capture**: Both tools capture network packets
**Timestamp Accuracy**: Timestamps match within microseconds  
**Protocol Parsing**: Correct identification of TCP/UDP/ICMP
**Address Resolution**: Proper IP address and port extraction
**No Crashes**: Stable operation throughout test duration

## Security Considerations

### Password Management

- **Environment Variables**: Passwords stored in `.env`, not in scripts
- **File Permissions**: `.env` restricted to owner access (600)
- **Git Ignore**: Automatic exclusion from version control
- **Validation**: Scripts verify password is set before use

### Network Monitoring Ethics

- **Authorized Networks Only**: Only test on networks you own
- **Temporary Testing**: Remove sensitive configurations after testing
- **Data Privacy**: Be mindful of captured network information

### Cleanup

After testing, consider:
```bash
# Remove test results
rm -rf test_results/

# Clear .env file (optional)
> ../.env

# Or remove it entirely
rm ../.env
```

## Integration with CI/CD

For automated testing in CI/CD pipelines:

```bash
# Set environment variable in CI system
export SUDO_PASSWORD="ci_password"

# Or use CI-specific secrets management
echo "$CI_SUDO_PASSWORD" > .env
chmod 600 .env
```

## Contributing

When adding new tests:

1. **Use Environment Variables**: Never hardcode credentials
2. **Validate Input**: Check required variables are set
3. **Error Handling**: Provide clear error messages
4. **Documentation**: Update this README with new test descriptions
5. **Security**: Follow established security practices