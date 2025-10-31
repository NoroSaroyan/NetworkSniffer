/**
 * @file Sniffer.h
 * @brief Berkeley Packet Filter (BPF) device management and packet capture interface
 * 
 * This header defines the Sniffer class which encapsulates all BPF device interactions
 * for network packet capture on macOS. It provides a high-level interface for opening
 * BPF devices, configuring network interfaces, and continuously reading packets.
 * 
 * The class follows RAII principles for automatic resource management and provides
 * exception-safe operations for robust network monitoring.
 */

#pragma once

#include <string>
#include <vector>

/**
 * @class Sniffer
 * @brief Network packet capture class using Berkeley Packet Filter (BPF)
 * 
 * The Sniffer class provides a complete interface for capturing network packets
 * at the link layer using macOS's BPF subsystem. It handles device discovery,
 * interface binding, real-time configuration, and continuous packet reading.
 * 
 * Key features:
 * - Automatic BPF device discovery and allocation
 * - Network interface binding and configuration  
 * - Real-time packet capture with immediate mode
 * - RAII-based resource management
 * - Exception-safe error handling
 * 
 * Usage example:
 * @code
 * try {
 *     Sniffer sniffer("en0");
 *     sniffer.run();  // Starts packet capture loop
 * } catch (const std::exception& e) {
 *     std::cerr << "Error: " << e.what() << std::endl;
 * }
 * @endcode
 */
class Sniffer {
public:
    /**
     * @brief Constructs a Sniffer instance for the specified network interface
     * 
     * Initializes the sniffer by opening an available BPF device and configuring
     * it for the specified network interface. This constructor performs all
     * necessary setup operations including device discovery, interface binding,
     * and buffer allocation.
     * 
     * @param iface Network interface name (e.g., "en0", "en1", "wlan0")
     * @throws std::runtime_error if BPF device cannot be opened or configured
     * @throws std::runtime_error if interface binding fails
     * @throws std::runtime_error if buffer allocation fails
     * 
     * @note Requires root privileges to access BPF devices
     * @see openBpfDevice(), configureInterface()
     */
    explicit Sniffer(const std::string& iface);
    
    /**
     * @brief Destructor - automatically cleans up BPF device resources
     * 
     * Ensures proper cleanup of BPF file descriptor and any allocated resources.
     * This destructor is exception-safe and will not throw.
     * 
     * @note Automatically called when Sniffer object goes out of scope
     */
    ~Sniffer();
    
    /**
     * @brief Starts the main packet capture loop
     * 
     * Begins continuous packet capture from the configured network interface.
     * This function runs indefinitely until interrupted by a signal or an
     * error occurs. Each captured packet is passed to the PacketParser for
     * analysis and display.
     * 
     * @throws std::runtime_error if packet reading fails
     * @note This function blocks until interrupted (typically by Ctrl+C)
     * @see doReadLoop(), PacketParser::parseAndPrint()
     */
    void run();

private:
    /**
     * @brief Discovers and opens an available BPF device
     * 
     * Iterates through /dev/bpf0 to /dev/bpf99 to find an available BPF device.
     * BPF devices are exclusive-use, so this function finds the first device
     * that can be opened successfully.
     * 
     * @return File descriptor of the opened BPF device
     * @throws std::runtime_error if no BPF devices are available
     * 
     * @note Requires root privileges to open BPF devices
     * @see man bpf(4) for BPF device documentation
     */
    int openBpfDevice();
    
    /**
     * @brief Configures the BPF device for the target network interface
     * 
     * Performs all necessary BPF device configuration including:
     * - Binding to the specified network interface (BIOCSETIF)
     * - Enabling immediate mode for real-time capture (BIOCIMMEDIATE)
     * - Querying and allocating optimal buffer size (BIOCGBLEN)
     * 
     * @throws std::runtime_error if interface binding fails
     * @throws std::runtime_error if immediate mode cannot be set
     * @throws std::runtime_error if buffer size cannot be determined
     * 
     * @see ioctl(2), bpf(4) for BPF configuration details
     */
    void configureInterface();
    
    /**
     * @brief Main packet reading loop - continuously captures and processes packets
     * 
     * Implements the core packet capture logic:
     * 1. Reads packet data from BPF device using read() system call
     * 2. Parses BPF record headers to extract individual packets
     * 3. Handles multiple packets per read() call (batch processing)
     * 4. Forwards each packet to PacketParser for analysis
     * 5. Properly advances through BPF records using alignment
     * 
     * @note Runs indefinitely until interrupted or error occurs
     * @note Uses BPF_WORDALIGN() for proper record alignment
     * @see struct bpf_hdr, BPF_WORDALIGN(), PacketParser::parseAndPrint()
     */
    void doReadLoop();

    // Member variables for BPF device and packet management
    
    /**
     * @brief File descriptor for the opened BPF device
     * 
     * Holds the file descriptor returned by open() for the BPF device.
     * Initialized to -1 to indicate unopened state. Used for all subsequent
     * ioctl() and read() operations on the BPF device.
     */
    int fd_ = -1;
    
    /**
     * @brief Target network interface name
     * 
     * Stores the network interface name (e.g., "en0", "wlan0") that this
     * sniffer instance is configured to monitor. Used in BIOCSETIF ioctl
     * to bind the BPF device to the specific interface.
     */
    std::string iface_;
    
    /**
     * @brief Packet capture buffer
     * 
     * Dynamically allocated buffer for storing packets read from the BPF device.
     * Size is determined by BIOCGBLEN ioctl call and typically ranges from
     * 4KB to 64KB depending on system configuration. Uses std::vector for
     * automatic memory management and exception safety.
     */
    std::vector<unsigned char> buffer_;
};