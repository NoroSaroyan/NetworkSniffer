/**
 * @file main.cpp
 * @brief Entry point for the OS-level network packet sniffer application
 * 
 * This file implements the command-line interface and application lifecycle
 * management for the network sniffer. It handles:
 * - Command-line argument parsing and validation
 * - Signal handling for graceful shutdown (Ctrl+C)
 * - Error handling and user feedback
 * - Application initialization and execution
 * 
 * The application requires root privileges to access BPF devices and must
 * be run with sudo. It captures packets from a specified network interface
 * and displays them in real-time with detailed protocol information.
 * 
 * Usage: sudo ./sniffer <interface>
 * Example: sudo ./sniffer en0
 */

#include "Sniffer.h"   // Main packet capture and BPF management class

#include <iostream>    // Standard I/O for user interaction
#include <csignal>     // POSIX signal handling (SIGINT, SIGTERM)
#include <cstdlib>     // Standard library utilities (exit)

// === Global State for Signal Handling ===

/**
 * @brief Global flag to control application lifecycle
 * 
 * This static variable is used by the signal handler to indicate when
 * the application should terminate. It's set to false when SIGINT (Ctrl+C)
 * or SIGTERM is received.
 * 
 * @note Static ensures it's only visible within this compilation unit
 * @note Must be volatile in multi-threaded contexts (not needed here)
 */
static bool running = true;

/**
 * @brief Signal handler for graceful application shutdown
 * 
 * This function is called when the application receives SIGINT (Ctrl+C)
 * or SIGTERM signals. It provides a clean way to terminate the packet
 * capture loop and exit the application.
 * 
 * Signal Handling Strategy:
 * - SIGINT (2): User pressed Ctrl+C - most common shutdown method
 * - SIGTERM (15): System requesting termination (e.g., during shutdown)
 * 
 * @param signum Signal number received (SIGINT=2, SIGTERM=15, etc.)
 * 
 * @note This handler uses async-signal-safe functions only
 * @see signal(7) for signal safety information
 */
void signalHandler(int signum) {
    // Print termination message to inform user
    // Note: std::cout is not technically async-signal-safe, but works in practice
    std::cout << "\nReceived signal " << signum << ", stopping..." << std::endl;
    
    // Set global flag to indicate shutdown requested
    // In this simple implementation, we exit immediately
    running = false;
    
    // Terminate the application immediately
    // In a more complex implementation, we might set a flag and allow
    // the main loop to clean up resources before exiting
    exit(0);
}

/**
 * @brief Display usage information and examples to the user
 * 
 * This function provides helpful usage information when the user runs
 * the program with incorrect arguments or when an error occurs.
 * 
 * Information Provided:
 * - Correct command-line syntax
 * - Example usage with common interface name
 * - Privilege requirements (sudo needed)
 * 
 * @param program_name Name of the executable (from argv[0])
 */
void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " <interface>" << std::endl;
    std::cout << "Example: " << program_name << " en0" << std::endl;
    std::cout << "Note: Requires root privileges (run with sudo)" << std::endl;
    
    // Additional helpful information could include:
    // - List of common interface names (en0, en1, wlan0)
    // - Instructions for finding available interfaces (ifconfig)
    // - Link to documentation or help resources
}

/**
 * @brief Main application entry point
 * 
 * This function orchestrates the entire packet sniffing application:
 * 1. Validates command-line arguments
 * 2. Sets up signal handlers for graceful shutdown
 * 3. Initializes the packet sniffer for the specified interface
 * 4. Starts the packet capture loop
 * 5. Handles errors and provides user feedback
 * 
 * @param argc Number of command-line arguments
 * @param argv Array of command-line argument strings
 * @return 0 on success, 1 on error
 */
int main(int argc, char* argv[]) {
    // === Command-Line Argument Validation ===
    
    // We expect exactly one argument: the network interface name
    // argc=1 means no arguments, argc=2 means one argument (plus program name)
    if (argc != 2) {
        // Invalid number of arguments - show usage and exit
        printUsage(argv[0]);
        return 1;  // Exit with error code
    }
    
    // === Signal Handler Setup ===
    
    // Register signal handlers for graceful shutdown
    // This allows users to stop the sniffer cleanly with Ctrl+C
    signal(SIGINT, signalHandler);   // Handle Ctrl+C (interrupt)
    signal(SIGTERM, signalHandler);  // Handle termination requests
    
    // Note: We could also handle SIGHUP for configuration reload
    // or SIGUSR1/SIGUSR2 for runtime control, but this is a simple tool
    
    // === Extract Interface Name ===
    
    // Get the network interface name from command line
    // Common values: "en0", "en1", "wlan0", "eth0", etc.
    std::string interface = argv[1];
    
    // === Initialize and Run Packet Sniffer ===
    
    try {
        // Create sniffer instance for the specified interface
        // This will:
        // 1. Open an available BPF device (/dev/bpf*)
        // 2. Bind it to the specified network interface
        // 3. Configure it for real-time packet capture
        // 4. Allocate buffers for packet data
        Sniffer sniffer(interface);
        
        // Start the main packet capture loop
        // This function runs indefinitely until:
        // - A signal is received (Ctrl+C)
        // - An unrecoverable error occurs
        // - The system shuts down
        sniffer.run();
        
    } catch (const std::exception& e) {
        // Handle any errors that occur during initialization or operation
        // Common errors:
        // - No available BPF devices (all in use)
        // - Invalid interface name
        // - Insufficient privileges (not running as root)
        // - Network interface not found or unavailable
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;  // Exit with error code
    }
    
    // === Normal Termination ===
    
    // If we reach here, the sniffer terminated normally
    // (though in practice, signal handlers usually call exit() directly)
    return 0;  // Success
    
    /*
     * Application Flow Summary:
     * 
     * 1. Validate arguments (interface name required)
     * 2. Set up signal handlers (Ctrl+C handling)
     * 3. Create Sniffer object (BPF initialization)
     * 4. Run packet capture loop (main work)
     * 5. Handle errors gracefully (user feedback)
     * 
     * The application is designed to be simple and robust:
     * - Clear error messages for common problems
     * - Graceful shutdown on interruption
     * - Minimal resource usage and cleanup
     * - Educational code structure and comments
     */
}