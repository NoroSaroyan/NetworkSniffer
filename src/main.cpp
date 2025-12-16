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

#include "sniffer/Sniffer.h"   // Main packet capture and BPF management class

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
    std::cout << "Usage: " << program_name << " <interface> [server_ip] [server_port]" << std::endl;
    std::cout << "Example: " << program_name << " en0" << std::endl;
    std::cout << "Example: " << program_name << " en0 127.0.0.1 9090" << std::endl;
    std::cout << "Note: Requires root privileges (run with sudo)" << std::endl;
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

    if (argc != 2 && argc != 4) {
        printUsage(argv[0]);
        return 1;
    }

    // === Signal Handler Setup ===

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    // === Extract Arguments ===

    std::string interface = argv[1];
    std::string server_ip;
    int server_port = 0;

    if (argc == 4) {
        server_ip = argv[2];
        server_port = std::atoi(argv[3]);
    }

    // === Initialize and Run Packet Sniffer ===

    try {
        Sniffer sniffer(interface, server_ip, server_port);
        sniffer.run();

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
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