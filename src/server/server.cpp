/**
 * @file server.cpp
 * @brief Central server for the distributed network sniffer system
 *
 * This server acts as a hub that:
 * 1. Accepts connections from remote BPF packet sniffers
 * 2. Registers each sniffer with a unique SSID (Sniffer Session ID)
 * 3. Receives TRAFFIC_LOG frames from sniffers
 * 4. Forwards aggregated logs to connected GUI clients
 *
 * ## Architecture
 *
 * The server handles two types of clients:
 * - **Sniffer Clients**: Send captured network packets as TRAFFIC_LOG frames
 * - **GUI Clients**: Receive logs via FORWARD_LOG frames for real-time monitoring
 *
 * Each connection is handled in its own thread. The server maintains:
 * - A client list with connection metadata (fd, IP, SSID, type)
 * - An IP-to-sniffer mapping for identifying sniffer instances
 * - A mutex to protect shared state during concurrent access
 *
 * ## Protocol
 *
 * All messages use a binary frame format:
 * ```
 * [Version:1][Type:1][Length:2][Payload:N][Terminator:1]
 * ```
 *
 * Message Types:
 * - 0x01 CLIENT_HELLO: Sniffer/GUI introduces itself (on connection)
 * - 0x02 SERVER_HELLO: Server responds with assigned SSID
 * - 0x03 TRAFFIC_LOG: Sniffer sends captured packet data
 * - 0x04 FORWARD_LOG: Server broadcasts logs to GUI clients
 * - 0x05 ERROR: Error notification
 *
 * ## Client Registration Flow
 *
 * For Sniffers:
 * 1. Sniffer connects and sends CLIENT_HELLO with {"interface":"en0", ...}
 * 2. Server assigns SSID and sends SERVER_HELLO response
 * 3. Sniffer begins sending TRAFFIC_LOG frames
 * 4. Server forwards each log to all connected GUI clients
 *
 * For GUI Clients:
 * 1. GUI connects and sends CLIENT_HELLO with {"type":"gui", ...}
 * 2. Server assigns SSID and sends SERVER_HELLO response
 * 3. GUI waits to receive FORWARD_LOG frames from sniffers
 * 4. GUI displays logs organized by sniffer SSID
 *
 * @usage ./SnifferServer <port>
 * @example ./SnifferServer 9090
 */

#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <thread>
#include <mutex>
#include <map>
#include <cstring>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

const uint8_t PROTOCOL_VERSION = 0x01;  ///< Current protocol version
const uint8_t TYPE_CLIENT_HELLO = 0x01; ///< Client introduction message
const uint8_t TYPE_SERVER_HELLO = 0x02; ///< Server acknowledgment with SSID
const uint8_t TYPE_TRAFFIC_LOG = 0x03;  ///< Traffic data from sniffer
const uint8_t TYPE_FORWARD_LOG = 0x04;  ///< Forwarded log to GUI client
const uint8_t TYPE_ERROR = 0x05;        ///< Error notification
const uint8_t TERM_BYTE = 0x0A;         ///< Frame terminator (newline)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @struct Client
 * @brief Represents a connected client (sniffer or GUI)
 */
struct Client {
    int fd;                    ///< File descriptor for socket connection
    std::string remote_ip;     ///< Client IP address
    uint32_t ssid;             ///< Unique Session ID assigned by server
    bool is_sniffer;           ///< True if sniffer, false if GUI client
};

/**
 * @struct SnifferRecord
 * @brief Metadata about a sniffer instance
 */
struct SnifferRecord {
    int sniffer_index;         ///< Sequential index of this sniffer
    std::string ip;            ///< IP address of the sniffer
};

// ============================================================================
// GLOBAL STATE (Protected by clients_mutex)
// ============================================================================

std::vector<Client> clients;                           ///< All connected clients
std::mutex clients_mutex;                              ///< Protects clients list access
std::map<std::string, SnifferRecord> ip_to_sniffer;    ///< Maps IP to sniffer metadata
std::map<int, uint32_t> fd_to_ssid;                    ///< Maps file descriptor to SSID
uint32_t next_ssid = 1;                                ///< Counter for assigning SSIDs
int next_sniffer_index = 1;                            ///< Counter for sniffer indices

/**
 * @struct Frame
 * @brief Parsed binary frame received from socket
 */
struct Frame {
    uint8_t type;           ///< Message type (CLIENT_HELLO, TRAFFIC_LOG, etc.)
    std::string payload;    ///< JSON payload (varies by message type)
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * @brief Read exactly N bytes from socket, handling partial reads
 *
 * TCP read() may return fewer bytes than requested. This function loops until
 * the requested number of bytes has been read or an error occurs.
 *
 * @param fd Socket file descriptor
 * @param buf Buffer to read into
 * @param len Number of bytes to read
 * @return true if exactly len bytes were read, false on any error or EOF
 *
 * @note This is a blocking call that will wait for data
 */
bool readExact(int fd, void* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (char*)buf + total, len - total);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

/**
 * @brief Read and parse a complete binary frame from socket
 *
 * Frame format: [Version:1][Type:1][Length:2][Payload:N][Terminator:1]
 *
 * Validates:
 * - Protocol version matches PROTOCOL_VERSION
 * - Payload length is reasonable (< 1024 bytes)
 * - Frame is properly terminated with TERM_BYTE
 *
 * @param fd Socket file descriptor
 * @param frame[out] Parsed frame (type and payload)
 * @return true if a valid frame was read, false on error or validation failure
 *
 * @note Sets frame.type and frame.payload on success
 */
bool readFrame(int fd, Frame& frame) {
    std::cout << "[DEBUG] readFrame: trying to read 4-byte header" << std::endl;
    uint8_t header[4];
    if (!readExact(fd, header, 4)) {
        std::cout << "[DEBUG] Failed to read header" << std::endl;
        return false;
    }

    std::cout << "[DEBUG] Header bytes: " << (int)header[0] << " " << (int)header[1] << " " << (int)header[2] << " " << (int)header[3] << std::endl;

    uint8_t version = header[0];
    if (version != PROTOCOL_VERSION) {
        std::cerr << "Invalid protocol version: " << (int)version << std::endl;
        return false;
    }

    frame.type = header[1];
    uint16_t length = (header[2] << 8) | header[3];

    std::cout << "[DEBUG] Frame type: " << (int)frame.type << ", payload length: " << length << std::endl;

    if (length > 1024) {
        std::cerr << "Payload too large: " << length << std::endl;
        return false;
    }

    std::vector<char> payload_buf(length);
    if (!readExact(fd, payload_buf.data(), length)) {
        std::cout << "[DEBUG] Failed to read payload" << std::endl;
        return false;
    }
    frame.payload = std::string(payload_buf.begin(), payload_buf.end());

    uint8_t term;
    if (!readExact(fd, &term, 1)) {
        std::cout << "[DEBUG] Failed to read terminator" << std::endl;
        return false;
    }

    if (term != TERM_BYTE) {
        std::cerr << "Invalid terminator byte: " << (int)term << std::endl;
        return false;
    }

    std::cout << "[DEBUG] Frame read successfully" << std::endl;
    return true;
}

/**
 * @brief Send a complete binary frame to client socket
 *
 * Constructs frame with proper header and sends:
 * [Version:1][Type:1][Length:2][Payload:N][Terminator:1]
 *
 * @param fd Socket file descriptor
 * @param type Message type (TYPE_SERVER_HELLO, TYPE_FORWARD_LOG, etc.)
 * @param payload JSON string to send (must be < 1024 bytes)
 * @return true if frame was sent successfully, false on error
 *
 * @note Does NOT handle partial writes - fails if full frame not sent atomically
 */
bool sendFrame(int fd, uint8_t type, const std::string& payload) {
    if (payload.length() > 1024) return false;

    uint8_t header[4];
    header[0] = PROTOCOL_VERSION;
    header[1] = type;
    header[2] = (payload.length() >> 8) & 0xFF;
    header[3] = payload.length() & 0xFF;

    if (write(fd, header, 4) != 4) return false;
    if (write(fd, payload.data(), payload.length()) != (ssize_t)payload.length()) return false;
    if (write(fd, &TERM_BYTE, 1) != 1) return false;

    return true;
}

/**
 * @brief Extract the remote IP address from a connected socket
 *
 * @param fd Socket file descriptor
 * @return IP address string (e.g., "192.168.1.1"), or empty string on error
 */
std::string getClientIP(int fd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr*)&addr, &len) == -1) {
        return "";
    }
    return std::string(inet_ntoa(addr.sin_addr));
}

// ============================================================================
// CLIENT HANDLING
// ============================================================================

/**
 * @brief Handle a single client connection (runs in its own thread)
 *
 * This is the main per-client handler. Each client connection (sniffer or GUI)
 * gets its own thread running this function.
 *
 * ## Protocol Flow
 *
 * 1. **CLIENT_HELLO Reception**
 *    - Receive and parse CLIENT_HELLO frame
 *    - Identify client type based on presence of "interface" field:
 *      - Sniffer: Contains "interface" field (e.g., "en0")
 *      - GUI: Contains "type":"gui" field
 *    - Assign unique SSID
 *    - Send SERVER_HELLO response with assigned SSID
 *    - Register client in global clients list
 *
 * 2. **Sniffer Handling**
 *    - Enter read loop waiting for TRAFFIC_LOG frames
 *    - For each TRAFFIC_LOG:
 *      - Wrap log with SSID in FORWARD_LOG message
 *      - Send to ALL connected GUI clients
 *    - Loop until sniffer disconnects
 *
 * 3. **GUI Client Handling**
 *    - Receive SERVER_HELLO acknowledgment
 *    - Sleep in a loop (doesn't send frames)
 *    - Continues receiving FORWARD_LOG messages from sniffers
 *    - Loop until GUI disconnects
 *
 * @param client_fd Socket file descriptor for this client
 * @param client_ip Remote IP address (for identification)
 *
 * @note This function is called in a detached thread, so cleanup happens
 *       when function returns
 * @note The function is resilient to errors - disconnects gracefully
 * @note Uses clients_mutex to protect concurrent access to clients list
 *
 * ## Example CLIENT_HELLO Payloads
 *
 * Sniffer:
 * ```json
 * {"hostname":"MacBook-Pro-3.local","interface":"en0"}
 * ```
 *
 * GUI:
 * ```json
 * {"hostname":"Qt GUI Client","type":"gui"}
 * ```
 *
 * SERVER_HELLO Response:
 * ```json
 * {"ssid":1,"ip":"127.0.0.1","registered":true}
 * ```
 *
 * FORWARD_LOG Format (sent to GUIs):
 * ```json
 * {"ssid":1,"log":{"timestamp":"2025-12-16 21:15:30.123","src":"192.168.1.100","dst":"142.251.41.14","protocol":"TCP",...}}
 * ```
 */
void handleClient(int client_fd, const std::string& client_ip) {
    std::cout << "[SERVER] handleClient: trying to read first frame" << std::endl;
    Frame frame;
    if (!readFrame(client_fd, frame)) {
        std::cout << "[SERVER] Failed to read first frame from " << client_ip << std::endl;
        close(client_fd);
        return;
    }

    std::cout << "[SERVER] Received frame type: " << (int)frame.type << ", payload size: " << frame.payload.size() << std::endl;

    if (frame.type == TYPE_CLIENT_HELLO) {
        try {
            std::cout << "[SERVER] Parsing CLIENT_HELLO payload..." << std::endl;
            std::cout.flush();
            json payload = json::parse(frame.payload);
            std::cout << "[SERVER] Parsed payload: " << payload.dump() << std::endl;
            std::cout.flush();

            // ================================================================
            // STEP 1: Identify client type and assign SSID
            // ================================================================
            // Sniffers send "interface" field, GUI clients send "type":"gui"
            bool is_sniffer = payload.contains("interface");

            uint32_t ssid;
            {
                // Critical section: protect clients list and SSID assignment
                std::lock_guard<std::mutex> lock(clients_mutex);

                // Register sniffer in IP-to-sniffer map (for grouping by source)
                if (is_sniffer && ip_to_sniffer.find(client_ip) == ip_to_sniffer.end()) {
                    ip_to_sniffer[client_ip] = {next_sniffer_index++, client_ip};
                }

                // Assign unique SSID for this client connection
                ssid = next_ssid++;
                fd_to_ssid[client_fd] = ssid;

                // ============================================================
                // STEP 2: Send SERVER_HELLO response
                // ============================================================
                json response;
                response["ssid"] = ssid;
                response["ip"] = client_ip;
                response["registered"] = true;

                if (!sendFrame(client_fd, TYPE_SERVER_HELLO, response.dump())) {
                    close(client_fd);
                    return;
                }

                // ============================================================
                // STEP 3: Register client and print confirmation
                // ============================================================
                clients.push_back({client_fd, client_ip, ssid, is_sniffer});

                if (is_sniffer) {
                    std::cout << "Sniffer registered: IP=" << client_ip << " SSID=" << ssid << std::endl;
                } else {
                    std::cout << "GUI Client registered: IP=" << client_ip << " SSID=" << ssid << std::endl;
                }
            } // Lock released here

            // ================================================================
            // STEP 4: Handle client-specific communication loop
            // ================================================================
            if (is_sniffer) {
                // SNIFFER HANDLER: Receive logs and broadcast to GUIs
                while (readFrame(client_fd, frame)) {
                    if (frame.type == TYPE_TRAFFIC_LOG) {
                        // Parse the traffic log JSON from sniffer
                        json log_payload = json::parse(frame.payload);

                        // Wrap with SSID for GUI clients to know which sniffer sent it
                        json forward;
                        forward["ssid"] = ssid;
                        forward["log"] = log_payload;

                        std::string forward_str = forward.dump();

                        // Broadcast to all connected GUI clients
                        {
                            std::lock_guard<std::mutex> lock(clients_mutex);
                            for (const auto& c : clients) {
                                if (!c.is_sniffer) {
                                    // Send FORWARD_LOG frame to GUI client
                                    sendFrame(c.fd, TYPE_FORWARD_LOG, forward_str);
                                }
                            }
                        } // Lock released
                    }
                }
            } else {
                // GUI CLIENT HANDLER: Just keep connection alive
                // Frames are sent to this client by sniffers' handler above
                while (true) {
                    sleep(1);
                }
            }

        } catch (const std::exception& e) {
            std::cerr << "Error handling client: " << e.what() << std::endl;
            std::cerr << "[SERVER] Exception details: " << typeid(e).name() << std::endl;
        }
    }

    std::lock_guard<std::mutex> lock(clients_mutex);
    clients.erase(std::remove_if(clients.begin(), clients.end(),
        [client_fd](const Client& c) { return c.fd == client_fd; }), clients.end());
    fd_to_ssid.erase(client_fd);
    close(client_fd);
}

// ============================================================================
// MAIN SERVER LOOP
// ============================================================================

/**
 * @brief Main server accept loop - listens for incoming connections
 *
 * Runs in the main thread, continuously accepting new client connections
 * and spawning a new thread for each one via handleClient().
 *
 * For each new connection:
 * 1. Accept the socket connection
 * 2. Extract the client's IP address
 * 3. Launch handleClient() in a detached thread
 *
 * The loop runs indefinitely - to stop the server, use Ctrl+C or kill signal.
 *
 * @param server_fd Listening socket file descriptor (already bound and listening)
 *
 * @note This function never returns - it's the main program loop
 * @note Each client connection runs handleClient() in its own detached thread
 * @note Errors in accept() are non-fatal - loop continues
 *
 * @see handleClient() for what happens on each connection
 */
void acceptLoop(int server_fd) {
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);

        if (client_fd < 0) {
            std::cerr << "Accept failed" << std::endl;
            continue;
        }

        std::string client_ip = std::string(inet_ntoa(client_addr.sin_addr));
        std::cout << "New connection from " << client_ip << std::endl;

        // Spawn a new thread for this client (detached so we don't track it)
        std::thread(handleClient, client_fd, client_ip).detach();
    }
}

// ============================================================================
// PROGRAM ENTRY POINT
// ============================================================================

/**
 * @brief Program entry point - sets up server and enters accept loop
 *
 * ## Initialization Steps
 *
 * 1. Parse command line arguments (port number required)
 * 2. Create TCP listening socket
 * 3. Set SO_REUSEADDR to allow quick port reuse on restart
 * 4. Bind socket to address 0.0.0.0:<port> (all interfaces)
 * 5. Listen for incoming connections with backlog of 10
 * 6. Enter acceptLoop() which runs until server is killed
 *
 * ## Shutdown
 *
 * To stop the server:
 * - Press Ctrl+C to send SIGINT
 * - Use `kill <pid>` to terminate
 * - Connection cleanup is OS-managed (doesn't need explicit cleanup)
 *
 * @param argc Argument count
 * @param argv Argument vector - expects [program_path, port_number]
 * @return 0 on success, 1 on initialization error
 *
 * @usage ./SnifferServer 9090
 *
 * @example
 * ```bash
 * $ ./SnifferServer 9090
 * Server listening on port 9090
 * New connection from 192.168.1.100
 * Sniffer registered: IP=192.168.1.100 SSID=1
 * ```
 */
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }

    int port = std::atoi(argv[1]);

    // ====================================================================
    // STEP 1: Create socket
    // ====================================================================
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    // ====================================================================
    // STEP 2: Set socket options
    // ====================================================================
    // SO_REUSEADDR allows the port to be reused immediately after server
    // restart, avoiding "Address already in use" errors
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set SO_REUSEADDR" << std::endl;
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind" << std::endl;
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        std::cerr << "Failed to listen" << std::endl;
        return 1;
    }

    std::cout << "Server listening on port " << port << std::endl;
    acceptLoop(server_fd);

    return 0;
}
