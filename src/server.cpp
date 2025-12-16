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

const uint8_t PROTOCOL_VERSION = 0x01;
const uint8_t TYPE_CLIENT_HELLO = 0x01;
const uint8_t TYPE_SERVER_HELLO = 0x02;
const uint8_t TYPE_TRAFFIC_LOG = 0x03;
const uint8_t TYPE_FORWARD_LOG = 0x04;
const uint8_t TYPE_ERROR = 0x05;
const uint8_t TERM_BYTE = 0x0A;

struct Client {
    int fd;
    std::string remote_ip;
    uint32_t ssid;
    bool is_sniffer;
};

struct SnifferRecord {
    int sniffer_index;
    std::string ip;
};

std::vector<Client> clients;
std::mutex clients_mutex;
std::map<std::string, SnifferRecord> ip_to_sniffer;
std::map<int, uint32_t> fd_to_ssid;
uint32_t next_ssid = 1;
int next_sniffer_index = 1;

struct Frame {
    uint8_t type;
    std::string payload;
};

bool readExact(int fd, void* buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, (char*)buf + total, len - total);
        if (n <= 0) return false;
        total += n;
    }
    return true;
}

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

std::string getClientIP(int fd) {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    if (getpeername(fd, (struct sockaddr*)&addr, &len) == -1) {
        return "";
    }
    return std::string(inet_ntoa(addr.sin_addr));
}

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

            // Determine if this is a sniffer or GUI client
            bool is_sniffer = payload.contains("interface");

            uint32_t ssid;
            {
                std::lock_guard<std::mutex> lock(clients_mutex);

                if (is_sniffer && ip_to_sniffer.find(client_ip) == ip_to_sniffer.end()) {
                    ip_to_sniffer[client_ip] = {next_sniffer_index++, client_ip};
                }

                ssid = next_ssid++;
                fd_to_ssid[client_fd] = ssid;

                json response;
                response["ssid"] = ssid;
                response["ip"] = client_ip;
                response["registered"] = true;

                if (!sendFrame(client_fd, TYPE_SERVER_HELLO, response.dump())) {
                    close(client_fd);
                    return;
                }

                clients.push_back({client_fd, client_ip, ssid, is_sniffer});

                if (is_sniffer) {
                    std::cout << "Sniffer registered: IP=" << client_ip << " SSID=" << ssid << std::endl;
                } else {
                    std::cout << "GUI Client registered: IP=" << client_ip << " SSID=" << ssid << std::endl;
                }
            }

            if (is_sniffer) {
                // Sniffers send TRAFFIC_LOG frames - wait for them in a loop
                while (readFrame(client_fd, frame)) {
                    if (frame.type == TYPE_TRAFFIC_LOG) {
                        json log_payload = json::parse(frame.payload);
                        json forward;
                        forward["ssid"] = ssid;
                        forward["log"] = log_payload;

                        std::string forward_str = forward.dump();
                        std::lock_guard<std::mutex> lock(clients_mutex);

                        for (const auto& c : clients) {
                            if (!c.is_sniffer) {
                                sendFrame(c.fd, TYPE_FORWARD_LOG, forward_str);
                            }
                        }
                    }
                }
            } else {
                // GUI clients only receive, they don't send frames after handshake
                // Keep thread alive until client disconnects
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

        std::thread(handleClient, client_fd, client_ip).detach();
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }

    int port = std::atoi(argv[1]);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

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
