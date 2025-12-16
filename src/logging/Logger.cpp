//
// Created by Norik Saroyan on 10.12.25.
//

#include "Logger.h"


#include "Logger.h"
#include <iostream>
#include <thread>

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

void Logger::startTcpServer(int port) {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        throw std::runtime_error("TCP server: socket() failed");
    }

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        throw std::runtime_error("TCP server: bind() failed");
    }

    if (listen(server_fd_, 5) < 0) {
        throw std::runtime_error("TCP server: listen() failed");
    }

    std::thread(&Logger::serverLoop, this).detach();
    std::cout << "TCP log server running on port " << port << std::endl;
}

void Logger::serverLoop() {
    while (true) {
        int client = accept(server_fd_, nullptr, nullptr);
        if (client >= 0) {
            std::lock_guard<std::mutex> lock(mtx_);
            clients_.push_back(client);
            std::cout << "Client connected." << std::endl;
        }
    }
}

void Logger::log(const std::string& msg) {
    {
        // stdout
        std::cout << msg << std::endl;
    }
    {
        // broadcast to TCP clients
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (send(*it, msg.c_str(), msg.size(), MSG_NOSIGNAL) < 0) {
                close(*it);
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }
}
