//
// Created by Norik Saroyan on 10.12.25.
//

#ifndef NETWORKSNIFFER_LOGGER_H
#define NETWORKSNIFFER_LOGGER_H


#pragma once
#include <string>
#include <mutex>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

class Logger {
public:
    static Logger &instance();

    void startTcpServer(int port = 9000);

    void log(const std::string &msg);

private:
    Logger() = default;

    void serverLoop();

    int server_fd_ = -1;
    std::vector<int> clients_;
    std::mutex mtx_;
};


#endif //NETWORKSNIFFER_LOGGER_H
