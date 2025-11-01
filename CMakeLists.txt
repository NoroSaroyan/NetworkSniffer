cmake_minimum_required(VERSION 3.16)
project(NetworkSniffer)

set(CMAKE_CXX_STANDARD 17)

add_executable(NetworkSniffer src/main.cpp
        src/PacketParser.cpp
        src/Sniffer.cpp)
