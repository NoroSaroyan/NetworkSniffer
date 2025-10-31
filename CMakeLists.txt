cmake_minimum_required(VERSION 4.0)
project(NetworkSniffer)

set(CMAKE_CXX_STANDARD 26)

add_executable(NetworkSniffer main.cpp
        src/PacketParser.cpp
        src/Sniffer.cpp)
