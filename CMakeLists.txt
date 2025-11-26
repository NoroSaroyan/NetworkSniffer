cmake_minimum_required(VERSION 3.16)
project(NetworkSniffer)

set(CMAKE_CXX_STANDARD 17)

add_executable(NetworkSniffer src/main.cpp
        src/PacketParser.cpp
        src/Sniffer.cpp)

# Link required system libraries for network packet capture
if(APPLE)
    # macOS uses BPF (Berkeley Packet Filter) for packet capture
    target_link_libraries(NetworkSniffer)
else()
    # Linux typically uses libpcap
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    target_link_libraries(NetworkSniffer ${PCAP_LIBRARIES})
    target_include_directories(NetworkSniffer PRIVATE ${PCAP_INCLUDE_DIRS})
endif()
