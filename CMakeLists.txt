cmake_minimum_required(VERSION 3.16)
project(NetworkSniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt
find_package(Qt6 COMPONENTS Core Widgets Network QUIET)
if (NOT Qt6_FOUND)
    find_package(Qt5 COMPONENTS Core Widgets Network REQUIRED)
    set(QT_VERSION_MAJOR 5)
else()
    set(QT_VERSION_MAJOR 6)
endif()

add_executable(NetworkSniffer src/main.cpp
        src/PacketParser.cpp
        src/Sniffer.cpp
        src/Logger.cpp)

add_executable(SnifferServer src/server.cpp)

add_executable(SnifferGUI
        src/qt_main.cpp
        src/MainWindow.cpp
        src/SnifferClient.cpp)

# Link required system libraries for network packet capture
if(APPLE)
    # macOS uses BPF (Berkeley Packet Filter) for packet capture
    target_include_directories(NetworkSniffer PRIVATE /usr/local/include)
    target_include_directories(SnifferServer PRIVATE /usr/local/include)
    target_include_directories(SnifferGUI PRIVATE /usr/local/include)
    target_link_libraries(NetworkSniffer pthread)
    target_link_libraries(SnifferServer pthread)
else()
    # Linux typically uses libpcap
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(PCAP REQUIRED libpcap)
    target_link_libraries(NetworkSniffer ${PCAP_LIBRARIES} pthread)
    target_include_directories(NetworkSniffer PRIVATE ${PCAP_INCLUDE_DIRS})
    target_link_libraries(SnifferServer pthread)
endif()

# Link Qt libraries
if (QT_VERSION_MAJOR EQUAL 6)
    target_link_libraries(SnifferGUI Qt6::Core Qt6::Widgets Qt6::Network)
else()
    target_link_libraries(SnifferGUI Qt5::Core Qt5::Widgets Qt5::Network)
endif()
