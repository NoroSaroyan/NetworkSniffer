CXX=clang++
CXXFLAGS=-std=c++17 -Wall -Wextra -O2
LDFLAGS=

SRCS=src/main.cpp src/Sniffer.cpp src/PacketParser.cpp
OBJS=$(SRCS:.cpp=.o)
TARGET=sniffer

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean