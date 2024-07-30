CC = gcc
CFLAGS = -Wall -Wextra -g
LIBS = -lpcap

TARGET = pcap-test
SRCS = pcap-test.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

clean:
	rm -f $(TARGET)

.PHONY: all clean