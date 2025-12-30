CC = gcc
CFLAGS = -Wall -Wextra -O2 -g
LDFLAGS = -lpcap

TARGET = ping_ack_latency
SRC = ping_ack_latency.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
