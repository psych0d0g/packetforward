# packetforward - Makefile

CC = gcc
INCLUDE = -I/usr/include
LIBS = -L/usr/lib -lpcap `libnet-config --defines --cflags --libs`
INSTALL_DIR = /usr/bin

all: 
	$(CC) packetforward.c -o packetforward $(INCLUDE) $(LIBS)
	
install:
	cp -f packetforward $(INSTALL_DIR)/packetforward
	
clean:
	rm -f $(INSTALL_DIR)/packetforward
	