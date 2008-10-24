all: 
	gcc packetforward.c -o packetforward -I/usr/include -L/usr/lib -lpcap `libnet-config --defines --cflags --libs`
	
install:
	cp -f packetforward /usr/bin/packetforward
	
clean:
	rm -f /usr/bin/packetforward
	