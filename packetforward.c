/*
 * packetforward.c
 * Copyright (c) 2007 by Micky Holdorf
 *
 */

#include <pcap.h>
#include <libnet.h>
#include "headers.h"

#define APP_NAME		"PacketForward 0.8"
#define APP_DESC		"IP packet capture and forward application based on libpcap and libnet."
#define APP_COPYRIGHT	"Copyright (c) 2007 by Micky Holdorf"

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 4096

char *dev = NULL;						/* capture device1 name */
char *dev2 = NULL;						/* capture device2 name */
char *daddr1 = NULL;
char *daddr2 = NULL;
char *saddr1 = NULL;
char *saddr2 = NULL;

u_char enet_src[6] = {0x0d, 0x0e, 0x0a, 0x0d, 0x00, 0x00};
u_char enet_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
int hide_header = 0;
int hide_payload = 0;
int capture_only = 0;

void send_packet(char *protocol, int sport, int dport, int id, int ttl, int count, const u_char *payload, int payload_size);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_payload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_app_banner(void);
void print_app_usage(char *name);

/* app name/banner */
void print_app_banner(void) {

	printf("\n%s\n", APP_NAME);
	printf("%s\n", APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("\n");

	return;
}

/* print help text */
void print_app_usage(char *name) {

	print_app_banner();

	printf("usage:\n   %s <interface> [options]\n\n", name);
	printf("interface:\n");
	printf("   -i interface1      Capture packets from interface1.\n\n");
	printf("options:\n");
	printf("   -I interface2      Forward packets to interface2.\n");
	printf("   -d ip address      Destination ip address of forwarded packets.\n");
	printf("   -n number          Number of packets to capture.\n");
	printf("   -h                 Hide packet headers.\n");
	printf("   -p                 Hide payload.\n");
	printf("   -c                 Capture packets only.\n");
	printf("   -f 'filter'        Tcpdump packet filter expression.\n\n");
	printf("example:\n");
	printf("   sudo packetforward -i en1 -I tap0 -d 5.124.100.100 -f 'udp port 6112 and dst host 255.255.255.255'\n\n'");

	return;
}

/* print data to file */
void fprint_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;
	FILE *file;
	file = fopen("/tmp/payload.txt", "w+");
	
	/* ascii */
	ch = payload;
	for(i = 0; i < len; i++) {
		fprintf(file, "%c", *ch);
		ch++;
	}
	fclose (file);

	return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 * 00000   4745 5420 2f20 4854   5450 2f31 2e31 0d0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x", *ch);
		ch++;
		/* print extra space after for visual aid */
		if (i%2 != 0)
			printf(" ");
		if (i == 7)
			printf("   ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf("   ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("  ");
			if (i%2 == 0)
				printf(" ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len) {

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

void send_packet(char *protocol, int sport2, int dport2, int id, int ttl, int count, const u_char *payload, int payload_size) {

	char errbuf[LIBNET_ERRBUF_SIZE];   /* error buffer */
	struct libnet_link_int *network;   /* pointer to link interface struct */
    int packet_size;                   /* size of our packet */
    int ip_size;				       /* size of our ip */
    int udp_size;                           /* size of our udp */
    int tcp_size;                           /* size of our tcp */
	int c;                
    u_char *packet;                    /* pointer to our packet buffer */
	
	  
    /*
     *  Step 1: Network Initialization (interchangable with step 2).
     */
	if ((network = libnet_open_link_interface(dev2, errbuf)) == NULL) {
        libnet_error(LIBNET_ERR_FATAL, "libnet_open_link_interface: %s\n", errbuf);
    }

    /*
     *  We're going to build a UDP packet with a payload using the
     *  link-layer API, so this time we need memory for a ethernet header
     *  as well as memory for the ICMP and IP headers and our payload.
     */
	if (protocol == "udp") {
		packet_size = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_UDP_H + payload_size;
		ip_size = LIBNET_IP_H + LIBNET_UDP_H + payload_size;
		udp_size = LIBNET_UDP_H + payload_size;

		/*
		*  Step 2: Memory Initialization (interchangable with step 1).
		*/
		if (libnet_init_packet(packet_size, &packet) == -1) {
			libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
		}

		/*
		*  Step 3: Packet construction (ethernet header).
		*/
		libnet_build_ethernet(
				enet_dst,
				enet_src,
				ETHERTYPE_IP,
				NULL,
				0,
				packet);

		printf("\n--- Injected packet number %i on %s ---\n", count, dev2);

		/*
		*  Step 3: Packet construction (IP header).
		*/
		libnet_build_ip(
				LIBNET_UDP_H + payload_size,
				0,                      /* IP tos */
				id,                     /* IP ID */
				0,                      /* Frag */
				ttl,                    /* TTL */
				IPPROTO_UDP,            /* Transport protocol */
				inet_addr(saddr2),         /* Source IP */
				inet_addr(daddr2),         /* Destination IP */
				payload,                   /* Pointer to payload (none) */
				0,
				packet + LIBNET_ETH_H); /* Packet header memory */

		/*
		*  Step 3: Packet construction (UDP header).
		*/
		libnet_build_udp(
				sport2,                 /* source port */
				dport2,                 /* dest. port */
				payload,                /* payload */ 
				payload_size,           /* payload length */ 
				packet + LIBNET_ETH_H + LIBNET_IP_H);
	
		/*
		*  Step 4: Packet checksums (ICMP header *AND* IP header).
		*/
		if (libnet_do_checksum(packet + ETH_H, IPPROTO_UDP, LIBNET_UDP_H + payload_size) == -1) {
			libnet_error(LIBNET_ERR_FATAL, "libnet_do_checksum failed\n");
		}
		if (libnet_do_checksum(packet + ETH_H, IPPROTO_IP, LIBNET_IP_H) == -1) {
			libnet_error(LIBNET_ERR_FATAL, "libnet_do_checksum failed\n");
		}
		
		
		/* print packet info */
		if (!hide_header) {
			printf("IP header    Src Addr: %s", saddr2);
			printf("   Dst Addr: %s\n", daddr2);
			printf("             Len: %i   ID: %i   TTL: %i\n", ip_size, id, ttl);
			printf("UDP header   Src port: %i   Dst port: %i   Len: %i\n", sport2, dport2, udp_size);
		}
		if (!hide_payload) {
			printf("Payload (%d bytes)\n", payload_size);
			print_payload(payload, payload_size);
		}
	}
	
	if (protocol == "tcp") {
		packet_size = LIBNET_ETH_H + LIBNET_IP_H + LIBNET_TCP_H + payload_size;
		ip_size = LIBNET_IP_H + LIBNET_TCP_H + payload_size;
		tcp_size = LIBNET_TCP_H + payload_size;
		
		/*
		*  Step 2: Memory Initialization (interchangable with step 1).
		*/
		if (libnet_init_packet(packet_size, &packet) == -1) {
			libnet_error(LIBNET_ERR_FATAL, "libnet_init_packet failed\n");
		}

		/*
		*  Step 3: Packet construction (ethernet header).
		*/
		libnet_build_ethernet(
				enet_dst,
				enet_src,
				ETHERTYPE_IP,
				NULL,
				0,
				packet);

		printf("\n--- Injected packet number %i on %s ---\n", count, dev2);

		/*
		*  Step 3: Packet construction (IP header).
		*/
		libnet_build_ip(
				LIBNET_TCP_H + payload_size,
				0,                      /* IP tos */
				id,                     /* IP ID */
				0,                      /* Frag */
				ttl,                    /* TTL */
				IPPROTO_TCP,            /* Transport protocol */
				inet_addr(saddr2),         /* Source IP */
				inet_addr(daddr2),         /* Destination IP */
				payload,                /* Pointer to payload */
				0,
				packet + LIBNET_ETH_H); /* Packet header memory */

		/*
		*  Step 3: Packet construction (TCP header).
		*/
		libnet_build_tcp(
				sport2,                /* source TCP port */
				dport2,                /* destination TCP port */
				0xa1d95,                /* sequence number */
				0x53,                   /* acknowledgement number */
				TH_SYN,                 /* control flags */
				1024,                   /* window size */
				0,                      /* urgent pointer */
				NULL,                   /* payload (none) */
				0,                      /* payload length */
				packet + LIBNET_ETH_H + LIBNET_IP_H);
	
		/*
		*  Step 4: Packet checksums (ICMP header *AND* IP header).
		*/
		if (libnet_do_checksum(packet + ETH_H, IPPROTO_TCP, LIBNET_TCP_H + payload_size) == -1) {
			libnet_error(LIBNET_ERR_FATAL, "libnet_do_checksum failed\n");
		}
		if (libnet_do_checksum(packet + ETH_H, IPPROTO_IP, LIBNET_IP_H) == -1) {
			libnet_error(LIBNET_ERR_FATAL, "libnet_do_checksum failed\n");
		}
		
		/* print packet info */
		if (!hide_header) {
			printf("IP header    Src Addr: %s", saddr2);
			printf("   Dst Addr: %s\n", daddr2);
			printf("             Len: %i   ID: %i   TTL: %i\n", ip_size, id, ttl);
			printf("TCP header   Src port: %i   Dst port: %i   Len: %i\n", sport2, dport2, tcp_size);
		}
		if (!hide_payload) {
			printf("Payload (%d bytes)\n", payload_size);
			print_payload(payload, payload_size);
		}
	}

	/*
	 *  Step 5: Packet injection.
	 */
	c = libnet_write_link_layer(network, dev2, packet, packet_size);
	if (c < packet_size) {
		libnet_error(LN_ERR_WARNING, "libnet_write_link_layer only wrote %d bytes\n", c);
	}

    /*
     *  Shut down the interface.
     */
    if (libnet_close_link_interface(network) == -1) {   
        libnet_error(LN_ERR_WARNING, "libnet_close_link_interface couldn't close the interface");
    }

    /*
     *  Free packet memory.
     */
    libnet_destroy_packet(&packet);
	printf("\n");
}

/*
 * dissect/print packet
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;            /* The UDP header */
	const u_char *payload;                  /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;
	char *protocol;
	char nemesis[1000];
	int sport,dport;
	const u_char *ch;
	char *errbuf;
	struct libnet_link_int *link2 = NULL;
	int id, ttl;
		
	printf("\n--- Captured packet number %i on %s ---\n", count,dev);
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("\n  Error: invalid IP header length: %u bytes\n", size_ip);
		return;
	}
		
	/* determine protocol */	
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			goto tcp;
		case IPPROTO_UDP:
			goto udp;
		case IPPROTO_ICMP:
			printf("  ICMP header\n");
			return;
		case IPPROTO_IP:
			printf("  IP header\n");
			return;
		default:
			printf("  Unknown header\n");
			return;
	}
	
tcp:
	/* this packet is TCP */	
	protocol="tcp";

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("\n  Error: invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	sport=ntohs(tcp->th_sport);
	dport=ntohs(tcp->th_dport);
	
	/* print packet info */
	if (!hide_header) {
		printf("IP header   Src Addr: %s", inet_ntoa(ip->ip_src));
		printf("   Dst Addr: %s\n", inet_ntoa(ip->ip_dst));
		printf("            Len: %i   ID: %i   TTL: %i\n", size_ip+size_tcp+size_payload, ip->ip_id, ip->ip_ttl);
		printf("TCP header  Src port: %i   Dst port: %i   Len: %i\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport), size_tcp+size_payload);
	}
	if (!hide_payload) {
		printf("Payload (%d bytes)\n", size_payload);
		print_payload(payload, size_payload);
	}
	goto end;

udp:
	/* this packet is UDP */	
	protocol="udp";
	
	/* define/compute udp header offset */
	udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
	size_udp = 8;
		
	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
	
	/* compute udp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

	sport=ntohs(udp->uh_sport);
	dport=ntohs(udp->uh_dport);
	
	if (!hide_header) {
	/* print source and destination IP addresses */
		printf("IP header    Src Addr: %s", inet_ntoa(ip->ip_src));
		printf("   Dst Addr: %s\n", inet_ntoa(ip->ip_dst));
		printf("             Len: %i   ID: %i   TTL: %i\n", size_ip+size_udp+size_payload, ip->ip_id, ip->ip_ttl);
		printf("UDP header   Src Port: %i   Dst Port: %i   Len: %i\n", ntohs(udp->uh_sport), ntohs(udp->uh_dport), size_udp+size_payload);
	}
	if (!hide_payload) {
		/* Print payload data; it might be binary, so don't just treat it as a string. */
		printf("Payload (%d bytes)\n", size_payload);
		print_payload(payload, size_payload);
	}
	goto end;

end:	
	if (daddr2 == NULL) daddr2 = inet_ntoa(ip->ip_dst);
	id = ip->ip_id;
	ttl = ip->ip_ttl;
	
	if (!capture_only)
		send_packet(protocol, sport, dport, id, ttl, count, payload, size_payload);
/*	
	ch = payload;
	fprint_ascii_line(ch, size_payload, 0);
	sprintf(nemesis,"sudo nemesis %s -x %i -y %i -S %s -D %s -d %s -T 255 -P/tmp/payload.txt", 
				protocol, sport, dport, saddr2, daddr2, dev2);
	system(nemesis);
*/
	count++;
	return;
}

int main(int argc, char **argv) {

	bpf_u_int32 mask, mask2;				/* subnet mask */
	bpf_u_int32 net, net2;					/* ip */
	char errbuf[PCAP_ERRBUF_SIZE];			/* error buffer */
	pcap_t *handle;							/* packet capture handle */
	char filter_exp[] = "ip";				/* filter expression */
	struct bpf_program fp;					/* compiled filter program (expression) */
	int c,num_packets = -1;					/* number of packets to capture */
    
	struct libnet_link_int *l;
	u_long i;
	 
	/* check command-line options */
    while ((c = getopt(argc, argv, "i:I:d:n:hpcf:")) != EOF) {
        switch (c) {
            case 'i':
				dev = optarg;
				dev2 = dev;				
                break;
            case 'I':
				dev2 = optarg;
				break;
			case 'd':
				daddr2 = optarg;
                break;
            case 'n':
				num_packets = atoi(optarg);
                break;
            case 'f':
				strcpy(filter_exp, optarg);
                break;
            case 'h':
				hide_header = 1;
                break;
            case 'p':
				hide_payload = 1;
                break;
            case 'c':
				capture_only = 1;
                break;
            default:
                print_app_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

	if (dev == NULL) {
		print_app_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* get source ip address associated with forward device */
	l = libnet_open_link_interface(dev2, errbuf);
	if (!l) {
        printf("libnet_open_link_interface: %s\n", errbuf);
        goto failure;
    }
	
	i = libnet_get_ipaddr(l, dev2, errbuf);
	if (!i) {
        printf("Can't get ip address: %s\n", errbuf);
        goto failure;
    }
	
	saddr2 = (char *)libnet_host_lookup(ntohl(i), 0);
					
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("  Error: couldn't get netmask for interface %s\n\n", errbuf);
		goto failure;
	}

	/* print capture info */
	printf("\n Capture from: %s\n", dev);
	printf("   Forward to: %s\n", dev2);
	printf("  Src Address: %s\n", saddr2);
	if (daddr2) printf("  Dst Address: %s\n", daddr2);
	else printf("  Dst Address: Not changed\n");
	if(num_packets > 0) printf("Packets to capture: %d\n", num_packets);
	printf("Packet Filter: %s\n", filter_exp);
	printf("\n");

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		printf("\n  Error: couldn't open interface %s: %s\n\n", dev, errbuf);
		goto failure;
	}

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("\n  Error: %s is not on ethernet\n\n", dev);
		goto failure;
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		printf("\n  Error: couldn't parse filter %s: %s\n\n", filter_exp, pcap_geterr(handle));
		goto failure;
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		printf("\n  Error: couldn't install filter %s: %s\n\n", filter_exp, pcap_geterr(handle));
		goto failure;
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture and forward complete.\n\n");
	exit(EXIT_SUCCESS);

failure:
	exit(EXIT_FAILURE);

}