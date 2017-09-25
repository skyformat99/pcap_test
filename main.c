#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h> /* Using ntohs, ... */
#include <pcap.h> /* libpcap: need -lpcap option */

#include <netinet/if_ether.h> /* Using struct ether_header */

/* Prints usage and quit */
void usage() {
	puts("Usage: pcap_test <interface>\n");
	exit(-1);
}

/* Prints error message and quit */
void error(const char *s, const char *e) {
	fprintf(stderr, "%s: %s\n", s, e);
	exit(-1);
}

/* Pretty-print functions */
void pp_ipv4(void*);
void pp_eth(const struct ether_header*);
void pp_packet(bpf_u_int32, const char*);

/* Make packet readable */
void make_readable(char*, const char*, uint32_t);

char errbuf[PCAP_ERRBUF_SIZE]; /* pcap error message */

int main(int argc, char *argv[]) {
	/* First, check argc == 2 */
	if (argc != 2) usage();

	/* We want to read packet from argv[1] */
	pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (!handle) error("Cannot open device", errbuf);

	/* Capture packets */
	while (1) {
		struct pcap_pkthdr *header;
		const u_char *packet;

		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		else if (res == -1 || res == -2) break;

		pp_packet(header->caplen, packet);
	}

	pcap_close(handle);
	return 0;
}

/* Define some network structures */
/* TODO */

/* Pretty-prints packet data */
void pp_packet(bpf_u_int32 len, const char *packet) {
	/* Prints length of packet */
	printf("Packet length: %6u\n", len);

	/* Is the packet eth? 100% Sure! */
	/* Let's check src and dest MAC address */
	pp_eth((const struct ether_header*)packet);
}

/* Pretty-prints eth data */
void pp_eth(const struct ether_header *packet_eth) {
	/* src */
	for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
		printf("%02X", packet_eth->ether_shost[i]);
	}
	/* dest */
	printf(" -> ");
	for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
		printf("%02X", packet_eth->ether_dhost[i]);
	}

	/* What type is it? */
	switch (ntohs(packet_eth->ether_type)) {
	case ETHERTYPE_IP:
		/* It is ipv4. */
		printf("Ether Type: ipv4\n");
		pp_ipv4(packet_eth); /* TODO */
		break;
	case ETHERTYPE_ARP:
		/* It is arp. */
		printf("Ether Type: arp\n");
		break;
	default:
		printf("Ether Type: unknown\n");
		break;
	}
}

/* Pretty-prints ipv4 data */
void pp_ipv4(void *ptr) {
	/* TODO */
}

void make_readable(char *B, const char *S, uint32_t len) {
	for (uint32_t i = 0; i < len; ++i) {
		/* 32 ~ 126 are readable ascii-codes */
		if (32 <= S[i] && S[i] <= 126) {
			B[i] = S[i];
		} else {
			B[i] = '.';
		}
	}
	B[len] = '\0';
}
