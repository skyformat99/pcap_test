#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h> /* Using ntohs, ... */
#include <pcap.h> /* libpcap: need -lpcap option */

#include <netinet/if_ether.h> /* Using struct ether_header */

/* prints usage and quit */
void usage() {
	puts("Usage: pcap_test <interface>\n");
	exit(-1);
}

/* prints error message and quit */
void error(const char *s, const char *e) {
	fprintf(stderr, "%s: %s\n", s, e);
	exit(-1);
}

int  pp_packet(bpf_u_int32, const char*);
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
int pp_packet(bpf_u_int32 len, const char *packet) {
	/* Prints length of packet */
	printf("Packet length: %5u\n", len);

	/* Is the packet eth? 100% Sure! */
	/* Let us check src and dest mac address */
	const struct ether_header *ptr1 = (const struct ether_header*)packet;

	/* src */
	printf("MAC[src]:");
	for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
		printf(" %02X", ptr1->ether_shost[i]);
	}

	/* dest */
	printf(" / MAC[dest]:");
	for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
		printf(" %02X", ptr1->ether_dhost[i]);
	}

	/* Then, what type is it? */
	switch (ntohs(ptr1->ether_type)) {
	case ETHERTYPE_IP:
		/* It is ipv4. */
		printf("Ether Type: ipv4\n");
		break;
	case ETHERTYPE_ARP:
		/* It is arp. */
		printf("Ether Type: arp\n");
		return 1;
	default:
		printf("Ether Type: unknown\n");
		return 2;
	}

	/* So, the packet is ipv4. */
	/* Let's check src and dest ip */

	/* TODO */
	return 3;
}

void make_readable(char *B, const char *S, uint32_t len) {
	for (uint32_t i = 0; i < len; ++i) {
		/* 32 ~ 127 are readable ascii-codes */
		if (32 <= S[i] && S[i] <= 126) {
			B[i] = S[i];
		} else {
			B[i] = '.';
		}
	}
	B[len] = '\0';
}
