#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <arpa/inet.h> /* Using ntohs, ... */
#include <pcap.h> /* libpcap: need -lpcap option */

#include "net_struct.h"

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
void pp_packet(bpf_u_int32, const u_char*);
void pp_eth(const struct eth_hdr*);
void pp_ipv4(const struct ipv4_hdr*);
void pp_tcp(const struct tcp_hdr*, uint16_t length);

/* Make packet readable */
void make_readable(uint8_t*, const uint8_t*, uint32_t);

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
		puts("");
	}

	pcap_close(handle);
	return 0;
}

/* Pretty-prints packet data */
void pp_packet(bpf_u_int32 len, const u_char *packet) {
	/* Prints length of packet */
	printf("Packet length: %u\n", len);

	/* Is the packet eth? 100% Sure! */
	/* Let's check src and dest MAC address */
	pp_eth((const struct eth_hdr*)packet);
}

/* Pretty-prints eth data */
void pp_eth(const struct eth_hdr *packet_eth) {
	printf("MAC: ");
	/* src */
	for (int i = 0; i < ETH_ALEN; ++i) {
		printf("%s%02X", (i>0 ? ":" : ""), packet_eth->src[i]);
	}
	/* dest */
	printf(" -> ");
	for (int i = 0; i < ETH_ALEN; ++i) {
		printf("%s%02X", (i>0 ? ":" : ""), packet_eth->dest[i]);
	}
	puts("");

	/* What type is it? */
	switch (ntohs(packet_eth->type)) {
	case ETH_IPV4:
		/* It is ipv4. */
		printf("Ethertype: ipv4\n");
		pp_ipv4((const struct ipv4_hdr*)packet_eth->data);
		break;
	case ETH_IPV6:
		/* It is ipv6. */
		printf("Ethertype: ipv6\n");
		break;
	case ETH_ARP:
		/* It is arp. */
		printf("Ethertype: arp\n");
		break;
	default:
		printf("Ethertype: unknown\n");
		break;
	}
}

/* Pretty-prints ipv4 data */
void pp_ipv4(const struct ipv4_hdr *packet_ipv4) {
	printf("IP: ");
	/* src */
	for (int i = 0; i < IPV4_ALEN; ++i) {
		printf("%s%d", (i>0 ? "." : ""), packet_ipv4->src[i]);
	}
	printf(" -> ");
	/* dest */
	for (int i = 0; i < IPV4_ALEN; ++i) {
		printf("%s%d", (i>0 ? "." : ""), packet_ipv4->dest[i]);
	}
	puts("");

	/* Does it has option field? */
	uint8_t ihl = IPV4_IHL(packet_ipv4);
	if (ihl < IPV4_IHL_MIN) error("Invalid ipv4 packet!", "IHL is too small");
	else if (ihl == IPV4_IHL_MIN) printf("ipv4 has no option\n");
	else printf("ipv4 has options. IHL: %d\n", ihl);

	/* What type is it? */
	switch (packet_ipv4->protocol) {
	case IPV4_TCP:
		printf("ipv4 protocol: tcp\n");
		pp_tcp((const struct tcp_hdr*)&packet_ipv4->data[ihl - IPV4_IHL_MIN], ntohs(packet_ipv4->length) - ihl);
		break;
	case IPV4_UDP:
		printf("ipv4 protocol: udp\n");
		break;
	case IPV4_ICMP:
		printf("ipv4 protocol: icmp\n");
		break;
	default:
		printf("ipv4 protocol: unknown\n");
		break;
	}
}

/* Pretty-prints tcp data */
void pp_tcp(const struct tcp_hdr *packet_tcp, uint16_t length) {
	/* Prints port */
	printf("PORT: %d -> %d\n", ntohs(packet_tcp->src), ntohs(packet_tcp->dest));
	
	/* Check header length */
	uint8_t hl = TCP_HL(packet_tcp);
	if (hl > TCP_HL_MAX) error("Invalid tcp packet!", "HL is too big");
	else if (hl < TCP_HL_MIN) error("Invalid tcp packet!", "HL is too small");
	
	/* Now prints data in tcp */
	uint8_t S[33];
	uint32_t len = length - hl;
	printf("TCP length: %u\n", len);
	if (len > 32) len = 32; /* Cut data if they are too long */
	make_readable(S, &packet_tcp->data[hl - TCP_HL_MIN], len);
	printf("Data: %s\n", S);
}

/* Make packet readable */
void make_readable(uint8_t *B, const uint8_t *S, uint32_t len) {
	for (uint32_t i = 0; i < len; ++i) {
		/* 32 ~ 126 are readable ascii-codes (32 is space) */
		if (33 <= S[i] && S[i] <= 126) {
			B[i] = S[i];
		} else {
			B[i] = '.';
		}
	}
	B[len] = '\0';
}
