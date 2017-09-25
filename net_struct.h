#include <stdint.h>

#ifndef NET_STRUCT_H
#define NET_STRUCT_H

/* eth */
#define ETH_ALEN 6
#define ETH_HLEN 14

#define ETH_ARP  0x0806
#define ETH_IPV4 0x0800
#define ETH_IPV6 0x86DD

struct eth_hdr {
	uint8_t dest[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t type;
	uint8_t data[0];
} __attribute__((packed));

/* ipv4 */
#define IPV4_VER(XX) ((uint8_t)(((XX)->VIHL & 0xF0) >> 4))
#define IPV4_HL(XX)  ((uint8_t)(((XX)->VIHL & 0x0F) << 2))

#define IPV4_HL_MIN 20
#define IPV4_ALEN 0x04

#define IPV4_ICMP 0x01
#define IPV4_TCP  0x06
#define IPV4_UDP  0x11

struct ipv4_hdr {
	uint8_t VIHL; /* Version(4), IHL(4) */
	uint8_t DSCP_ECN; /* DSCP(6), ECN(2) */
	uint16_t length; /* Total length */
	uint16_t id; /* Identification */
	uint16_t FF; /* Flags(2), Fragment offset(14) */
	uint8_t TTL;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src[4];
	uint8_t dest[4];
	uint8_t data[0];
} __attribute__((packed));

/* tcp */
#define TCP_HL(XX) ((uint8_t)((((uint8_t*)(&(XX)->DRF))[0] & 0xF0) >> 2))
#define TCP_HL_MIN 20
#define TCP_HL_MAX 60

struct tcp_hdr {
	uint16_t src;
	uint16_t dest;
	uint32_t seq;
	uint32_t ack;
	uint16_t DRF; /* Data offset (4), Reserved (3), Flags (9) */
	uint16_t wsize;
	uint16_t checksum;
	uint16_t urg;
	uint8_t payload[0];
} __attribute__((packed));

#endif
