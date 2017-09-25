#include <stdint.h>

#ifndef NET_STRUCT_H
#define NET_STRUCT_H

/* ipv4 */
#define GET_VER(XX) (uint8_t)((XX)->VIHL & 0x0F)
#define GET_IHL(XX) (uint8_t)((XX)->VIHL & 0xF0)

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

#endif
