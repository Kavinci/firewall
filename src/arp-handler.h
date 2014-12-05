#ifndef 	__ARP_HANDLER
#define 	__ARP_HANDLER

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <pcap.h>

#define MAX_INTERFACE_STRING_LEN 10
#define MAC_LENGTH 12

struct ethernet_hdr
{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint8_t ethertype[2];
	uint8_t data[0];
};
typedef struct ethernet_hdr* ethernet_hdr_t;

struct arp_packet
{
	uint16_t 	hw_type;
	uint16_t 	pr_type;
	uint8_t 	hw_addr_len;
	uint8_t 	pr_addr_len;
	uint16_t 	opcode;
	uint8_t 	hw_src_addr[6];
	uint8_t 	ip_src_addr[4];
	uint8_t 	hw_dst_addr[6];
	uint8_t 	ip_dst_addr[4];
};
typedef struct arp_packet* arp_packet_t;

void get_hardware_address(const char *interface, char *address);

void resolve_arp_requests(char *address,char *interface);

#endif