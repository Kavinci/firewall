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
#define MAX_ARP_PACKET_SIZE 1024

struct ethernet_hdr
{
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint8_t ethertype[2];
	uint8_t data[0];
};
typedef struct ethernet_hdr* ethernet_hdr_t;

struct ip_hdr
{
	uint8_t version_ihl;
	uint8_t dscp_enc;
	uint8_t total_len[2];
	uint8_t identification[2];
	uint8_t flags_offset[2];
	uint8_t ttl;
	uint8_t protocol;
	uint8_t header_checksum[2];
	uint8_t src_ip[4];
	uint8_t dst_ip[4];
	uint8_t options_and_data[0];
};
typedef struct ip_hdr* ip_hdr_t;

struct arp_packet
{
	uint8_t 	dst_mac[6];
	uint8_t 	src_mac[6];
	uint8_t 	ethertype[2];
	uint8_t 	hw_type[2];
	uint8_t 	pr_type[2];
	uint8_t 	hw_addr_len;
	uint8_t 	pr_addr_len;
	uint8_t 	opcode[2];
	uint8_t 	hw_src_addr[6];
	uint8_t 	ip_src_addr[4];
	uint8_t 	hw_dst_addr[6];
	uint8_t 	ip_dst_addr[4];
};
typedef struct arp_packet* arp_packet_t;

#define ARP_RESP_LEN 42
#define ARP_IP 0x0800

void get_hardware_address(const char *interface, char *address);

void resolve_arp_requests(const char *interface, char *address);

// ERROR CODES

#define HANDLE_ERROR 200
#define LOOKUP_ERROR 201
#define PACKET_ERROR 202
#define ACTIVATE_ERROR 203
#define TIMEOUT_ERROR 204
#define FILTER_ERROR 205
#define COMPILE_ERROR 206

#endif