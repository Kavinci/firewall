#ifndef __DEFS
#define __DEFS


// Make sure indents don't break anything
#define MAC_LENGTH 		12
#define IP_LENGTH		16
#define PROTOCOL_UDP 	0x11
#define PROTOCOL_TCP 	0x06
#define PROTOCOL_ICMP	0x01

#define IP_HDR_LEN 		20
#define UDP_HDR_LEN		12
#include <stdint.h>

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

struct tcp_hdr
{
	uint8_t src_port[2];
	uint8_t dst_port[2];
	uint8_t seq_num[4];
	uint8_t ack_num[4];
	uint8_t off_res;
	uint8_t flags;
	uint8_t window_size[2];
	uint8_t checksum[2];
	uint8_t urg_ptr[2];
	uint8_t options_and_data[0];
};
typedef struct tcp_hdr* tcp_hdr_t;

struct udp_hdr
{
	uint8_t src_port[2];
	uint8_t dst_port[2];
	uint8_t length[2];
	uint8_t checksum[2];
	uint8_t options_and_data[0];
};
typedef struct udp_hdr* udp_hdr_t;

struct nat_mapping
{
	uint8_t originator_hw_addr[6];
	uint32_t originator_ip_addr;
	uint16_t originator_src_port;
};
typedef struct nat_mapping* nat_mapping_t;

uint16_t unpack_port(uint8_t* port);

uint32_t unpack_ip_addr(uint8_t* addr);

void pack_ip_addr(uint8_t* store,uint32_t addr);
void pack_and_convert_ip_addr(uint8_t* store,uint32_t addr);

void pack_port(uint8_t* store, uint16_t port);

#endif