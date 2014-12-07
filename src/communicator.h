#ifndef __COMMUNICATOR
#define __COMMUNICATOR


#include "arp-handler.h"
#include "parser.h"

#define GATEWAY "192.168.252.1"
#define GATEWAY_HW_ADDR {0x00,0x0f,0xea,0xee,0x99,0x71}
#define IP_LENGTH 16

struct io
{
	const char *input;
	const char *output;
};
typedef struct io* io_t;

void initialize_NAT_mappings();

void get_my_addresses(const char *interface, char *address,char *inet_addr);

void transfer_to_world(pcap_t *out,const u_char* packet_to_send,int len);

void transfer_to_protected_space(pcap_t *out,const u_char *packet_to_send,int len);

// ERROR CODES

#define UNDEFINED_INTERFACE 500


#endif