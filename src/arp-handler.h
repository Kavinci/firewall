/** @file arp-handler.h
 *  @brief ARP handling protocol within the protected space.
 *  
 *  Implemented functions include a hardware address generator.
 *  There is also a main loop that resolves the ARP requests.
 */
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
#define MAX_ARP_PACKET_SIZE 1024


/** @struct arp_packet
 *  @brief Packets that get injected or recovered from the protected netspace.
 *
 *  This is the structure of the packet that gets injected on the wire.
 *  Notice that the ethernet frame is wrapped around the packet as well.
 *  This is just because it is easier to deal with rather than having multiple
 *  pointers.
 */
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
void *resolve_arp_requests(void *inter);

// ERROR CODES

#define HANDLE_ERROR 200
#define LOOKUP_ERROR 201
#define PACKET_ERROR 202
#define ACTIVATE_ERROR 203
#define TIMEOUT_ERROR 204
#define FILTER_ERROR 205
#define COMPILE_ERROR 206
#define UNKNOWN_ERROR 207

#endif