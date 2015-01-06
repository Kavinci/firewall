#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <pcap.h>

#include "communicator.h"
#include "defs.h"
#include "parser.h"

nat_mapping_t safe_to_unsafe_mapping[PORT_RANGE];
uint16_t unsafe_to_safe_mapping[PORT_RANGE];
nat_mapping_t translation_ICMP[0xff];

const char *global_interface;

const char global_gtwy_hw_addr[MAC_LENGTH] = GATEWAY_HW_ADDR;
const char *global_gtwy_inet_addr = GATEWAY;

char global_self_hw_addr[MAC_LENGTH+1];
char global_self_inet_addr[IP_LENGTH];
uint32_t global_self_inet_addr_net_order;

void initialize_NAT_mappings()
{
	int i;
	for(i = 0; i < PORT_RANGE; i++)
	{
		safe_to_unsafe_mapping[i] = NULL;
		unsafe_to_safe_mapping[i] = 0x00;

		// unsafe_to_safe_mapping_udp[i] = NULL;
		// unsafe_to_safe_mapping_tcp[i] = NULL;
	}
}

void get_my_addresses(const char *interface, char *address,char *inet_addr)
{
	struct ifreq req;
	int sock;
	int i;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(req.ifr_name,interface,MAX_INTERFACE_STRING_LEN);
	req.ifr_addr.sa_family = AF_INET;

	ioctl(sock,SIOCGIFHWADDR,&req);
	strncpy(address,req.ifr_hwaddr.sa_data,MAC_LENGTH);
	strncpy(global_self_hw_addr,req.ifr_hwaddr.sa_data,MAC_LENGTH);
	printf("My Hardware Address: ");
	for(i = 0; i < 6; i++)
	{
		printf("%02x",address[i]);
		if(i != 5)
			printf(":");
		else
			printf("\n");
	}

	ioctl(sock,SIOCGIFADDR,&req);
	i = strlen(inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr));
	strncpy(inet_addr,inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr),i);
	strncpy(global_self_inet_addr,inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr),i);
	printf("Internet Address: %s\n",inet_addr);
}

/*
 *  Need to make sure those addresses are defined
 *  by calling get_my_addresses before.
 */
void set_up_outgoing_ether(nat_mapping_t map,ethernet_hdr_t packet_ether)
{
	int i;
	for(i = 0; i < 6; i++)
	{
		if(map != NULL)
		{
			map->originator_hw_addr[i] = packet_ether->src_mac[i];
		}
		packet_ether->src_mac[i] = global_self_hw_addr[i];
		packet_ether->dst_mac[i] = global_gtwy_hw_addr[i];
	}
}

// Verified Correct
void calculate_ip_checksum(ip_hdr_t packet_ip)
{
	int i;
	uint16_t word;
	uint32_t acc=0xffff;
	packet_ip->header_checksum[0] = 0x00;
	packet_ip->header_checksum[1] = 0x00;

	for(i = 0; i < IP_HDR_LEN; i+=2)
	{
		memcpy(&word,((char *)packet_ip) + i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
	}
	// Put the accumulator in network byte order
	pack_port(packet_ip->header_checksum,~acc);
}

void calculate_udp_checksum(ip_hdr_t packet_ip,udp_hdr_t packet_udp)
{
	uint16_t src_addr[2];
	uint16_t dst_addr[2];
	uint16_t protocol;
	uint16_t length;
	uint16_t udp_length;
	uint16_t word;
	int i,pad;
	uint32_t acc;
	uint16_t final_checksum;
	char *buff;

	src_addr[0] = (packet_ip->src_ip[0] << 8) + packet_ip->src_ip[1];
	src_addr[1] = (packet_ip->src_ip[2] << 8) + packet_ip->src_ip[3];

	dst_addr[0] = (packet_ip->dst_ip[0] << 8) + packet_ip->dst_ip[1];
	dst_addr[1] = (packet_ip->dst_ip[2] << 8) + packet_ip->dst_ip[3];

	packet_udp->checksum[0] = 0x00;
	packet_udp->checksum[1] = 0x00;

	protocol = PROTOCOL_UDP;
	length = (packet_ip->total_len[0] << 8) + packet_ip->total_len[1];
	udp_length = (packet_udp->length[0] << 8) + packet_udp->length[1];

	buff = (char *)packet_udp;
	acc = 0;
	if(udp_length % 2 == 0)
		pad = 1;

	for(i = 0; i < udp_length + pad; i+=2)
	{
		if(i+1 < udp_length)
			word =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
		else
			word =((buff[i]<<8)&0xFF00);
		acc = acc + word;
	}

	acc = acc + src_addr[0] + src_addr[1];
	acc = acc + dst_addr[0] + dst_addr[1];

	acc = acc + htons(protocol);
	acc = acc + length;
	while (acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	acc = ~acc;
	final_checksum = (uint16_t)acc;
	pack_port(packet_udp->checksum,final_checksum);
}

void calculate_tcp_checksum(ip_hdr_t packet_ip,tcp_hdr_t packet_tcp)
{
	uint16_t src_addr[2];
	uint16_t dst_addr[2];
	uint16_t protocol;
	uint16_t length;
	uint16_t counter;
	uint32_t acc;
	uint16_t *tcp_iterator;
	uint16_t final_checksum;

	src_addr[0] = (packet_ip->src_ip[0] << 8) + packet_ip->src_ip[1];
	src_addr[1] = (packet_ip->src_ip[2] << 8) + packet_ip->src_ip[3];

	dst_addr[0] = (packet_ip->dst_ip[0] << 8) + packet_ip->dst_ip[1];
	dst_addr[1] = (packet_ip->dst_ip[2] << 8) + packet_ip->dst_ip[3];

	protocol = PROTOCOL_TCP;
	length = (packet_ip->total_len[0] << 8) + packet_ip->total_len[1];
	counter = length;
	tcp_iterator = (uint16_t *)packet_tcp;

	acc = 0;
	while (counter > 1)
	{
		acc = acc + *(tcp_iterator);
		tcp_iterator++;
		if(acc & 0x80000000)
		{
			acc = (acc & 0xffff) + (acc >> 16);
		}
		counter = counter - 2;
	}

	if(counter & 1) // Faster comparison
	{
		acc = acc + *((uint8_t *)tcp_iterator);
	}

	acc = acc + src_addr[0] + src_addr[1];
	acc = acc + dst_addr[0] + dst_addr[1];

	acc = acc + htons(protocol);
	acc = acc + length;
	while(acc >> 16)
		acc = (acc & 0xffff) + (acc >> 16);
	acc = ~acc;
	final_checksum = (uint16_t)acc;
	pack_port(packet_tcp->checksum,final_checksum);
}

void transfer_to_world(pcap_t *out,const u_char* packet_to_send,int len)
{
	ethernet_hdr_t packet_ether;
	ip_hdr_t packet_ip;
	tcp_hdr_t packet_tcp;
	udp_hdr_t packet_udp;
	uint16_t src_port,nat_port;
	uint32_t ip_src,my_src;
	nat_mapping_t map;
	struct sockaddr_in mine;
	int result;

	inet_aton(global_self_inet_addr,&mine.sin_addr);
	my_src = mine.sin_addr.s_addr;
	packet_ether = (ethernet_hdr_t)packet_to_send;
	packet_ip = (ip_hdr_t)packet_ether->data;
	packet_tcp = (tcp_hdr_t)packet_ip->options_and_data;
	packet_udp = (udp_hdr_t)packet_ip->options_and_data;
	switch(packet_ip->protocol)
	{
		case PROTOCOL_UDP:
			src_port = unpack_port(packet_udp->src_port);
			ip_src = unpack_ip_addr(packet_ip->src_ip);

			if(!unsafe_to_safe_mapping[src_port])
			{
				nat_port = get_open_port(DEFAULT_PORT_BEHAVIOR);
				map = (nat_mapping_t)(malloc(sizeof(struct nat_mapping)));
				map->originator_ip_addr = ip_src;
				map->originator_src_port = src_port;
				pack_port(packet_udp->src_port,nat_port);
				safe_to_unsafe_mapping[nat_port] = map;
				unsafe_to_safe_mapping[src_port] = nat_port;
			}
			else
			{
				map = safe_to_unsafe_mapping[unsafe_to_safe_mapping[src_port]];
				pack_port(packet_udp->src_port,unsafe_to_safe_mapping[src_port]);
			}
			set_up_outgoing_ether(map,packet_ether);
			pack_ip_addr(packet_ip->src_ip,my_src);
			calculate_ip_checksum(packet_ip);
			calculate_udp_checksum(packet_ip,packet_udp);
			result = pcap_inject(out,packet_to_send,len);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}
		break;
		case PROTOCOL_TCP:
			src_port = unpack_port(packet_tcp->src_port);
			ip_src = unpack_ip_addr(packet_ip->src_ip);

			if(!unsafe_to_safe_mapping[src_port])
			{
				nat_port = get_open_port(DEFAULT_PORT_BEHAVIOR);
				map = (nat_mapping_t)(malloc(sizeof(struct nat_mapping)));
				map->originator_ip_addr = ip_src;
				map->originator_src_port = src_port;
				pack_port(packet_tcp->src_port,nat_port);
				safe_to_unsafe_mapping[nat_port] = map;
				unsafe_to_safe_mapping[src_port] = nat_port;
			}
			else
			{
				map = safe_to_unsafe_mapping[unsafe_to_safe_mapping[src_port]];
				pack_port(packet_tcp->src_port,unsafe_to_safe_mapping[src_port]);
			}
			set_up_outgoing_ether(map,packet_ether);
			pack_ip_addr(packet_ip->src_ip,my_src);
			calculate_ip_checksum(packet_ip);
			calculate_tcp_checksum(packet_ip,packet_tcp);
			result = pcap_inject(out,packet_to_send,len);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}
		break;
		case PROTOCOL_ICMP:
			map = (nat_mapping_t)(malloc(sizeof(struct nat_mapping)));
			set_up_outgoing_ether(map,packet_ether);
			ip_src = unpack_ip_addr(packet_ip->src_ip);
			map->originator_ip_addr = ip_src;
			translation_ICMP[packet_ip->dst_ip[0]] = map;
			pack_ip_addr(packet_ip->src_ip,my_src);
			calculate_ip_checksum(packet_ip);
			calculate_tcp_checksum(packet_ip,packet_tcp);
			result = pcap_inject(out,packet_to_send,len);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}
		break;
		default:
			printf("Unknown Protocol being sent out: %d\n",packet_ip->protocol);
			return;
		break;
	}
	// Compute Checksum
	// PCAP INJECT
	printf("Returning from transfer\n");
}

void set_up_ether_to_protected(nat_mapping_t map,ethernet_hdr_t packet_ether)
{
	int i;
	for(i = 0; i < 6; i++)
	{
		packet_ether->dst_mac[i] = map->originator_hw_addr[i];
		packet_ether->src_mac[i] = global_self_hw_addr[i];
	}
}

void transfer_to_protected_space(pcap_t *out, const u_char *packet_to_send,int len)
{
	ethernet_hdr_t packet_ether;
	ip_hdr_t packet_ip;
	tcp_hdr_t packet_tcp;
	udp_hdr_t packet_udp;
	uint16_t dst_port;
	nat_mapping_t map;
	int result;

	packet_ether = (ethernet_hdr_t)packet_to_send;
	packet_ip = (ip_hdr_t)packet_ether->data;
	packet_tcp = (tcp_hdr_t)packet_ip->options_and_data;
	packet_udp = (udp_hdr_t)packet_ip->options_and_data;
	switch(packet_ip->protocol)
	{
		case PROTOCOL_UDP:
			dst_port = unpack_port(packet_udp->dst_port);
			map = safe_to_unsafe_mapping[dst_port];
			if(map == NULL)
				return;
			set_up_ether_to_protected(map,packet_ether);

			pack_and_convert_ip_addr(packet_ip->dst_ip,map->originator_ip_addr);
			pack_port(packet_udp->dst_port,map->originator_src_port);
			calculate_ip_checksum(packet_ip);
			calculate_udp_checksum(packet_ip,packet_udp);
			result = pcap_inject(out,packet_to_send,len);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}
		break;
		case PROTOCOL_TCP:
			dst_port = unpack_port(packet_tcp->dst_port);
			map = safe_to_unsafe_mapping[dst_port];
			if(map == NULL)
				return;
			set_up_ether_to_protected(map,packet_ether);
			pack_and_convert_ip_addr(packet_ip->dst_ip,map->originator_ip_addr);
			pack_port(packet_tcp->dst_port,map->originator_src_port);
			calculate_ip_checksum(packet_ip);
			calculate_tcp_checksum(packet_ip,packet_tcp);
			result = pcap_inject(out,packet_to_send,len);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}
		break;
		case PROTOCOL_ICMP:
			map = translation_ICMP[packet_ip->src_ip[0]];
			if(map == NULL)
				return;
			set_up_ether_to_protected(map,packet_ether);
			pack_and_convert_ip_addr(packet_ip->dst_ip,map->originator_ip_addr);
			calculate_ip_checksum(packet_ip);
			result = pcap_inject(out,packet_to_send,len);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}
		break;
		default:

		break;
	}
}


