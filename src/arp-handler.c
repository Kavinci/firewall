/** @file arp-handler.c
 *  @brief Implementation of arp-handler.h
 *  @internal
 */
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "arp-handler.h"
#include "defs.h"

const char *global_interface;
char interface_server[MAC_LENGTH+1];

/** @fn void get_hardware_address(const char *interface, char *address)
 *  @brief Uses <sys/ioctl.h> to get HW addresses. 
 *
 *  @pre address is a valid 7 byte buffer.
 *  @param interface The ethernet interface whose address is needed
 *  @param address 7 byte buffer where interface address is filled
 *  @returns hw address of \b interface in \b address
 */
void get_hardware_address(const char *interface, char *address)
{
	struct ifreq req;
	int sock;
	int i;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(req.ifr_name,interface,MAX_INTERFACE_STRING_LEN);
	ioctl(sock,SIOCGIFHWADDR,&req);
	strncpy(address,req.ifr_hwaddr.sa_data,MAC_LENGTH);

	strncpy(interface_server,address,MAC_LENGTH);
	interface_server[MAC_LENGTH] = '\0';
	global_interface = interface;

	printf("Ethernet Address: ");
	for(i = 0; i < 6; i++)
	{
		printf("%02x",address[i]);
		if(i != 5)
			printf(":");
		else
			printf("\n");
	}
}

/** @fn char* get_mac_address(const char *interface, char *address)    
 *  @brief a memoized version of get hardware address
 *    
 *  @pre The interface being called never changes
 */
char* get_mac_address(const char *interface, char *address)
{
	if(interface_server[MAC_LENGTH] != '\0')
	{
		get_hardware_address(interface,address);
	}
	return interface_server;
}


/** @internal
 *  @fn void populate_response(char* resolve,char *address)
 *  @brief prepopulate the response packet.
 *  
 *  @pre resolve is a buffer the size of a struct arp_packet
 *  @pre address contains ethernet address and is null terminated
 *  @param resolve A buffer containing an arp packet struct
 *  @param address An address populated by get_mac_address
 *  @return resolve packet is filled
 *  
 */
void populate_response(char* resolve,char *address)
{
	int i;
	arp_packet_t resp = (arp_packet_t)(resolve);
	for(i = 0 ; i < 6 ; i++)
	{
		resp->src_mac[i] = address[i];
		resp->hw_src_addr[i] = address[i];
		resp->dst_mac[i] = 0xff;
	}

	resp->ethertype[0] = 0x08;
	resp->ethertype[1] = 0x06;

	resp->hw_type[0] = 0x00;
	resp->hw_type[1] = 0x01;
	resp->pr_type[0] = 0x08;
	resp->pr_type[1] = 0x00;
	resp->hw_addr_len = 6;
	resp->pr_addr_len = 4;
	resp->opcode[0] = 0;
	resp->opcode[1] = 2;
	resp->ip_src_addr[0] = 0xff;
	resp->ip_src_addr[1] = 0xff;
	resp->ip_src_addr[2] = 0xff;
	resp->ip_src_addr[3] = 0xff;
}

void *resolve_arp_requests(void *inter)
{
	// PCAP STUFF
	pcap_t *handler 					= NULL;
	struct pcap_pkthdr* packet_header	= NULL;
	struct bpf_program fp;
	char err_buff[PCAP_ERRBUF_SIZE];

	// GRABBING DATA
	const u_char *packet 				= NULL;
	arp_packet_t arp 					= NULL;
	uint32_t net,mask					= 0;
	int i,result 						= 0;

	// RESPONDING TO DATA
	char resolve[ARP_RESP_LEN];
	char *compile_program 				= "ether dst ff:ff:ff:ff:ff:ff";
	const void *response_packet 		= (void *)resolve;
	arp_packet_t resp 					= (arp_packet_t)(resolve);

	// RESETTING ADDRESS
	char *address = interface_server;
	const char *interface = (const char *)inter;

	// Make Sure Correct State
	if(interface != global_interface)
		return NULL;

	populate_response(resolve,address);
	handler = pcap_create(interface,err_buff);

	if(handler == NULL)
	{
		printf("Could not open Interface %s.\n",interface);
		printf("Error Message: %s\n",err_buff);
		exit(HANDLE_ERROR);
	}

	if(pcap_set_timeout(handler,1000))
	{
		printf("Error setting pcap timeout\n");
		exit(TIMEOUT_ERROR);
	}

	result = pcap_lookupnet(interface,&net,&mask,err_buff);
	if (result != 0) {
		 net = 0;
		 mask = 0;
	 }

	if(pcap_activate(handler) != 0)
	{
		printf("Error activating pcap handler on interface: %s.\n",interface);
		pcap_perror(handler,err_buff);
		exit(ACTIVATE_ERROR);
	}

	if(net == 0)
	{
		
		if(pcap_compile(handler,&fp,compile_program,0,PCAP_NETMASK_UNKNOWN) != 0)
		{
			printf("Can't compile: %s\n", pcap_geterr(handler));
			exit(COMPILE_ERROR);
		}
	}
	else
	{
		if(pcap_compile(handler,&fp,compile_program,0,net) != 0)
		{
			printf("Can't compile with netmask: %s\n", pcap_geterr(handler));
			exit(COMPILE_ERROR);
		}
	}
	

	if(pcap_setfilter(handler,&fp) != 0)
	{
		printf("Couldn't get filter to setup: %s\n",pcap_geterr(handler));
		exit(FILTER_ERROR);
	}

	while(1)
	{
		result = pcap_next_ex(handler,&packet_header,&packet);
		if(result == 1)
		{
			arp = (arp_packet_t)(packet);
			if(unpack_port(arp->pr_type) == ARP_IP)
			for(i = 0; i < 6; i++)
			{
				resp->hw_dst_addr[i] = arp->hw_src_addr[i];
			}
			for(i = 0; i < 4; i++)
			{
				resp->ip_src_addr[i] = arp->ip_dst_addr[i];
				resp->ip_dst_addr[i] = arp->ip_src_addr[i];
			}

			result = pcap_inject(handler,response_packet,ARP_RESP_LEN);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}

		}
		else if (result == -2)
		{
			printf("REACHED EOF\n");
			return NULL;
		}
		else if(result == -1)
		{
			printf("Packet Error.\n");
			printf("Error Message: %s\n",err_buff);
			exit(PACKET_ERROR);
		}
	}
}
