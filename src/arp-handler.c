#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "arp-handler.h"



void get_hardware_address(const char *interface, char *address)
{
	struct ifreq req;
	int sock;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(req.ifr_name,interface,MAX_INTERFACE_STRING_LEN);
	ioctl(sock,SIOCGIFHWADDR,&req);
	strncpy(address,req.ifr_hwaddr.sa_data,MAC_LENGTH);
}

void resolve_arp_requests(const char *interface, char *address)
{
	char err_buff[PCAP_ERRBUF_SIZE];
	pcap_t *handler = NULL;
	struct pcap_pkthdr* packet_header;
	//struct bpf_program *fp;
	const u_char *packet = NULL;
	//arp_packet_t arp_header = NULL;
	//uint32_t addr;
	int i,result;

	handler = pcap_create(interface,err_buff);
	if(handler == NULL)
	{
		printf("Could not open Interface %s.\n",interface);
		printf("Error Message: %s\n",err_buff);
		exit(HANDLE_ERROR);
	}

	if(pcap_set_timeout(handler,60000))
	{
		printf("Error setting pcap timeout\n");
		exit(TIMEOUT_ERROR);
	}

	if(pcap_activate(handler) != 0)
	{
		printf("Error activating pcap handler on interface: %s.\n",interface);
		pcap_perror(handler,err_buff);
		exit(ACTIVATE_ERROR);
	}

	for(i = 0; i < 5 ; i++)
	{
		result = pcap_next_ex(handler,&packet_header,&packet);
		if(result == -1)
		{
			printf("Packet Error.\n");
			printf("Error Message: %s\n",err_buff);
			exit(PACKET_ERROR);
		}
		else if (result == -2)
		{
			printf("REACHED EOF\n");
			return;
		}
		else if(result == 0)
		{
			printf("Callback timed out.\n");
		}
		else if(result == 1)
		{
			printf("Got a packet with length: %d!\n",packet_header->len);
		}
		else
		{
			pcap_perror(handler,err_buff);
		}
	}

}
