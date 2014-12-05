#include <stdio.h>
#include "arp-handler.h"

void get_hardware_address(const char *interface, char * address)
{
	struct ifreq req;
	int sock;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(req.ifr_name,interface,MAX_INTERFACE_STRING_LEN);
	ioctl(sock,SIOCGIFHWADDR,&req);
	strncpy(address,req.ifr_hwaddr.sa_data,MAC_LENGTH);
}

// void resolve_arp_requests(char *address,char *interface)
// {
// 	char error_buffer[PCAP_ERRBUF_SIZE];
// 	pcap_t *handler = NULL;
// 	struct pcap_pkthdr packet_header;
// 	char *packet = NULL;
// 	arp_packet_t arp_header = NULL;
// 	uint32_t addr, mask;
// }
