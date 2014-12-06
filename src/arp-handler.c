#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "arp-handler.h"



void get_hardware_address(const char *interface, char *address)
{
	struct ifreq req;
	int sock;
	int i;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(req.ifr_name,interface,MAX_INTERFACE_STRING_LEN);
	ioctl(sock,SIOCGIFHWADDR,&req);
	strncpy(address,req.ifr_hwaddr.sa_data,MAC_LENGTH);
	printf("Ethernet Address");
	for(i = 0; i < 6; i++)
	{
		printf("%02x",address[i]);
		if(i != 5)
			printf(":");
		else
			printf("\n");
	}
}

uint16_t unpack_port(uint8_t* port)
{
	uint16_t result;
	result = 0;
	result += port[0] << 8;
	result += port[1];
	return result;
}

uint32_t unpack_ip_addr(uint8_t* addr)
{
	uint32_t result;
	result = 0;
	result += addr[0] << 24;
	result += addr[1] << 16;
	result += addr[2] << 8;
	result += addr[3];
	return result;
}

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

void resolve_arp_requests(const char *interface, char *address)
{
	char err_buff[PCAP_ERRBUF_SIZE];
	pcap_t *handler = NULL;
	struct pcap_pkthdr* packet_header;
	struct bpf_program fp;
	const u_char *packet = NULL;
	arp_packet_t arp = NULL;
	uint32_t net,mask;
	int i,j,result;
	char resolve[ARP_RESP_LEN];
	char *compile_program = "ether dst ff:ff:ff:ff:ff:ff";
	const void *response_packet = (void *)resolve;
	arp_packet_t resp = (arp_packet_t)(resolve);

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
		 printf("Can't get netmask for device: %s with error %d.\n", interface,result);
		 net = 0;
		 mask = 0;
		 //exit(LOOKUP_ERROR);
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

	for(i = 0; i < 5 ; i++)
	{
		printf("Looking for an ARP Packet\n");
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
			arp = (arp_packet_t)(packet);
			if(unpack_port(arp->pr_type) == ARP_IP)
			for(j = 0; j < 6; j++)
			{
				resp->hw_dst_addr[j] = arp->hw_src_addr[j];
			}
			for(j = 0; j < 4; j++)
			{
				resp->ip_src_addr[j] = arp->ip_dst_addr[j];
				resp->ip_dst_addr[j] = arp->ip_src_addr[j];
			}

			result = pcap_inject(handler,response_packet,ARP_RESP_LEN);
			if(result == -1)
			{
				printf("PCAP response injection broke down.\n");
			}
		}
		else
		{
			pcap_perror(handler,err_buff);
		}
	}

}
