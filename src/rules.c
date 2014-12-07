#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "rules.h"
#include "communicator.h"

void *forward_tcp(void *interfaces)
{
	pcap_t *handler_in						= NULL;
	pcap_t *handler_out						= NULL;
	struct pcap_pkthdr* packet_header_in	= NULL;
	struct pcap_pkthdr* packet_header_out	= NULL;
	struct bpf_program fp_in;
	struct bpf_program fp_out;
	char err_buff_in[PCAP_ERRBUF_SIZE];
	char err_buff_out[PCAP_ERRBUF_SIZE];
	const u_char *packet_in;
	const u_char *packet_out;
	io_t ports = (io_t)interfaces;
	char *compile_program = "ip and tcp";


	err_buff_in[PCAP_ERRBUF_SIZE-1] 	= '\0';
	err_buff_out[PCAP_ERRBUF_SIZE-1] 	= '\0';

	handler_in = pcap_create(ports->input,err_buff_in);
	handler_out = pcap_create(ports->output,err_buff_out);

	int result;
	int turn = 0;

	if(handler_in == NULL || handler_out == NULL)
	{
		printf("Could not open Interface.\n");
		printf("Error Message: %s,%s\n",err_buff_in,err_buff_out);
		exit(TCP_INTERFACE_HANDLE_ERROR);
	}

	if(pcap_set_timeout(handler_in,10) || pcap_set_timeout(handler_out,10))
	{
		printf("Error setting pcap timeout\n");
		exit(TCP_TIMEOUT_ERROR);
	}

	if(pcap_activate(handler_in))
	{
		printf("Error activating External Interface.\n");
		pcap_perror(handler_in,err_buff_in);
		exit(TCP_ACTIVATE_ERROR);
	}

	if(pcap_activate(handler_out))
	{
		printf("Error activating Internal Interface.\n");
		pcap_perror(handler_out,err_buff_out);
		exit(TCP_ACTIVATE_ERROR);
	}

	if(pcap_compile(handler_in,&fp_in,compile_program,0,PCAP_NETMASK_UNKNOWN) ||
		pcap_compile(handler_out,&fp_out,compile_program,0,PCAP_NETMASK_UNKNOWN))
	{
		printf("Can't Compile: %s, %s",pcap_geterr(handler_in),pcap_geterr(handler_out));
		exit(TCP_COMPILE_ERROR);
	}

	if(pcap_setfilter(handler_in,&fp_in) !=0 || pcap_setfilter(handler_out,&fp_out) != 0)
	{
		printf("Couldn't get filter to setup: %s, %s\n",pcap_geterr(handler_in),pcap_geterr(handler_out));
		exit(TCP_FILTER_ERROR);
	}

	printf("Setting up TCP loop.\n");
	while(1)
	{
		if(turn % 2)
		{
			result = pcap_next_ex(handler_in,&packet_header_in,&packet_in);
			if(result == 1)
			{
				transfer_to_protected_space(handler_out,packet_in,packet_header_in->len);
			}
		}
		else
		{
			result = pcap_next_ex(handler_out,&packet_header_out,&packet_out);
			if(result == 1)
			{
				transfer_to_world(handler_in,packet_out,packet_header_out->len);
			}
		}
		turn++;
	}

	return NULL;
}