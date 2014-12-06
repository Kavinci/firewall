#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#include "icmp.h"

void *forward_icmp(void *interfaces)
{
	io_t ports = (io_t)interfaces;
	printf("Ports %s in and %s out\n",ports->input,ports->output );
	return NULL;
}