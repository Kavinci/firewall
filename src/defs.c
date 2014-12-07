#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "defs.h"

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


void pack_ip_addr(uint8_t* store,uint32_t addr)
{
	memcpy(store,&addr,sizeof(addr));
}

void pack_and_convert_ip_addr(uint8_t* store,uint32_t addr)
{
	addr = htonl(addr);
	memcpy(store,&addr,sizeof(addr));
}

void pack_port(uint8_t* store, uint16_t port)
{
	port = htons(port);
	memcpy(store,&port,sizeof(port));
}