#ifndef __COMMUNICATOR
#define __COMMUNICATOR


#include "arp-handler.h"
#define GATEWAY 192.168.252.1

struct io
{
	const char *input;
	const char *output;
};
typedef struct io* io_t;


#endif