#ifndef __ICMP
#define __ICMP

#include "communicator.h"

void *forward_icmp(void *interfaces);


#define INTERFACE_HANDLE_ERROR 400
#define ICMP_TIMEOUT_ERROR 401
#define ICMP_COMPILE_ERROR 402
#define ICMP_ACTIVATE_ERROR 403
#define ICMP_FILTER_ERROR 404
#endif