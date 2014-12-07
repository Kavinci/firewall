#ifndef __RULES
#define __RULES

#include "communicator.h"

void *forward_tcp(void *interfaces);


#define TCP_INTERFACE_HANDLE_ERROR 600
#define TCP_TIMEOUT_ERROR 601
#define TCP_COMPILE_ERROR 602
#define TCP_ACTIVATE_ERROR 603
#define TCP_FILTER_ERROR 604
#endif