#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <pcap.h>

#include "communicator.h"

void get_ip_address_behind_gateway(const char *interface, char *address,char *inet_addr)
{
	struct ifreq req;
	int sock;
	int i;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(req.ifr_name,interface,MAX_INTERFACE_STRING_LEN);
	req.ifr_addr.sa_family = AF_INET;

	ioctl(sock,SIOCGIFHWADDR,&req);
	ioctl(sock,SIOCGIFADDR,&req);

	strncpy(address,req.ifr_hwaddr.sa_data,MAC_LENGTH);

	printf("Address that talks to Gateway: ");
	for(i = 0; i < 6; i++)
	{
		printf("%02x",address[i]);
		if(i != 5)
			printf(":");
		else
			printf("\n");
	}
	i = strlen(inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr));
	strncpy(inet_addr,inet_ntoa(((struct sockaddr_in *)&req.ifr_addr)->sin_addr),i);
	printf("Internet Address: %s\n",inet_addr);
}

void do_nothing()
{
	return;
}