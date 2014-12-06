#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "firewall.h"
#include "parser.h"
#include "arp-handler.h"

void initialize_rules(rule_t *rules)
{
	FILE *fp;
	int i;

	fp = fopen("rules.txt","r");
	if(fp == NULL)
	{
		printf("Error reading rule file\n");
		exit(RULE_READ_ERROR);
	}

	for(i = 0; i < MAX_RULE_SIZE; i++)
		rules[i] = NULL;

	read_rules_file(fp,rules);
	if(fp != NULL)
	{
		fclose(fp);
	}
}

void graceful_exit(rule_t *rules)
{
	int i;
	for(i = 0; i < MAX_RULE_SIZE; i++)
	{
		if(rules[i])
			free(rules[i]);
	}
	free_port_structure();
}

int main(int argc, char **argv)
{	
	pthread_t arp_server;
	rule_t rules[MAX_RULE_SIZE];
	char address[MAC_LENGTH + 1];
	int i;

	initialize_rules(rules);

	// CREATE ARP RESPONSE MODULE
	get_open_port(REPOPULATE_PORT);
	for(i = 0; i <= MAC_LENGTH; i++)
		address[i] = '\0';
	get_hardware_address(ep1s,address);
	if(pthread_create( &arp_server, NULL, resolve_arp_requests,(void *) ep1s))
	{
		printf("Error creating pthread.\n");
		exit(THREAD_CREATE_ERROR);
	}



	pthread_join( arp_server, NULL );
	graceful_exit(rules);

	return 0;
}