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
#include "icmp.h"

const char *big_bad_world;
const char *protected_space;

rule_t rules[MAX_RULE_SIZE];
char address[MAC_LENGTH + 1];

pthread_t arp_server;
pthread_t icmp_forwarder;

char *log_location = "log.txt";
struct io pipes;

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


void run_arp_server()
{
	int i;
	get_open_port(REPOPULATE_PORT);
	for(i = 0; i <= MAC_LENGTH; i++)
		address[i] = '\0';
	get_hardware_address(protected_space,address);
	if(pthread_create( &arp_server, NULL, resolve_arp_requests,(void *) protected_space))
	{
		printf("Error creating pthread for ARP.\n");
		exit(THREAD_CREATE_ERROR);
	}
}

void run_icmp_forwarder()
{
	pipes.input 	= big_bad_world;
	pipes.output 	= protected_space;

	if(pthread_create( &icmp_forwarder, NULL, forward_icmp,(void *)(&pipes)))
	{
		printf("Error creating pthread for ICMP.\n");
		exit(THREAD_CREATE_ERROR);
	}
}



int main(int argc, char **argv)
{	

	if(argc != 3)
	{
		printf("Usage firewall <input interface> <output interface>\n");
		exit(NOT_ENOUGH_ARGS);
	}
	big_bad_world 	= argv[1];
	protected_space = argv[2];

	// READ THE RULE SET
	initialize_rules(rules);

	// CREATE ARP RESPONSE MODULE
	run_arp_server();

	// CREATE ICMP FORWARDER
	run_icmp_forwarder();

	

	// WRITE TO LOG SOME ENTRIES. CURRENTLY NOTHING TO WRITE. 
	write_log(log_location,NULL);

	pthread_join( arp_server, NULL );
	pthread_join( icmp_forwarder, NULL );

	graceful_exit(rules);

	return 0;
}