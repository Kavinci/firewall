#include <stdio.h>
#include <stdlib.h>
#include <pcap.h> 
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "firewall.h"
#include "defs.h"
#include "parser.h"
#include "arp-handler.h"
#include "icmp.h"
#include "rules.h"
#include "communicator.h"

const char *big_bad_world;
const char *protected_space;

rule_t rules[MAX_RULE_SIZE];
char my_mac_address[MAC_LENGTH + 1];

pthread_t arp_server;
pthread_t icmp_forwarder;
pthread_t rule_enforcer;

char *log_location = "log.txt";
struct io pipes;

char big_bad_mac[MAC_LENGTH + 1];
char big_bad_ip[IP_LENGTH];

/** @fn void initialize_rules(rule_t *rules)
 *  @brief Parse rules and convert it into internal structures.
 *
 *  Refer to parser.h for how these rules are read.
 */
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

/** @fn void graceful_exit(rule_t *rules);
 *  @brief Free long running structures.
 *  
 *  If program works correctly, should never really happen.
 */
void graceful_exit(rule_t *rules)
{
	int i;
	for(i = 0; i < MAX_RULE_SIZE; i++)
	{
		if(rules[i])
		{
			free(rules[i]);
		}
	}
	free_port_structure();
}

/** @fn void run_arp_server()
 *  @brief Spawns a thread that manages ARPs in the protected space
 *
 *  Main functionality documented in arp-handler.h
 */
void run_arp_server()
{
	int i;
	get_open_port(REPOPULATE_PORT);
	for(i = 0; i <= MAC_LENGTH; i++)
		my_mac_address[i] = '\0';
	get_hardware_address(protected_space,my_mac_address);
	if(pthread_create( &arp_server, NULL, resolve_arp_requests,(void *) protected_space))
	{
		printf("Error creating pthread for ARP.\n");
		exit(THREAD_CREATE_ERROR);
	}
}

/** @fn void run_icmp_forwarder()
 *  @brief Transfer ICMP packets between the protected/public space
 *
 *  Main functionality documented in icmp.h
 */
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

void run_global_forwarder()
{
	pipes.input 	= big_bad_world;
	pipes.output 	= protected_space;

	if(pthread_create( &rule_enforcer, NULL, forward_tcp,(void *)(&pipes) ))
	{
		printf("Unable to create pipe pthread.\n");
		exit(PIPE_CREATE_ERROR);
	}
}


/** @fn int main(int argc, char **argv)
 *  @brief Main entrypoint for the firewall.
 *
 *  Usage: Call ./firewall int0 int1
 *  int0 - Input Interface (connection to outside world)
 *  int1 - Output Interface (connection to protected space)
 *  
 *  You might need to run this with sudo if you do not have permissions.
 */
int main(int argc, char **argv)
{	

	if(argc != 3)
	{
		printf("Usage firewall <input interface> <output interface>\n");
		exit(NOT_ENOUGH_ARGS);
	}
	big_bad_world 	= argv[1];
	protected_space = argv[2];

	// SET UP NAT STRUCTURES
	get_my_addresses(big_bad_world,big_bad_mac,big_bad_ip);
	printf("Mac Address (unreadable): %s\n",big_bad_mac);
	printf("IP Address (readable): %s\n",big_bad_ip);
	initialize_NAT_mappings();

	// READ THE RULE SET
	initialize_rules(rules);

	// CREATE ARP RESPONSE MODULE
	run_arp_server();

	// CREATE ICMP FORWARDER - on average 27 ms delay
	run_icmp_forwarder();

	// THIS IS WHERE FIREWALL RULES ARE SUPPOSED TO GO
	run_global_forwarder();

	// WRITE TO LOG SOME ENTRIES. CURRENTLY NOTHING TO WRITE. 
	// write_log(log_location,NULL);

	 pthread_join( arp_server, NULL );
	 pthread_join( icmp_forwarder, NULL );

	// Exit after freeing heap space
	graceful_exit(rules);

	return 0;
}