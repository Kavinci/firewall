/** @file firewall.h
 *  @brief Top-Level execution file
 *
 *  This is the main entrypoint to the firewall program.
 *  Tasks implemented in this file:
 *  - Parsing rules file
 *  - Creating ARP Handling server
 *  - Initializing communication modules
 *  - Handling heap memory
 *   
 */
#ifndef __firewall
#define __firewall

#include <stdint.h>

#define STRING_BUFF_SIZE 1024
#define MAX_RULE_SIZE 10

int main(int argc, char **argv);

// Private 
void initialize_rules(rule_t *rules);
void run_icmp_forwarder();

#define RULE_READ_ERROR 1
#define THREAD_CREATE_ERROR 2
#define NOT_ENOUGH_ARGS 3
#define PIPE_CREATE_ERROR 4

#endif