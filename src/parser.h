#ifndef __PARSER
#define __PARSER

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>

#define STRING_BUFF_SIZE 1024

struct rule
{
	uint8_t 	interface;
	uint8_t 	action;
	uint8_t 	protocol;
	uint16_t 	ports_low;
	uint16_t    ports_high;
	uint32_t 	ip_address_src;
	uint8_t 	ip_mask_src;
	uint32_t 	ip_address_dst;
	uint8_t 	ip_mask_dst;
};
typedef struct rule* rule_t;

// INTERFACES

extern const char *ingress;
extern const char *egress;

extern const char *ep1s;
extern const char *ep1;
#define INTERFACE_WORLD 0
#define INTERFACE_PROTECTED 1

// ACTION

extern const char *pass;
extern const char *block;

#define PASS 1
#define BLOCK 0

// PROTOCOL 

extern const char *tcp;
extern const char *udp;

#define TCP 0
#define UDP 1

// RULE PARSING

#define INTERFACE_DELIM 0
#define ACTION_DELIM 1
#define PROTOCOL_DELIM 2
#define PORT_LOW_DELIM 3
#define PORT_HIGH_DELIM 4
#define IP_SRC_DELIM 5
#define IP_SRC_MASK_DELIM 6
#define IP_DST_DELIM 7
#define IP_DST_MASK_DELIM 8
#define ERROR_DELIM 9

#define PORT_RANGE 65536

#define REPOPULATE_PORT 1
#define DEFAULT_PORT_BEHAVIOR 0

uint16_t get_open_port(int repopulate);
void return_unused_port();
void free_port_structure();

/*
 *  Read a rule file to create the rule struct
 *  This is then passed to the firewall creator
 */
void read_rules_file(FILE* fp,rule_t* rules);

void write_log(char* dest,char** entries);

char* get_mac_address(const char *interface, char *address);


// ERROR CODES

#define MISREAD_RULE 100
#define FILE_WRITE_ERROR 101

#endif