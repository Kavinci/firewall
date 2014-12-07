#include "parser.h"


const char *ingress = 	"wlan0";
const char *egress 	= 	"eth0";

const char *ep1s 	= 	"ep1s";
const char *ep1 	= 	"ep1";

const char *pass 	= 	"pass";
const char *block 	= 	"block";

const char *tcp 	= 	"tcp";
const char *udp 	= 	"udp";

uint8_t *open_ports;

uint16_t get_open_port(int repopulate)
{
	int i;
	char contents[STRING_BUFF_SIZE];
	char *reader;
	int port_in_use;
	if(!open_ports || repopulate)
	{
		// Free old structure if we are repopulating array
		if(open_ports)
			free(open_ports);

		open_ports = malloc(sizeof(uint8_t) * PORT_RANGE);
		for(i = 0;i < PORT_RANGE; i++)
			open_ports[i] = 1;
		FILE* fp = fopen("/proc/net/tcp","r");
		if(fp == NULL)
		{
			printf("Error opening file\n");
			exit(1);
		}
		// DISCARD FIRST LINE
		fgets(contents,STRING_BUFF_SIZE,fp);
		while(fgets(contents,STRING_BUFF_SIZE,fp))
		{
			reader = strtok(contents, " ");
			reader = strtok(NULL," ");
			strncpy(contents,reader,STRING_BUFF_SIZE);
			reader = strtok(contents,":");
			reader = strtok(NULL," ");
			port_in_use = atoi(reader);
			open_ports[port_in_use] = 0;
		}

		if(fp != NULL)
			fclose(fp);
	}

	i = PORT_RANGE - 5000;
	while(open_ports[i] == 0 && i > 0)
	{
		i--;
	}
	if (i == 0)
		return 0;
	
	open_ports[i] = 0;
	return i;
}

void return_port_in_use(int port)
{
	// Do nothing if we don't ever get a port
	if(!open_ports)
		return;

	open_ports[port] = 1;
}

void free_port_structure()
{
	if(open_ports)
	{
		free(open_ports);
	}
}

void read_rules_file(FILE* fp,rule_t *rules)
{
	char *reader;
	int rules_read = 0;
	int i = 0;
	int parse_error = 0;
	struct in_addr addr;
	int low_port, high_port, mask;
	char contents[STRING_BUFF_SIZE];

	// Read Garbage line
	fgets(contents,STRING_BUFF_SIZE,fp);

	while(fgets(contents,STRING_BUFF_SIZE,fp))
	{
		reader = strtok(contents," ");
		i = 0;
		parse_error = 1;
		rule_t rule_being_read = (rule_t)malloc(sizeof(struct rule));
		while (reader != NULL)
		{
			switch(i)
			{
				case INTERFACE_DELIM:
					if (strcmp(reader,ingress) == 0)
					{
						rule_being_read->interface = INTERFACE_WORLD;
					}
					else if(strcmp(reader,egress) == 0)
					{
						rule_being_read->interface = INTERFACE_PROTECTED;
					}
					else
					{
						printf("No defined interface: %s\n",reader);
						parse_error = INTERFACE_DELIM;
						exit(MISREAD_RULE);
					}
				break;
				case ACTION_DELIM:
					if(strcmp(reader,pass) == 0)
					{
						rule_being_read->action = PASS;
					}
					else if(strcmp(reader,block) == 0)
					{
						rule_being_read->action = BLOCK;
					}
					else
					{
						parse_error = ACTION_DELIM;
						exit(MISREAD_RULE);
					}
				break;
				case PROTOCOL_DELIM:
					if(strcmp(reader,tcp) == 0)
					{
						rule_being_read->protocol = TCP;
					}
					else if(strcmp(reader,udp) == 0)
					{
						rule_being_read->protocol = UDP;
					}
					else
					{
						printf("No defined protocol: %s\n",reader);
						parse_error = PROTOCOL_DELIM;
						exit(MISREAD_RULE);
					}
				break;
				case PORT_LOW_DELIM:
					low_port =  atoi(reader);
					rule_being_read->ports_low = low_port;
					if(!low_port)
					{
						parse_error = PORT_LOW_DELIM;
						exit(MISREAD_RULE);
					}
				break;
				case PORT_HIGH_DELIM:
					high_port =  atoi(reader);
					rule_being_read->ports_low = high_port;
					if(!high_port)
					{
						parse_error = PORT_HIGH_DELIM;
						exit(MISREAD_RULE);
					}
				break;
				case IP_SRC_DELIM:
					if(inet_pton(AF_INET,reader,&addr))
					{
						rule_being_read->ip_address_src = addr.s_addr;
					}
					else
					{
						printf("No defined source address\n");
						exit(MISREAD_RULE);
					}
				break;
				case IP_SRC_MASK_DELIM:
					mask =  atoi(reader);
					rule_being_read->ip_mask_src = mask;
					mask = 0;
				break;
				case IP_DST_DELIM:
					if(inet_pton(AF_INET,reader,&addr))
					{
						rule_being_read->ip_address_dst = addr.s_addr;
					}
					else
					{
						printf("No defined destination address\n");
						exit(MISREAD_RULE);
					}
				break;
				case IP_DST_MASK_DELIM:
					mask =  atoi(reader);
					rule_being_read->ip_mask_dst = mask;
				break;
				default:
					printf("Error %d\n",parse_error);
					exit(MISREAD_RULE);
				break;
			}
			i++;
			reader = strtok(NULL," ");
		}

		rules[rules_read] = rule_being_read;
		rules_read++;
	}
	printf("Rules Parsed: %d\n",rules_read);
}

void write_log(char *dest,char** entries)
{
	FILE *f = fopen(dest,"w");
	if(f == NULL)
	{
		printf("Unable to open file.\n");
		exit(FILE_WRITE_ERROR);
	}

	while(entries != NULL)
	{
		fprintf(f, "%s\n", *entries);
		entries++;
	}

	if(f != NULL)
		fclose(f);
}