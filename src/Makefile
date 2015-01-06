.PHONY: all firewall clean

CC = gcc
LIBS = -lpthread -lpcap
CFLAGS = -Wall -ggdb -g -funsigned-char

SRCS = defs.c 		\
	communicator.c 	\
	parser.c 		\
	arp-handler.c 	\
	icmp.c 			\
	rules.c 		\
	firewall.c 
HDRS = $(SRCS:.c=.h)

FILES = $(SRCS) $(HDRS)

all: firewall
	sudo ./firewall wlan0 ep1s
firewall: $(FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
clean:
	rm -f firewall
	rm -f log.txt
curate:
	rm -f *.o
