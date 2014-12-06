.PHONY: all firewall clean

CC = gcc
LIBS = -lpthread -lpcap
CFLAGS = -Wall -ggdb -g -funsigned-char

SRCS = communicator.c \
	parser.c \
	arp-handler.c \
	icmp.c \
	firewall.c 
HDRS = $(SRCS:.c=.h)

FILES = $(SRCS) $(HDRS)

all: firewall
	./firewall
firewall: $(FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)
clean:
	rm -f firewall
	rm -f log.txt
curate:
	rm -f *.o
