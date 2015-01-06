Firewall
========

This is a simple firewall that mediates packets between two interfaces.
Currently, there is no firewall functionality.
However, all the other pieces are there.

There is a text rule parser that converts rules to be used by my program.
This parser class also checks /proc/net/tcp to see whether ports are in use.
This parser class also is able to log to a file in the current directory.

There is a fully functioning ARP handling system. It runs on its own thread
and responds to ARP requests within the network. It has been thoroughly tested
and is known to work.

There is a communicator system that moves packets from one interface to another.

TODO:
Fix UDP/TCP checksums to properly receive packets from a netspace.
Spawn threads to mediate access between the netspace and the outside world.
Implement the filter functionality. 

Maintained by Akshay Dongaonkar (akd54).
