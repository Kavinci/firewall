firewall
========

Simple C Firewall - Status of project.

Currently, there is no firewall functionality.
However, all the other pieces are there.

There is a text rule parser that converts rules to be used by my program.
This parser class also checks /proc/net/tcp to see whether ports are in use.
This parser class also is able to log to a file in the current directory.

There is a hashtable that has had modifications from project 2.
It has been tested further and is flexible enough to be used in the logical
places in this assignment. 

There is a fully functioning ARP handling system. It runs on its own thread
and responds to ARP requests within the network. It has been thoroughly tested
and is known to work.

I am planning on continuing to work on the core functionality, as most of the
pieces are in place. The first thing that will be implemented is a cleaner
forwarding abstraction. Right now I have ICMP functionaly working in my 
firewall but it is poorly designed. Packets are just haphazardly forwarded.

Once that interface is done, it will be easy to enumerate over the set of rules
and forward packets that need to be forwarded and drop those that do not.

Thanks for looking at the code.
Akshay Dongaonkar (akd54).
