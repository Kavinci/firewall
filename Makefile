.PHONY: all compile netspace doc

all:
	cd reports/final && make
	cd reports/intermediate && make
	cd src && make
compile:
	cd reports/final && make compile
	cd reports/intermediate && make compile
	cd src && make firewall
	cd reports/final && make curate
	cd reports/intermediate && make curate
netspace:
	sudo ip netns add ep1
	sudo ip link add name ep1 type veth peer name ep1s
	sudo ip link set ep1 up netns ep1
	sudo ip link set ep1s up
	sudo ip netns exec ep1 ifconfig ep1 10.0.0.1 netmask 255.255.255.0 broadcast 10.0.0.255 up
	sudo ip netns exec ep1 ip link set lo up
	sudo ip netns exec ep1 route add default gw 10.0.0.1
	sudo ip netns exec ep1 bash
doc:
	doxygen doc/firewall_doxygen
clean:
	cd src && make clean
	cd reports/final && make clean
	cd reports/intermediate && make clean
