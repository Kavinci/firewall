.PHONY: all compile

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
	