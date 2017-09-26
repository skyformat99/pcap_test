all: pcap_test

pcap_test: main.o
	gcc -g -O2 -opcap_test main.o -lpcap

main.o: net_struct.h
	gcc -g -c -O2 -omain.o main.c

clean:
	rm -f pcap_test
	rm -f *.o
