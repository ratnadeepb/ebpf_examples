CC=clang
CFLAGS=-O2 -Wall -target bpf

all: drop_arp.o drop_icmp.o

drop_arp.o: drop_arp.c
	${CC} ${CFLAGS} -c $^ -o $@

drop_icmp.o: drop_icmp.c
	${CC} ${CFLAGS} -c $^ -o $@

clean:
	@rm -rf *.o