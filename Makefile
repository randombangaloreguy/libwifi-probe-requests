CC=clang
CFLAGS=-Wall -Werror -O3 -o parse_probe
LDFLAGS=-lpcap -lwifi

parse_eapol: parse_probe.o
	$(CC) $(CFLAGS) parse_probe.c $(LDFLAGS)

clean:
	rm parse_probe *.o
