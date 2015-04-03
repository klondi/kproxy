.PHONY: clean all

all: kproxy

clean:
	rm -rf *.o kproxy

%.o: %.c
	$(CC) -c -o $@ $^ $(CFLAGS) -levent -std=gnu99

kproxy: kproxy.o socks5_client.o dns.o tproxy.o
	$(CC) -o $@ $^ $(CFLAGS) -levent -std=gnu99
