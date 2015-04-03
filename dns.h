#ifndef DNS_H
#define DNS_H
#include <event2/event.h>

#define MAX_DNS_LEN 255
#define MAX_DNS_STR (MAX_DNS_LEN + 1)
int addr_to_name (const struct sockaddr_storage *ss, char *dest, size_t dest_len);

//ipv4addr start_dns_server (event_base *base);
int start_dns_server (struct event_base *base);
#endif
