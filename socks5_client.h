#ifndef SOCKS5_CLIENT
#define SOCKS5_CLIENT
#include <stddef.h>
#include <stdint.h>
#include <event2/bufferevent.h>
//TODO: the callback should be cleaner
#include "socks.h"

typedef void (*socks5_error_handler)(enum socks_err_types, void *);
typedef void (*socks5_success_handler)(struct bufferevent *, void *);

void socks5_connect (struct bufferevent *bev, struct sockaddr *sa, size_t ssa,
		     socks5_error_handler errorcb,
		     socks5_success_handler successcb, void * cbdata);

void socks5_connect_hostname (struct bufferevent *bev, const char *name,
			      uint16_t port, socks5_error_handler errorcb,
			      socks5_success_handler successcb, void * cbdata);
#endif