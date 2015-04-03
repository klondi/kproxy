/** Kproxy is a C program intended to do proxying stuff*/
/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
/* For fcntl */
#include <fcntl.h>

#include <event2/event.h>
#include <event2/util.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/netfilter_ipv4.h>
#include <net/if.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <netdb.h>
#include "socks5_client.h"
#include "tproxy.h"
#include "dns.h"

#define MAX_LINE 16384

struct tproxy_handler {
	struct bufferevent *local;
	struct bufferevent *remote;
	struct sockaddr_storage destination; //TODO: use dns
};

static int get_real_destination (evutil_socket_t sock, const struct sockaddr_storage *ss, struct sockaddr_storage *dest) {
	socklen_t socklen = sizeof(struct sockaddr_storage);
	switch (ss->ss_family) {
		case AF_INET6:
			if (!IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)ss)->sin6_addr)))
				return getsockopt(sock, IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST, dest, &socklen);
		case AF_INET:
			return getsockopt(sock, IPPROTO_IP, SO_ORIGINAL_DST, dest, &socklen);
		default:
			memcpy(dest,ss,sizeof(struct sockaddr_storage));
			return 0;
	}
}

//TODO: move somewhere else
int addr_to_string (const struct sockaddr_storage *ss, char *dest, size_t dest_len) {
// 	if(addr_to_name (ss, dest, dest_len))
// 		return 1;
	switch (ss->ss_family) {
		case AF_INET6:
			if (!IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)ss)->sin6_addr)))
				return inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)ss)->sin6_addr), dest, dest_len) != NULL;
			else {
				struct in_addr addr;
				memcpy(&addr,((char *)&(((struct sockaddr_in6 *)ss)->sin6_addr))+12,sizeof(struct in_addr));
				return inet_ntop(AF_INET, &addr, dest, dest_len) != NULL;
			}
		case AF_INET:
			return inet_ntop(AF_INET, &(((struct sockaddr_in *)ss)->sin_addr), dest, dest_len) != NULL;
		default:
			strncpy(dest,"???",dest_len);
			return 0;
	}
}

static void eventcb(struct bufferevent *bev, short error, struct tproxy_handler *handler);
static void local_read_cb(struct bufferevent *bev, struct tproxy_handler *handler);
static void remote_read_cb(struct bufferevent *bev, struct tproxy_handler *handler);

static void proxy_socks5_error_handler (enum socks_err_types error, struct tproxy_handler *handler) {
	printf("SOCKS5 ERROR! %d\n",error);
	bufferevent_free(handler->local);
	bufferevent_free(handler->remote);
	free(handler);
}

static void proxy_socks5_success_handler (struct bufferevent *bev, struct tproxy_handler *handler) {
	puts("SOCKS5 SUCCESS!");
	bufferevent_enable(handler->local, EV_READ|EV_WRITE);
	bufferevent_enable(handler->remote, EV_READ|EV_WRITE);
	bufferevent_setwatermark(handler->local, EV_READ, 0, MAX_LINE);
	bufferevent_setwatermark(handler->remote, EV_READ, 0, MAX_LINE);
	bufferevent_setcb(handler->local, (bufferevent_data_cb)local_read_cb, NULL, (bufferevent_event_cb)eventcb, handler);
	bufferevent_setcb(handler->remote, (bufferevent_data_cb)remote_read_cb, NULL, (bufferevent_event_cb)eventcb, handler);
}

inline static void readcb(struct bufferevent *bev, struct bufferevent *other)
{
	puts("Reading data!");
	bufferevent_write_buffer (other, bufferevent_get_input(bev));
	bufferevent_flush (other, EV_WRITE, BEV_FLUSH);
}

static void local_read_cb(struct bufferevent *bev, struct tproxy_handler *handler)
{
	readcb(handler->local,handler->remote);
}

static void remote_read_cb(struct bufferevent *bev, struct tproxy_handler *handler)
{
	readcb(handler->remote,handler->local);
}


static void eventcb(struct bufferevent *bev, short error, struct tproxy_handler *handler)
{
	puts("EVENT!");
	if (error & BEV_EVENT_CONNECTED && bev == handler->remote) {
		char dnsname[MAX_DNS_STR];
		struct sockaddr *dest = (struct sockaddr *)&(handler->destination);
		if (addr_to_name (&(handler->destination), dnsname, MAX_DNS_STR)) {
			fprintf(stderr,"Connecting to %s:80\n",dnsname);
			socks5_connect_hostname (bev, dnsname, htons(80),
						 (socks5_error_handler) proxy_socks5_error_handler,
						 (socks5_success_handler) proxy_socks5_success_handler,
						 (void *)handler);
		} else {
			char straddr[256];
			addr_to_string(&handler->destination, straddr,sizeof(straddr));
			fprintf(stderr,"Connecting to %s:80\n",straddr);
			socks5_connect(bev, dest,
				       sizeof(handler->destination),
				       (socks5_error_handler) proxy_socks5_error_handler,
				       (socks5_success_handler) proxy_socks5_success_handler,
				       (void *)handler);
		}
		return;
	}
	if (error & BEV_EVENT_EOF) {
		bufferevent_flush (handler->local, EV_WRITE, BEV_FLUSH);
		bufferevent_flush (handler->remote, EV_WRITE, BEV_FLUSH);
		/* connection has been closed, do any clean up here */
		/* ... */
	} else if (error & BEV_EVENT_ERROR) {
		/* check errno to see what error occurred */
		/* ... */
	} else if (error & BEV_EVENT_TIMEOUT) {
		/* must be a timeout event handle, handle it */
		/* ... */
	}
	bufferevent_free(handler->local);
	bufferevent_free(handler->remote);
	free(handler);
}

static void do_accept(evutil_socket_t listener, short event, struct event_base *base)
{
	struct sockaddr_storage ss;
	socklen_t slen = sizeof(ss);
	evutil_socket_t fd = accept(listener, (struct sockaddr*)&ss, &slen);
	if (fd < 0) {
		perror("accept");
	} else if (fd > FD_SETSIZE) {
		close(fd);
	} else {
		struct tproxy_handler *handler = malloc(sizeof(struct tproxy_handler));
		{
			char straddr[256];
			addr_to_string(&ss, straddr,sizeof(straddr));
			printf("%s %d\n", straddr, ntohs(ss.ss_family == AF_INET6? ((struct sockaddr_in6 *)&ss)->sin6_port: ((struct sockaddr_in *)&ss)->sin_port));
		}
		{
			int error;
			error = get_real_destination (fd, &ss, &(handler->destination));
			if (error) {
				free(handler);
				perror("getsockopt");
			}
			else 
			{
				char straddr[256];
				addr_to_string(&(handler->destination), straddr,sizeof(straddr));
				printf("%s %d\n", straddr, ntohs((handler->destination).ss_family == AF_INET6? ((struct sockaddr_in6 *)&(handler->destination))->sin6_port: ((struct sockaddr_in *)&(handler->destination))->sin_port));
				*((handler->destination).ss_family == AF_INET6? &((struct sockaddr_in6 *)&(handler->destination))->sin6_port: &((struct sockaddr_in *)&(handler->destination))->sin_port) = htons(80);

				//Set the bufferevent on the local side
				evutil_make_socket_nonblocking(fd);
				handler->local = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
				//Set the bufferevent on the remote side
				handler->remote = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

				bufferevent_setcb(handler->remote, NULL, NULL, (bufferevent_event_cb)eventcb, handler);

				//HACK: get configuration somehow
				struct sockaddr_in sin;
				memset(&sin, 0, sizeof(sin));
				sin.sin_family = AF_INET;
				sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
				sin.sin_port = htons(8080); /* Port 8080 */
				bufferevent_socket_connect(handler->remote, (struct sockaddr *) &sin, sizeof(sin));
			}
		}
	}
}

int start_tproxy_server (struct event_base *base)
{
	evutil_socket_t listener;
	static struct event *listener_event;

	struct sockaddr_in6 sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin6_family = AF_INET6;
	sin.sin6_addr = in6addr_any;
	sin.sin6_port = htons(40713);

	listener = socket(AF_INET6, SOCK_STREAM, 0);
	evutil_make_socket_nonblocking(listener);
	if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0)
		return -1;

	if (listen(listener, 16)<0)
		return -2;

// event_assign(&port->event, port->event_base,
//                          port->socket, EV_READ | EV_PERSIST,
//                          server_port_ready_callback, port);
      //TODO: memleak
	listener_event = event_new(base, listener, EV_READ|EV_PERSIST, (event_callback_fn)do_accept, (void*)base);
	/*XXX check it */
	if(event_add(listener_event, NULL))
		return -3;
	return 0;
}
