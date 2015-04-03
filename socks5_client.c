#include <stddef.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include "socks.h"
#include "socks_util.h"
#include "socks5_client.h"

struct socks5_client_handler {
	void *cbdata;
	socks5_error_handler errorcb;
	socks5_success_handler successcb;
	enum socks_addr_types addrtype;
	union socks_address address;
	uint16_t port;
};

#define CALLERRORCB(handler,error) {\
	if((handler)->errorcb)\
		(handler)->errorcb((error),(handler)->cbdata);\
	free(handler);\
	return;\
}

#define CALLSUCCESSCB(handler,bev) {\
	if((handler)->successcb)\
		(handler)->successcb((bev),(handler)->cbdata);\
	free(handler);\
	return;\
}

//TODO: choose auths in a better way
static void socks5_send_auth (struct bufferevent *bev,
			      struct socks5_client_handler *handler)
{
	uint8_t supported_auths[3] = {SOCKS5,1,SOCKS5_AUTH_NONE};
	bufferevent_write (bev, supported_auths, 3);
}

static void socks5_send_request (struct bufferevent *bev,
				 struct socks5_client_handler *handler)
{
	size_t size = socks5_get_request_size (handler->addrtype,
					       handler->address.dns.size);
	assert (size != 0);
	uint8_t request[size];
	request[0] = SOCKS5;
	request[1] = SOCKS_CMD_CONNECT;
	request[2] = 0; //RSV
	request[3] = handler->addrtype;
	switch (handler->addrtype)
	{
		case SOCKS5_ADDR_IPV4:
			memcpy(request+4,&(handler->address.ip),4);
			break;
		case SOCKS5_ADDR_IPV6:
			memcpy(request+4,handler->address.ipv6, 16);
			break;
		case SOCKS5_ADDR_DNS:
			request[4] = handler->address.dns.size;
			memcpy(request+5,handler->address.dns.value,
			       handler->address.dns.size);
			break;
	}
	memcpy(request+size-2,&(handler->port),2);
	bufferevent_write (bev, request, size);
}

static void socks5_event_cb(struct bufferevent *bev, short error,
			    struct socks5_client_handler *handler)
{
	if (error & BEV_EVENT_CONNECTED)
		return;
	if (error & BEV_EVENT_EOF) {
		CALLERRORCB(handler,SOCKS5_NOT_SOCKS5);
	} else if (error & BEV_EVENT_ERROR) {
		CALLERRORCB(handler,SOCKS5_GEN_FAIL);
	} else if (error & BEV_EVENT_TIMEOUT) {
		CALLERRORCB(handler,SOCKS5_NOT_SOCKS5);
	}
}

static void socks5_read_reply_cb (struct bufferevent *bev,
				  struct socks5_client_handler *handler)
{
	struct evbuffer *input;
	input = bufferevent_get_input(bev);
	if (evbuffer_get_length(input) < MIN_SOCKS5_REPLY_SIZE)
		return;

	int res;
	uint8_t peek[5];
	res = evbuffer_copyout(input, peek, 5);
	assert(res == 5);
	
	if (peek[0] != SOCKS5)
		CALLERRORCB(handler,SOCKS5_NOT_SOCKS5);
	if (!is_supported_socks5_err_type(peek[1]))
		CALLERRORCB(handler,SOCKS5_NOT_SOCKS5);
	if (peek[2] != 0)
		CALLERRORCB(handler,SOCKS5_NOT_SOCKS5);
	if (!is_supported_socks5_addr_type(peek[3]))
		CALLERRORCB(handler,SOCKS5_NOT_SOCKS5);

	size_t size = socks5_get_reply_size (peek[3], peek[4]);
	assert(size);

	if (evbuffer_get_length(input) < size) return;
	uint8_t reply[size];

	res = evbuffer_remove(input, reply, size);
	assert ((size_t)res == size);
	
	if(reply[2] != SOCKS5_OK)
		CALLERRORCB(handler,reply[2]);

	//TODO: pass around reply data
	CALLSUCCESSCB(handler,bev);

}

static void socks5_choose_auth_cb (struct bufferevent *bev,
				   struct socks5_client_handler *handler)
{
	struct evbuffer *input;
	input = bufferevent_get_input(bev);
	if (evbuffer_get_length(input) < 2) return;
	uint8_t auth_cmd[2];
	int res = evbuffer_remove(input, auth_cmd, 2);
	assert (res == 2);
	if (auth_cmd[0] != SOCKS5)
		CALLERRORCB(handler,SOCKS5_NOT_SOCKS5);
	if(auth_cmd[1] != SOCKS5_AUTH_NONE)
		CALLERRORCB(handler,SOCKS5_AUTH_UNSUP);
	bufferevent_setcb(bev, (bufferevent_data_cb)socks5_read_reply_cb,
			  NULL, (bufferevent_event_cb)socks5_event_cb,
			  (void *)handler);
	bufferevent_setwatermark(bev, EV_READ, MIN_SOCKS5_REPLY_SIZE, MAX_SOCKS5_REPLY_SIZE);
	socks5_send_request (bev, handler);
	socks5_read_reply_cb (bev, handler);
}


static void socks5_do_connect (struct bufferevent *bev, enum socks_addr_types addrtype,
		     const union socks_address *address, uint16_t port,
		     socks5_error_handler errorcb,
		     socks5_success_handler successcb, void * cbdata)
{
	struct socks5_client_handler * handler = malloc(sizeof(struct socks5_client_handler));
	handler->cbdata = cbdata;
	handler->errorcb = errorcb;
	handler->successcb = successcb;
	handler->addrtype = addrtype;
	handler->address = *address;
	handler->port = port;
	bufferevent_setcb(bev, (bufferevent_data_cb)socks5_choose_auth_cb,
			  NULL, (bufferevent_event_cb)socks5_event_cb,
			  (void *)handler);
	bufferevent_enable(bev, EV_READ|EV_WRITE);
	bufferevent_setwatermark(bev, EV_READ, 2, 2);
	socks5_send_auth(bev, handler);
}

void socks5_connect (struct bufferevent *bev, struct sockaddr *sa, size_t ssa,
		     socks5_error_handler errorcb,
		     socks5_success_handler successcb, void * cbdata)
{
	uint16_t port;
	enum socks_addr_types addrtype;
	union socks_address address;
	switch (sa->sa_family)
	{
		case AF_INET6:
		{
			if (ssa < sizeof(struct sockaddr_in6)) return;
			struct sockaddr_in6 * destination;
			destination = (struct sockaddr_in6 *)sa;
			addrtype = SOCKS5_ADDR_IPV6;
			port = destination->sin6_port;
			memcpy(address.ipv6, &(destination->sin6_addr), 16);
		}
			break;
		case AF_INET:
		{
			if (ssa < sizeof(struct sockaddr_in)) return;
			struct sockaddr_in * destination;
			destination = (struct sockaddr_in *)sa;
			addrtype = SOCKS5_ADDR_IPV4;
			port = destination->sin_port;
			memcpy(&address.ip, &(destination->sin_addr), 4);
		}
			break;
		default: return;
	}
	socks5_do_connect(bev, addrtype, &address, port, errorcb, successcb,
			  cbdata);
}

void socks5_connect_hostname (struct bufferevent *bev, const char *name,
			      uint16_t port, socks5_error_handler errorcb,
			      socks5_success_handler successcb, void * cbdata)
{
	size_t dnslen = strlen(name);
	if ( dnslen > MAX_SOCKS_HOSTNAME_SIZE)
		return;
	union socks_address address;
	address.dns.size = dnslen;
	memcpy(address.dns.value,name,dnslen);
	socks5_do_connect(bev, SOCKS5_ADDR_DNS, &address, port, errorcb,
			  successcb, cbdata);
}