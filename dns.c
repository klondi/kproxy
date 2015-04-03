#include <arpa/inet.h>
#include <event2/dns.h>
#include <event2/dns_struct.h>
#include <event2/util.h>
#include <event2/event.h>

#include <sys/socket.h>

#include <string.h>
#include <assert.h>
#include "ext/uthash/src/uthash.h"
#include "dns.h"

#define LISTEN_PORT 5300

struct domainmap {
	char domain[MAX_DNS_STR];
	struct in6_addr ipv6;
	struct in_addr ipv4;
	UT_hash_handle hhdom;
	UT_hash_handle hhipv6;
	UT_hash_handle hhipv4;
	struct event *remove;
};

struct v4_range {
	struct in_addr ip;
	struct in_addr mask;
};

struct v6_range {
	struct in6_addr ip;
	struct in6_addr mask;
};

struct dns_server {
	struct event_base *base;
	struct evdns_server_port *server;
	evutil_socket_t server_fd;
	struct timeval ttltv;
};

//TODO: make this thread safe
//TODO: make this server independent?
static struct domainmap *domainmap = NULL;
static struct domainmap *ipv6map = NULL;
static struct domainmap *ipv4map = NULL;
static struct dns_server *server;

//TODO: make this configurable and server independent
static struct v4_range v4range;
static struct v6_range v6range;

//TODO: make this configurable and server independent
#define TTL 60
//This one is the extra time provided after the TTL expires 
#define TTLEXTRA 10

inline static struct domainmap * entry_from_domain (const char *domain) {
	struct domainmap *rv;
	HASH_FIND(hhdom,domainmap,domain,(unsigned)strlen(domain),rv);
	return rv;
}

inline static struct domainmap * entry_from_ipv4 (const struct in_addr *ipv4) {
	struct domainmap *rv;
	HASH_FIND (hhipv4, ipv4map, ipv4, sizeof(struct in_addr), rv);
	return rv;
}

inline static struct domainmap * entry_from_ipv6 (const struct in6_addr *ipv6) {
	struct domainmap *rv;
	HASH_FIND (hhipv6, ipv6map, ipv6, sizeof(struct in6_addr), rv);
	return rv;
}

inline static void generate_random_ip (uint8_t *dst, const uint8_t *ip, const uint8_t *mask, size_t size) {
	size_t i;
	evutil_secure_rng_get_bytes(dst, size);
	for (i = 0; i < size; i++) {
		dst[i] = (ip[i] & mask[i]) | (dst[i] & ~mask[i]);
	}
}

inline static void generate_random_ipv4 (struct in_addr *dst, const struct in_addr *ip, const struct in_addr *mask) {
	generate_random_ip ((uint8_t *)dst, (const uint8_t *)ip, (const uint8_t *)mask, sizeof(struct in_addr));
}

inline static void generate_random_ipv6 (struct in6_addr *dst, const struct in6_addr *ip, const struct in6_addr *mask) {
	generate_random_ip ((uint8_t *)dst, (const uint8_t *)ip, (const uint8_t *)mask, sizeof(struct in6_addr));
}

int addr_to_name (const struct sockaddr_storage *ss, char *dest, size_t dest_len) {
	struct domainmap *result;
	switch (ss->ss_family) {
		case AF_INET6:
			if (!IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)ss)->sin6_addr))) {
				result = entry_from_ipv6(&(((struct sockaddr_in6 *)ss)->sin6_addr));
			} else {
				result = entry_from_ipv4((struct in_addr *)((char *)&(((struct sockaddr_in6 *)ss)->sin6_addr))+12);
			}
			break;
		case AF_INET:
			result = entry_from_ipv4(&(((struct sockaddr_in *)ss)->sin_addr));
			break;
		default:
			return 0;
	}
	if (result == NULL)
		return 0;
	if (strlen(result->domain) > dest_len)
		return 0;
	strcpy(dest,result->domain);
	return 1;
}

static inline int is_v4_empty (struct domainmap *entry) {
	return entry->ipv4.s_addr == INADDR_ANY;
}

static inline int is_v6_empty (struct domainmap *entry) {
	return !memcmp(&(entry->ipv6),&(in6addr_any),sizeof(struct in6_addr));
}

static void clear_entry (evutil_socket_t fd __attribute__((unused)), short what __attribute__((unused)), struct domainmap *entry)
{
	fprintf(stderr,"Removing the entry for %s\n",entry->domain);
	HASH_DELETE(hhdom, domainmap, entry);
	if(entry_from_ipv6(&entry->ipv6))
		HASH_DELETE(hhipv6,ipv6map, entry);
	if(entry_from_ipv4(&entry->ipv4))
		HASH_DELETE(hhipv4, ipv4map, entry);
	if(entry->remove)
		event_free(entry->remove);
	free(entry);
}

static inline void clear_entry_if_empty (struct domainmap *entry)
{
	if (is_v4_empty(entry) && is_v6_empty(entry))
		event_active(entry->remove, EV_TIMEOUT, 0);
}

static void server_callback(struct evdns_server_request *request, struct dns_server *server)
{
	int error=DNS_ERR_NONE;

	if (request->nquestions != 1)
	{
		evdns_server_request_respond(request, DNS_ERR_FORMAT);
		return;
	}
	const struct evdns_server_question *q = request->questions[0];
	int ok=-1;
	size_t namelen = strlen(q->name);
	if (namelen > MAX_DNS_LEN)
	{
		evdns_server_request_respond(request, DNS_ERR_FORMAT);
		return;
	}
	struct domainmap *head = NULL;
	//Find the appropriate entry
	switch (q->type)
	{
//TODO: prefer ipv6, how?
		case EVDNS_TYPE_A:
		case EVDNS_TYPE_AAAA:
			head = entry_from_domain(q->name);
			if (!head)
			{
				head = calloc(1,sizeof(struct domainmap));
				strncpy(head->domain,q->name,MAX_DNS_STR);
				head->ipv6 = in6addr_any;
				head->ipv4.s_addr = INADDR_ANY;
				//TODO: check this isn't null
				head->remove = evtimer_new(server->base, (event_callback_fn) clear_entry, head);
				if (!head->remove) {
					free(head);
					error = DNS_ERR_SERVERFAILED;
					goto done;
				}
				HASH_ADD(hhdom, domainmap, domain[0], strlen(head->domain), head);
			}
			break;
		case EVDNS_TYPE_PTR:
			if ((namelen >= 20 || namelen <= 28) && ! strcmp(q->name+namelen-13,".in-addr.arpa")) {
				int dots = 0;
				int num = 0;
				const char *c = q->name;
				uint8_t ptraddr[4];
				while (dots < 4) {
					if (*c >= '0' && *c <= '9')
						num = num * 10 + *c - '0';
					else if (*c == '.' && num >= 0 && num <= 255) {
						ptraddr[3-dots] = num;
						dots++;
						num = 0;
					} else {
						error = DNS_ERR_NOTEXIST;
						goto done;
					}
					c++;
				}
				if (strcmp(c,"in-addr.arpa")) {
					error = DNS_ERR_NOTEXIST;
					goto done;
				}
				head = entry_from_ipv4((const struct in_addr *)ptraddr);
			} else if(namelen == 72) {
				int dots = 0;
				int num;
				const char *c = q->name;
				uint8_t ptraddr[16];
				while (dots < 16) {
					if (*c >= '0' && *c <= '9')
						num = *c - '0';
					else if (*c >= 'a' && *c <= 'f')
						num = *c - 'a' + 10;
					else {
						error = DNS_ERR_NOTEXIST;
						goto done;
					}
					c++;
					if (*c != '.') {
						error = DNS_ERR_NOTEXIST;
						goto done;
					}
					c++;
					if (*c >= '0' && *c <= '9')
						num += (*c - '0')*16;
					else if (*c >= 'a' && *c <= 'f')
						num += (*c - 'a' + 10)*16;
					else {
						error = DNS_ERR_NOTEXIST;
						goto done;
					}
					c++;
					if (*c == '.') {
						ptraddr[15-dots] = num;
						dots++;
					} else {
						error = DNS_ERR_NOTEXIST;
						goto done;
					}
					c++;
				}
				if (strcmp(c,"ip6.arpa")) {
					error = DNS_ERR_NOTEXIST;
					goto done;
				}
				head = entry_from_ipv6((const struct in6_addr *)ptraddr);
			} else {
				error = DNS_ERR_NOTEXIST;
				goto done;
			}
			break;
		default:
			error = DNS_ERR_NOTEXIST;
			goto done;
	}
	//Craft and send the reply
	struct domainmap *retry = NULL;
	//TODO: make configurable
	int num_attempts = 10;
	//Create a valid random ip
	switch (q->type)
	{
		case EVDNS_TYPE_A:
			if (is_v4_empty(head)) {
				do {
					generate_random_ipv4 (&(head->ipv4), &(v4range.ip), &(v4range.mask));
					retry = entry_from_ipv4(&head->ipv4);
					num_attempts--;
				} while (retry != NULL && num_attempts > 0);
				if (retry != NULL) {
					clear_entry_if_empty(head);
					error = DNS_ERR_SERVERFAILED;
					goto done;
				}
				HASH_ADD(hhipv4, ipv4map, ipv4, sizeof(struct in_addr), head);
			}
			ok = evdns_server_request_add_a_reply(request, q->name, 1, &(head->ipv4), TTL);
			break;
		case EVDNS_TYPE_AAAA:
			if (is_v6_empty(head)) {
				do {
					generate_random_ipv6 (&(head->ipv6), &(v6range.ip), &(v6range.mask));
					retry = entry_from_ipv6(&head->ipv6);
					num_attempts--;
				} while (retry != NULL && num_attempts > 0);
				if (retry != NULL) {
					clear_entry_if_empty(head);
					error = DNS_ERR_SERVERFAILED;
					goto done;
				}
				HASH_ADD(hhipv6, ipv6map, ipv6, sizeof(struct in6_addr), head);
			}
			ok = evdns_server_request_add_aaaa_reply(request, q->name, 1, &(head->ipv6), TTL);
			break;
		case EVDNS_TYPE_PTR: //Look up on the ipv4map and ipv6map
			if (head)
				ok = evdns_server_request_add_ptr_reply(request, NULL, q->name, head->domain, TTL);
			else
				error = DNS_ERR_NOTEXIST;
			goto done;
		default:
			goto done;
			error = DNS_ERR_NOTEXIST;
	}
	done:
	if (ok<0 && error==DNS_ERR_NONE)
		error = DNS_ERR_SERVERFAILED;
	/* Now send the reply. */
	evdns_server_request_respond(request, error);
	//Refresh the TTL countdown
	if (error==DNS_ERR_NONE)
		evtimer_add(head->remove,&server->ttltv);
}

//TODO: allow for clean closing by returning a propper struct
int start_dns_server (struct event_base *base)
{
// 	struct dns_server *server;
	server = malloc(sizeof(struct dns_server));
	server->base=base;
	server->ttltv.tv_sec = TTL + TTLEXTRA;
	server->ttltv.tv_usec = 0;

	struct sockaddr_in6 sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin6_family = AF_INET6;
	sin.sin6_addr = in6addr_any;
	sin.sin6_port = htons(LISTEN_PORT);
	server->server_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (server->server_fd < 0)
		return -1;
	evutil_make_socket_nonblocking(server->server_fd);
	if (bind(server->server_fd, (struct sockaddr*)&sin, sizeof(sin))<0)
		return -2;

	server->server = evdns_add_server_port_with_base(base, server->server_fd, 0, (evdns_request_callback_fn_type) server_callback, server);
	if (server->server == NULL)
		return -3;

	if(evutil_secure_rng_init() < 0)
		return -4;

	//TODO: CIDR support
	inet_pton(AF_INET,"127.0.0.1",&(v4range.ip));
	inet_pton(AF_INET,"255.0.0.0",&(v4range.mask));
	inet_pton(AF_INET6,"1::",&(v6range.ip));
	inet_pton(AF_INET6,"ffff:ffff::",&(v6range.mask));

// 	event_base_dispatch(base);
// 
// 	evdns_close_server_port(server->server);
// 	event_base_free(base);

	return 0;
}
