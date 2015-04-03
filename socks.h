#ifndef SOCKS_H
#define SOCKS_H
#include <stdint.h>

#define MAX_SOCKS_HOSTNAME_SIZE 255
#define MAX_SOCKS5_REQUEST_SIZE 262
#define MIN_SOCKS5_REQUEST_SIZE 10
#define MAX_SOCKS5_REPLY_SIZE 262
#define MIN_SOCKS5_REPLY_SIZE 10


struct socks_dns
{
	uint8_t size;
	char value[MAX_SOCKS_HOSTNAME_SIZE];
};

enum socks_auth_methods
{
	SOCKS5_AUTH_NONE = 0, //No authentication, skip to next step
	SOCKS5_AUTH_GSSAPI = 1, //GSSAPI authentication
	SOCKS5_AUTH_USERPASSWD = 2, //Username and password
	SOCKS5_AUTH_UNACCEPTABLE = 0xff //No acceptable method found
};

enum socks_addr_types
{
	SOCKS5_ADDR_IPV4 = 1, //IPv4 address (4 octets)
	SOCKS5_ADDR_DNS = 3, // DNS name (up to 255 octets)
	SOCKS5_ADDR_IPV6 = 4 //IPV6 address (16 octets)
};

enum socks_err_types
{
	SOCKS5_OK = 0, // No error for SOCKS5
	SOCKS5_GEN_FAIL = 1, // General server failure
	SOCKS5_RULE_DENIED = 2, // Connection disallowed by ruleset
	SOCKS5_NET_UNREACH = 3, // Network unreachable
	SOCKS5_HOST_UNREACH = 4, // Host unreachable
	SOCKS5_CONN_REFUSED = 5, // Connection refused by the peer
	SOCKS5_TTL_EXPIRED = 6, // TTL Expired
	SOCKS5_CMD_UNSUP = 7, // Command unsuported
	SOCKS5_ADDR_UNSUP = 8, // Address type unsuported
	SOCKS4_OK = 90, // No error for SOCKS4
	SOCKS4_FAIL = 91, // Failed establishing connecting or not allowed
	SOCKS4_IDENTD_MISSING = 92, // Couldn't connect to the identd server
	SOCKS4_IDENTD_DIFFER = 93, // The ID reported by the application and by identd differ
	//These aren't defined by the protocol
	SOCKS5_AUTH_UNSUP, // Authentication type unsuported
	SOCKS5_NOT_SOCKS5 // The server isn't SOCKS5
};

enum socks_cmd_types
{
	SOCKS_CMD_CONNECT = 1, // TCP Connect
	SOCKS_CMD_BIND = 2, // TCP Bind
	SOCKS_CMD_UDP = 3 // UDP associate
};

enum socks_versions
{
	SOCKS4 = 4, // SOCKS4
	SOCKS5 = 5 // SOCKS5
};

union socks_address
{
	//TODO: change to the appropriate types
	uint32_t ip;
	struct socks_dns dns;
	uint8_t ipv6[16];
};

#endif