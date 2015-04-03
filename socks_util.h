#ifndef SOCKS_UTIL_H
#define SOCKS_UTIL_H
#include <stddef.h>
#include <stdint.h>
#include "socks.h"

static inline size_t socks5_get_request_size (enum socks_addr_types type,
					      uint8_t dns)
{
	switch (type)
	{
		case SOCKS5_ADDR_IPV4: return 10;
		case SOCKS5_ADDR_IPV6: return 22;
		case SOCKS5_ADDR_DNS: return 7+dns;
		default: return 0;
	}
}

static inline size_t socks5_get_reply_size (enum socks_addr_types type,
					    uint8_t dns)
{
	switch (type)
	{
		case SOCKS5_ADDR_IPV4: return 10;
		case SOCKS5_ADDR_IPV6: return 22;
		case SOCKS5_ADDR_DNS: return 7+dns;
		default: return 0;
	}
}

static inline int is_supported_socks5_addr_type (uint8_t type)
{
	switch (type)
	{
		case SOCKS5_ADDR_IPV4: return 1;
		case SOCKS5_ADDR_DNS: return 1;
		case SOCKS5_ADDR_IPV6: return 1;
		default: return 0;
	}
}

static inline int is_supported_socks5_err_type (uint8_t type)
{
	return (type <= SOCKS5_ADDR_UNSUP);
}

static inline int is_supported_socks_cmd_type (uint8_t type)
{
	return (type >= SOCKS_CMD_CONNECT && type <= SOCKS_CMD_UDP);
}

#endif