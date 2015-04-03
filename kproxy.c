/** Kproxy is a C program intended to do proxying stuff*/
#include <event2/event.h>
// #include <stdio.h>
#include "dns.h"
#include "tproxy.h"

int main(int c, char **v)
{
	struct event_base *base;

	base = event_base_new();
	if (!base)
		return 1; /*XXXerr*/

	setvbuf(stdout, NULL, _IONBF, 0);

	if (start_dns_server (base) < 0 )
		return 3;

	if (start_tproxy_server (base) < 0 )
		return 2;

	event_base_dispatch(base);
	return 0;
}
