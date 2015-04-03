#ifndef TPROXY_H
#define TPROXY_H
#include <event2/event.h>

int start_tproxy_server (struct event_base *base);
#endif
