#ifndef CANCOMM_DSCAO__
#define CANCOMM_DSCAO__
#include <net/if.h>
#include <time.h>

#define PACKET_LENGTH	4000
#define ETHERNET	1
#define CANBUS		280

struct nicport {
	int ifidx;
	int nictyp;
	char ifname[IF_NAMESIZE];
} __attribute__((aligned(4)));

struct caninfo {
	int action;    /* -1 down, 1 up */
	struct nicport nic;
} __attribute__((aligned(4)));

struct cancomm {
	unsigned int ifidx;
	unsigned int iftyp;
	struct timespec tm;
	char buf[] __attribute__((aligned(4)));
};
#endif  /* CANCOMM_DSCAO__ */
