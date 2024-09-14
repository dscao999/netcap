#ifndef CANCOMM_DSCAO__
#define CANCOMM_DSCAO__
#include <time.h>

#define PACKET_LENGTH	4096
#define ETHERNET	1
#define CANBUS		280

struct cancomm {
	unsigned int ifidx;
	unsigned int iftyp;
	struct timespec tm;
	char buf[];
};
#endif  /* CANCOMM_DSCAO__ */
