#ifndef CANCOMM_DSCAO__
#define CANCOMM_DSCAO__

#define ETHERNET	1
#define CANBUS		280

struct cancomm {
	unsigned int ifidx;
	unsigned int iftyp;
	char buf[];
};
#endif  /* CANCOMM_DSCAO__ */
