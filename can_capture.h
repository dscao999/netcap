#ifndef CAN_CAPTURE_DSCAO__
#define CAN_CAPTURE_DSCAO__
#include <stdbool.h>
#include <pthread.h>
#include <linux/un.h>
#include <net/if.h>
#include "list_head.h"
#include "cancomm.h"

#define SUN_PATH_LEN	108
#define CAN_TYPE	280
#define DEFAULT_SOCKET_PATH	"/var/tmp/can_capture"

struct can_list {
	struct list_head head;
	pthread_mutex_t mutex;
};

struct flow_statistics {
	unsigned long num_bytes;
	unsigned long num_pkts;
};

struct can_sock {
	pthread_t thid;
	struct list_head lnk;
	const struct sockaddr_un *peer;
	struct flow_statistics st;
	struct nicport nic;
	int u_sock;
	int c_sock;
	bool stop_cap;
};

#endif /* CAN_CAPTURE_DSCAO__ */
