#ifndef LINK_WATCH_DSCAO__
#define LINK_WATCH_DSCAO__
#include <linux/un.h>
#include "can_capture.h"

struct cmdl_options {
	int debug;
	const char *sun_path;
};

struct comm_info {
	const struct cmdl_options *opts;
	int *stop_flag;
	const struct sockaddr_un *peer;
	int u_sock;
};

struct watch_param {
	pthread_t thid;
	struct can_list *cans;
	int *stop_flag;
	const struct sockaddr_un *peer;
	int u_sock;
	unsigned short inc;
	unsigned short dec;
	unsigned short debug;
	unsigned short error;
};

struct watch_param *link_watch_start(struct can_list *cans,
		struct comm_info *info);
int link_watch_stop(struct watch_param *wparam);

void canlist_free(struct can_list *cans);

int cansock_list_build(struct can_list *cans, struct comm_info *info);

#endif  /* LINK_WATCH_DSCAO__ */
