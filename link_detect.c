#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <linux/un.h>
#include <sys/socket.h>
#include "miscs.h"
#include "list_head.h"
#include "can_capture.h"
#include "link_watch.h"
#include "cancomm.h"

#define MSGBUF_LEN	2000

static int stop_flag = 0;
static int echo_st = 0;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		stop_flag = 1;
	else if (sig == SIGUSR2)
		echo_st = 1;
}

static inline const char *getlstr(const struct option *lopts, int c)
{
	const struct option *opt = lopts;

	for (opt = lopts; opt->name; opt++)
		if (opt->val == c)
			return opt->name;
	return "unknown";
}

static void parse_options(int argc, char *argv[], struct cmdl_options *cmdargs)
{
	int fin = 0, c;
	char *path, *r_path;
	extern char *optarg;
	extern int opterr, optopt;
	static const struct option lopts[] = {
		{
			.name = "debug",
			.has_arg = 0,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "socket",
			.has_arg = 1,
			.flag = NULL,
			.val = 'p'
		},
		{}
	};
	static const char *opts = ":dp:";

	r_path = malloc(128);
	if (unlikely(!r_path)) {
		fprintf(stderr, "Out of Memory!\n");
		exit(ENOMEM);
	}
	memset(r_path, 0, 128);
	cmdargs->debug = 0;
	cmdargs->sun_path = DEFAULT_SOCKET_PATH;
	opterr = 0;
	do {
		optopt = 0;
		c = getopt_long(argc, argv, opts, lopts, NULL);
		switch(c) {
		case -1:
			fin = 1;
			break;
		case '?':
			if (optopt)
				fprintf(stderr, "Unknown option: -%c\n", (char)optopt);
			else
				fprintf(stderr, "Unknown option: --%s\n", argv[optind-1]);
			break;
		case ':':
			fprintf(stderr, "Missing arguments for -%c/--%s\n",
					(char)optopt, getlstr(lopts, optopt));
			break;
		case 'd':
			cmdargs->debug += 1;
			break;
		case 'p':
			if (unlikely(strlen(optarg) > 64)) {
				fprintf(stderr, "Sock Path Too Long: %s ignored\n",
						optarg);
				break;
			}
			path = realpath(r_path, optarg);
			if (unlikely(!path && errno != ENOENT)) {
				fprintf(stderr, "Invalid socket path %s ignored: %s\n",
						optarg, strerror(errno));
				break;
			}
			cmdargs->sun_path = optarg;
			break;
		default:
			fprintf(stderr, "Logic Error in parse options\n");
			break;
		}
	} while (fin == 0);
	free(r_path);
}

static void send_can(const struct cancomm *canmsg, int msglen, struct can_list *cans)
{
	struct can_sock *node;
	int numbytes;
	int sock;

	sock = -1;
	pthread_mutex_lock(&cans->mutex);
	list_for_each_entry(node, &cans->head, lnk) {
		if (node->nic.ifidx == canmsg->ifidx)
			break;
	}
	if (likely(&node->lnk != &cans->head))
		sock = node->c_sock;
	pthread_mutex_unlock(&cans->mutex);
	if (sock != -1) {
		numbytes = send(sock, canmsg->buf, msglen, 0);
		if (unlikely(numbytes == -1)) {
			fprintf(stderr, "Cannot send to CAN %d %s: %d-%s\n",
					node->nic.ifidx, node->nic.ifname,
					errno, strerror(errno));
		}
	} else
		fprintf(stderr, "Warning: no such CAN whith index of %d\n", canmsg->ifidx);
}

static struct can_list cans = {
	.head = LIST_HEAD_INIT(cans.head),
	.mutex = PTHREAD_MUTEX_INITIALIZER
};

static struct sockaddr_un peer;
static struct sockaddr_un usock_me;

static void echo_statistics(struct can_list *cans)
{
	struct can_sock *node;
	unsigned long num_bytes, num_pkts;

	num_bytes = 0;
	num_pkts = 0;
	pthread_mutex_lock(&cans->mutex);
	list_for_each_entry(node, &cans->head, lnk) {
		printf("Statistics for %s - %d:\n", node->nic.ifname, node->nic.ifidx);
		printf("\tNumber of bytes: %lu, Number of packets: %lu\n",
				node->st.num_bytes, node->st.num_pkts);
		num_bytes += node->st.num_bytes;
		num_pkts += node->st.num_pkts;
	}
	pthread_mutex_unlock(&cans->mutex);
	printf("Total %lu number of bytes, %lu number of packets\n",
			num_bytes, num_pkts);
}

int main(int argc, char *argv[])
{
	int retv = 0, u_sock, sysret, nums;
	struct watch_param *wparam;
	struct sigaction mact;
	struct can_sock *node;
	socklen_t peer_len;
	struct cancomm *canmsg;
	struct comm_info cinfo;
	struct sockaddr_un *who;
	static struct cmdl_options opts;

	parse_options(argc, argv, &opts);
	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (unlikely(sigaction(SIGINT, &mact, NULL) == -1))
		fprintf(stderr, "Cannot install signal handler for SIGINT\n");
	if (unlikely(sigaction(SIGTERM, &mact, NULL) == -1))
		fprintf(stderr, "Cannot install signal handler for SIGTERM\n");
	if (unlikely(sigaction(SIGUSR2, &mact, NULL) == -1))
		fprintf(stderr, "Cannot install signal handler for SIGUSR2\n");

	usock_me.sun_family = AF_UNIX;
	strcpy(usock_me.sun_path, opts.sun_path);
	u_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (unlikely(u_sock == -1)) {
		fprintf(stderr, "Cannot create UNIX socket: %d-%s\n",
				errno, strerror(errno));
		return errno;
	}
	sysret = bind(u_sock, (const struct sockaddr *)&usock_me, sizeof(usock_me));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot bind UNIX socket to %s: %s\n",
				usock_me.sun_path, strerror(errno));
		fprintf(stderr, "Another instance is already running?\n");
		goto exit_10;
	} else
		printf("Listening on socket %s\n", usock_me.sun_path);
	canmsg = malloc(sizeof(struct cancomm)+MSGBUF_LEN);
	if (unlikely(!canmsg)) {
		fprintf(stderr, "Out of Memory!\n");
		retv = ENOMEM;
		goto exit_15;
	}

	cinfo.opts = &opts;
	cinfo.u_sock = u_sock;
	cinfo.stop_flag = &stop_flag;
	cinfo.peer = &peer;
	wparam = link_watch_start(&cans, &cinfo);
	if (unlikely(!wparam)) {
	       	retv = ENOMEM;
		goto exit_20;
	}
	retv = ((unsigned long)wparam) >> 16;
	if (unlikely(retv == 0)) {
		fprintf(stderr, "Cannot start the watching thread\n");
		retv = ((unsigned long)wparam) & 0x0ff;
		goto exit_20;
	}
	retv = cansock_list_build(&cans, &cinfo);
	if (unlikely(retv != 0)) {
		fprintf(stderr, "Unable to build CAN port list\n");
		WRITE_ONCE(stop_flag, 1);
		goto wait_for_watch;
	}
	if (opts.debug) {
		printf("CAN watched:\n");
		pthread_mutex_lock(&cans.mutex);
		list_for_each_entry(node, &cans.head, lnk)
			printf("\t%s - idx: %d\n", node->nic.ifname, node->nic.ifidx);
		pthread_mutex_unlock(&cans.mutex);
	}
	who = &usock_me;
	WRITE_ONCE(peer.sun_family, 0);
	do {
		peer_len = sizeof(struct sockaddr_un);
		nums = recvfrom(u_sock, (char *)canmsg,
				MSGBUF_LEN+sizeof(struct cancomm), 0,
				(struct sockaddr *)who, &peer_len);
		if (unlikely(READ_ONCE(echo_st) == 1)) {
			WRITE_ONCE(echo_st, 0);
			echo_statistics(&cans);
		}
		if (unlikely(nums == -1)) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "recvfrom failed: %d-%s. " \
					"Cannot receive messages\n",
					errno, strerror(errno));
			WRITE_ONCE(stop_flag, 1);
			continue;
		}
		if (unlikely(nums < sizeof(struct cancomm))) {
			fprintf(stderr, "Corrupt Message Received. Ignored!\n");
			continue;
		}
		if (canmsg->ifidx != 0) {
			send_can(canmsg, nums-sizeof(struct cancomm), &cans);
			continue;
		}
		WRITE_ONCE(peer.sun_family, 0);
		memcpy(peer.sun_path, who->sun_path, sizeof(peer.sun_path));
		WRITE_ONCE(peer.sun_family, AF_UNIX);
	} while (READ_ONCE(stop_flag) == 0);

wait_for_watch:
	if (link_watch_stop(wparam) != 0 && opts.debug)
		printf("Link Up/Down detected.\n");
	canlist_free(&cans);

	printf("Exiting...\n");

exit_20:
	free(canmsg);
exit_15:
	unlink(usock_me.sun_path);
exit_10:
	close(u_sock);
	return retv;
}
