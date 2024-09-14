#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <linux/if_ether.h>
#include <linux/can.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <endian.h>
#include "miscs.h"
#include "cancomm.h"

#define CANBUF_LEN	3000

static const char *default_dir = "/var/tmp/cancap";
static const char *default_server = "can_capture";
static const char *default_client = "can_receiver";

static int stop_flag = 0;
static struct timespec epcho_start;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		stop_flag = 1;
}

static long usec_timediff(const struct timespec *t0, const struct timespec *t1)
{
	long tv_sec, tv_nsec;

	tv_sec = 0;
	tv_nsec = t1->tv_nsec - t0->tv_nsec;
	if (tv_nsec < 0) {
		tv_nsec += 1000000000l;
		tv_sec -= 1;
	}
	tv_sec += (t1->tv_sec - t0->tv_sec);
	return (tv_sec * 1000000) + (tv_nsec / 1000);
}

static inline void can_packet(struct cancomm *canbuf, int msglen)
{
	struct can_frame *frame;
	long stamp;
	unsigned int canid;
	int i;

	stamp = usec_timediff(&epcho_start, &canbuf->tm);
	printf("%8ld.%06ld ", (stamp/1000000), (stamp%1000000));
	frame = (struct can_frame *)canbuf->buf;
	if (unlikely((frame->can_id & CAN_ERR_FLAG) != 0)) {
		fprintf(stderr, "An Error CAN frame received\n");
		return;
	}
	if ((frame->can_id & CAN_EFF_FLAG) != 0)
		canid = (frame->can_id & CAN_EFF_MASK);
	else
		canid = (frame->can_id & CAN_SFF_MASK);
	if (unlikely((frame->can_id & CAN_RTR_FLAG) != 0)) {
		printf("Remote Request of CAN ID: %8X\n", canid);
	} else {
		printf("CAN ID: %8X, Payload Len: %d Data:", canid, frame->len);
		for (i = 0; i < frame->len; i++)
			printf(" %02X", frame->data[i]);
		printf("\n");
	}
}

static void ethernet_packet(struct cancomm *canbuf, int msglen)
{
	struct ethhdr *eth;
	long stamp;

	eth = (struct ethhdr *)canbuf->buf;
	if (unlikely(msglen < sizeof(struct ethhdr))) {
		fprintf(stderr, "corrupt ethernet packet ignored\n");
		return;
	}
	stamp = usec_timediff(&epcho_start, &canbuf->tm);
	printf("%8ld.%06ld ", (stamp/1000000), (stamp%1000000));
	printf("Etherenet: %04hX ", be16toh(eth->h_proto));
	printf("Dest: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ",
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
			eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("Source: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ",
			eth->h_source[0], eth->h_source[1], eth->h_source[2],
			eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("Payload Length: %d\n", msglen - (int)sizeof(struct ethhdr));
}

struct cmdl_options {
	char sock_dir[76];
	char sock_svr[32];
	char sock_cli[32];
};

static inline const char *getlstr(const struct option *lopts, int c)
{
	const struct option *opt;

	for (opt  = lopts; opt->name; opt++)
		if (opt->val == c)
			return opt->name;
	return "unknown";
}

static void parse_options(int argc, char *argv[], struct cmdl_options *cmdl)
{
	int fin = 0, c;
	extern char *optarg;
	extern int opterr, optopt;
	static const struct option lopts[] = {
		{
			.name = "sock-dir",
			.has_arg = 1,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "sock-server",
			.has_arg = 1,
			.flag = NULL,
			.val = 's'
		},
		{
			.name = "sock-client",
			.has_arg = 1,
			.flag = NULL,
			.val = 'c'
		},
		{}
	};
	static const char *opts = ":d:s:c:";

	strcpy(cmdl->sock_dir, default_dir);
	strcpy(cmdl->sock_svr, default_server);
	strcpy(cmdl->sock_cli, default_client);
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
		       strcpy(cmdl->sock_dir, optarg);
		       break;
		case 's':
		       strcpy(cmdl->sock_svr, optarg);
		       break;
		case 'c':
		       strcpy(cmdl->sock_cli, optarg);
		       break;
		default:
		       fprintf(stderr, "Logic error in parsing options\n");
		       break;
		}
	} while (fin == 0);
}

int main(int argc, char *argv[])
{
	int retv, sockfd, sysret, msglen, dirlen;
	struct cancomm *canbuf;
	struct sigaction mact;
	struct sockaddr_un skaddr;
	struct stat fst;
	time_t tm;
	static char un_path[128];
	static struct cmdl_options opts;

	retv = 0;
	parse_options(argc, argv, &opts);
	dirlen = sprintf(un_path, "%s", opts.sock_dir);
	sysret = stat(un_path, &fst);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Directory %s is unusable: %d-%s\n",
				opts.sock_dir, errno, strerror(errno));
		return errno;
	}

	memset(&mact, 0, sizeof(mact));
	mact.sa_handler = sig_handler;
	if (unlikely(sigaction(SIGINT, &mact, NULL) == -1))
		fprintf(stderr, "Cannot install handler for SIGINT: %d-%s\n",
				errno, strerror(errno));
	if (unlikely(sigaction(SIGTERM, &mact, NULL) == -1))
		fprintf(stderr, "Cannot install handler for SIGINT: %d-%s\n",
				errno, strerror(errno));

	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (unlikely(sockfd == -1)) {
		fprintf(stderr, "Unable to create UNIX socket: %d-%s\n",
				errno, strerror(errno));
		return errno;
	}
	sprintf(un_path+dirlen, "/%s-%d", opts.sock_cli, (int)getpid());
	memset(&skaddr, 0, sizeof(skaddr));
	skaddr.sun_family = AF_UNIX;
	strcpy(skaddr.sun_path, un_path);
	sysret = bind(sockfd, (struct sockaddr *)&skaddr, sizeof(skaddr));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Unable to bind to %s: %d-%s\n", default_client,
				errno, strerror(errno));
		goto exit_10;
	}
	sprintf(un_path+dirlen, "/%s", opts.sock_svr);
	strcpy(skaddr.sun_path, un_path);
	sysret = connect(sockfd, (struct sockaddr *)&skaddr, sizeof(skaddr));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot connect to server socket with path %s: %d-%s\n",
				un_path, errno, strerror(errno));
		retv = errno;
		goto exit_20;
	}
	canbuf = (struct cancomm *)malloc(sizeof(struct cancomm)+CANBUF_LEN);
	if (unlikely(!canbuf)) {
		retv = ENOMEM;
		fprintf(stderr, "Out of Memory!\n");
		goto exit_20;
	}
	canbuf->ifidx = 0;
	canbuf->iftyp = 0;
	msglen = sizeof(struct cancomm);
	sysret = send(sockfd, (char *)canbuf, msglen, 0);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot send to capture server: %d-%s\n",
				errno, strerror(errno));
		retv = errno;
		goto exit_30;
	}
	clock_gettime(CLOCK_MONOTONIC_COARSE, &epcho_start);
	tm = time(NULL);
	printf("Begin at %s", ctime(&tm));
	do {
		sysret = recv(sockfd, (char *)canbuf, CANBUF_LEN+sizeof(struct cancomm), 0);
		if (unlikely(sysret == -1)) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "Cannot receive from UNIX socket: %d-%s, Aborting\n",
					errno, strerror(errno));
			break;
		} else if (unlikely(sysret < sizeof(struct cancomm)))
			assert(0);
		msglen = sysret - sizeof(struct cancomm);
		if (canbuf->iftyp == ETHERNET)
			ethernet_packet(canbuf, msglen);
		else if (canbuf->iftyp == CANBUS)
			can_packet(canbuf, msglen);
		else 
			fprintf(stderr, "Unknown NIC type: %u ignored\n", canbuf->iftyp);

	} while (READ_ONCE(stop_flag) == 0);
	canbuf->ifidx = 0;
	canbuf->iftyp = 1;
	msglen = sizeof(struct cancomm);
	sysret = send(sockfd, (char *)canbuf, msglen, 0);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot send to capture server: %d-%s\n",
				errno, strerror(errno));
		retv = errno;
	}
	printf("Exiting...\n");

exit_30:
	free(canbuf);
exit_20:
	sprintf(un_path+dirlen, "/%s-%d", opts.sock_cli, (int)getpid());
	unlink(un_path);
exit_10:
	close(sockfd);
	return retv;
}
