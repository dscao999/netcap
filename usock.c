#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/un.h>

#define unlikely __builtin_expect((x), 0)
#define CAN_DATALEN	8
#define READ_ONCE(x)	(*((volatile int *)&x))

static int stop_flag = 0;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		stop_flag = 0;
}

struct can_frame {
	unsigned int id;
	unsigned int extended:1;
	unsigned int remote:1;
	unsigned int dlc_len:4;
	unsigned char data[CAN_DATALEN];
};

struct can_options {
	const char *name;
	unsigned int seqno;
	unsigned int bitrate;
	unsigned int mask;
	unsigned int filter;
};

struct cmdl_options {
	int numcans;
	struct can_options canopts[];
};

static int parse_options(struct cmdl_options *opts, int argc, char *argv[])
{
}

int main(int argc, char *argv[])
{
	int sock, retv = 0;
	struct sockaddr_un unaddr;

	unaddr.sun_family = AF_UNIX;
	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (unlikely(sock == -1)) {
		fprintf(stderr, "Cannot open Unix Socket: %s\n", strerror(errno));
		return errno;
	}

	return retv;
}
