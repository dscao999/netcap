#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <endian.h>
#include "miscs.h"
#include "cancomm.h"

#define CANBUF_LEN	2000

static const char *default_server = "/var/tmp/can_capture";
static const char *default_client = "/var/tmp/can_receiver";

static int stop_flag = 0;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		stop_flag = 1;
}

static inline void can_packet(struct cancomm *canbuf, int buflen)
{
}

static void ethernet_packet(struct cancomm *canbuf, int buflen)
{
	struct ethhdr *eth;

	eth = (struct ethhdr *)canbuf->buf;
	if (unlikely(buflen < sizeof(struct ethhdr))) {
		fprintf(stderr, "corrupt ethernet packet ignored\n");
		return;
	}
	printf("Etherenet packet type: %d ", be16toh(eth->h_proto));
	printf("Dest: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ",
			eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
			eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("Source: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx ",
			eth->h_source[0], eth->h_source[1], eth->h_source[2],
			eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("Payload Length: %d\n", buflen - (int)sizeof(struct ethhdr));

}

int main(int argc, char *argv[])
{
	int retv, sockfd, sysret, msglen;
	const char *server;
	struct cancomm *canbuf;
	struct sigaction mact;
	struct sockaddr_un skaddr;
	static char client_un_path[96];

	retv = 0;
	server = default_server;
	if (argc > 1)
		server = argv[1];
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
	sprintf(client_un_path, "%s-%d", default_client, (int)getpid());
	memset(&skaddr, 0, sizeof(skaddr));
	skaddr.sun_family = AF_UNIX;
	strcpy(skaddr.sun_path, client_un_path);
	sysret = bind(sockfd, (struct sockaddr *)&skaddr, sizeof(skaddr));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Unable to bind to %s: %d-%s\n", default_client,
				errno, strerror(errno));
		goto exit_10;
	}
	strcpy(skaddr.sun_path, server);
	sysret = connect(sockfd, (struct sockaddr *)&skaddr, sizeof(skaddr));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot connect to server socket with path %s: %d-%s\n",
				server, errno, strerror(errno));
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
	unlink(client_un_path);
exit_10:
	close(sockfd);
	return retv;
}
