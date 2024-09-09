#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "miscs.h"
#include "cancomm.h"

#define CANBUF_LEN	2000

static const char *default_server = "/var/tmp/can_capture";

int main(int argc, char *argv[])
{
	int retv, sockfd, sysret;
	const char *server;
	struct cancomm *canbuf;
	static sockaddr_un svraddr;

	retv = 0;
	server = default_server;
	if (argc > 1)
		server = argv[1];
	sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (unlikely(sockfd == -1)) {
		fprintf(stderr, "Unable to create UNIX socket: %d-%s\n",
				errno, strerror(errno));
		return errno;
	}
	memset(&svraddr, 0, sizeof(svraddr));
	svraddr.sun_family = AF_UNIX;
	strcpy(svraddr.sun_path, server);
	sysret = connect(sockfd, (sockaddr *)&svraddr, sizeof(svraddr));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot connect to server socket: %d-%s\n",
				errno, strerror(errno));
		retv = errno;
		goto exit_10;
	}
	canbuf = (struct cancomm *)malloc(sizeof(struct cancomm)+CANBUF_LEN);
	if (unlikely(!canbuf)) {
		retv = ENOMEM;
		fprintf(stderr, "Out of Memory!\n");
		goto exit_10;
	}
	canbuf->ifidx = 0;
	canbuf->iftyp = 0;
	msglen = sizeof(struct cancomm);
	sysret = send(sockfd, (char *)canbuf, msglen, 0);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot send to capture server: %d-%s\n",
				errno, strerror(errno));
		retv = errno;
		goto exit_20;
	}
	do {
	} while (READ_ONCE(stop_flag) == 0);

exit_20:
	free(canbuf);
exit_10:
	close(sockfd);
	return retv;
}
