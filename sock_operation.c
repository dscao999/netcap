#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include "miscs.h"
#include "sock_operation.h"
#include "cancomm.h"

extern int debug;

int check_sock_mtu(int sockfd)
{
	int usock_mtu, sysret;
	socklen_t sock_len;

	sock_len = sizeof(usock_mtu);
	sysret = getsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
			&usock_mtu, &sock_len);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot get the UNIX socket MTU: %d-%s\n",
				errno, strerror(errno));
		return -errno;
	}
	if (debug)
		printf("UNIX Socket MTU: %d\n", usock_mtu);
	if (unlikely(usock_mtu < 2*(sizeof(struct cancomm)+PACKET_LENGTH))) {
		usock_mtu = sizeof(struct cancomm)+PACKET_LENGTH;
		if (debug)
			printf("UNIX Socket MTU not enough. Set it to: %d\n",
					usock_mtu);
		sysret = setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF,
				&usock_mtu, sizeof(usock_mtu));
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "Cannot set UNIX socket MTU: %d-%s\n",
					errno, strerror(errno));
			return -errno;
		}
		usock_mtu *= 2;
	}
	return usock_mtu;
}
