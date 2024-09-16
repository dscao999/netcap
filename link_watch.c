#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <dirent.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/can.h>
#include "list_head.h"
#include "miscs.h"
#include "can_capture.h"
#include "link_watch.h"
#include "cancomm.h"

static const char SYS_NET_DIR[] = "/sys/class/net/";

static void *can_capture(void *arg);

static inline void parse_rtattr(struct rtattr *tb[], int max,
		struct rtattr *rta, int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta,len);
	}
}

static int parse_nlmsg(struct nlmsghdr *nlmsg, struct nicport *nic)
{
	struct ifinfomsg *ifi;
	const char *link_name;
	int updown = 0, rtalen;
	static struct rtattr *tb[IFLA_MAX+1];
	static const char *default_ifname = "none";

	if (nlmsg->nlmsg_type != RTM_DELLINK &&
			nlmsg->nlmsg_type != RTM_NEWLINK)
		return updown;
	ifi = NLMSG_DATA(nlmsg);
	if (ifi->ifi_type != ETHERNET && ifi->ifi_type != CANBUS)
		return updown;
	nic->nictyp = ifi->ifi_type;
	strcpy(nic->ifname, default_ifname);
	nic->ifidx = ifi->ifi_index;
	rtalen = nlmsg->nlmsg_len - NLMSG_HDRLEN -
			NLMSG_ALIGN(sizeof(struct ifinfomsg));
	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), rtalen);
	if (tb[IFLA_IFNAME]) {
		link_name = (char*)RTA_DATA(tb[IFLA_IFNAME]);
		strcpy(nic->ifname, link_name);
	}
	if ((ifi->ifi_flags & IFF_UP))
		updown = 1;
	else
		updown = -1;

	return updown;
}

static int insert_node(struct can_sock *cansock, struct can_list *cans)
{
	int retv = 1, sysret;
	struct can_sock *node;

	pthread_mutex_lock(&cans->mutex);
	list_for_each_entry(node, &cans->head, lnk) {
		if (node->nic.ifidx == cansock->nic.ifidx)
			break;
	};
	if (&node->lnk == &cans->head) {
		cansock->stop_cap = false;
		sysret = pthread_create(&cansock->thid, NULL, can_capture, cansock);
		if (unlikely(sysret)) {
			retv = -sysret;
			fprintf(stderr, "Unable to create CAN capturing thread: %d-%s\n",
					sysret, strerror(sysret));
		} else {
			list_add(&cansock->lnk, &cans->head);
			retv = 0;
		}
	}
	pthread_mutex_unlock(&cans->mutex);
	return retv;
}

static int link_up(struct watch_param *wparam, const struct nicport *nic)
{
	int inserted;
	struct can_list *cans = wparam->cans;
	struct can_sock *nnode;

	inserted = 0;
	nnode = malloc(sizeof(struct can_sock));
	if (unlikely(!nnode)) {
		fprintf(stderr, "Out of Memory!\n");
		inserted = -ENOMEM;
		return inserted;
	}
	INIT_LIST_HEAD(&nnode->lnk);
	nnode->nic.ifidx = nic->ifidx;
	nnode->nic.nictyp = nic->nictyp;
	strcpy(nnode->nic.ifname, nic->ifname);
	nnode->u_sock = wparam->u_sock;
	nnode->peer = wparam->peer;

	printf("Link: %s Index: %d up\n", nnode->nic.ifname, nnode->nic.ifidx);
	wparam->inc += 1;
	inserted = insert_node(nnode, cans);
	if (inserted != 0) {
		if (inserted < 0)
			inserted = -inserted;
		else
			inserted = 0;
		free(nnode);
	}
	return inserted;
}

static void del_node(struct can_list *cans, int if_index)
{
	struct can_sock *node, *node_s;
	bool deleted = false;
	int sysret;

	pthread_mutex_lock(&cans->mutex);
	list_for_each_entry_safe(node, node_s, &cans->head, lnk) {
		if (node->nic.ifidx != if_index)
			continue;
		list_del(&node->lnk, &cans->head);
		deleted = true;
		break;
	}
	pthread_mutex_unlock(&cans->mutex);
	if (deleted) {
		node->stop_cap = true;
		sysret = pthread_join(node->thid, NULL);
		if (unlikely(sysret))
			fprintf(stderr, "Wait for thread failed: %d-%s\n",
					sysret, strerror(sysret));
		free(node);
	}
}

static void link_down(struct watch_param *wparam, int if_index)
{
	struct can_list *cans = wparam->cans;

	printf("Link with Index: %d down\n", if_index);
	wparam->dec += 1;
	del_node(cans, if_index);
}

#define NLMSG_BUFLEN	8192
#define IFNAME_LEN	64

static void *watch_entry(void *arg)
{
	struct watch_param *param = arg;
	int sockfd, sysret, retv;
	struct sockaddr_nl sa;
	struct msghdr msg;
	struct iovec iov;
	struct nlmsghdr *nlmsg;
	int msglen, datlen, status, numbytes;
	struct pollfd pfd;
	char *msgbuf;
	struct nicport nic;

	msgbuf = malloc(NLMSG_BUFLEN);
	if (unlikely(msgbuf == NULL)) {
		fprintf(stderr, "Out of Memory!\n");
		param->error = ENOMEM;
		return arg;
	}
	memset(msgbuf, 0, NLMSG_BUFLEN);
	iov.iov_base = msgbuf;
	iov.iov_len = NLMSG_BUFLEN;
	sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
	if (unlikely(sockfd == -1)) {
		fprintf(stderr, "Cannot create a socket: %d, %s\n",
			       errno, strerror(errno));
		param->error = errno;
		goto exit_10;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_LINK;
	sa.nl_pid = getpid();
	sysret = bind(sockfd, (struct sockaddr *)&sa, sizeof(sa));
	if (unlikely(sysret == -1)) {
		param->error = errno;
		fprintf(stderr, "Cannot listen for link events: %d, %s\n",
				errno, strerror(errno));
		goto exit_20;
	}
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	pfd.fd = sockfd;
	pfd.events = POLLIN;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 200);
		if (sysret == 0)
			continue;
		if (unlikely(sysret == -1)) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll failed: %d, %s\n",
					errno, strerror(errno));
			param->error = errno;
			goto exit_20;
		}
		if (unlikely((pfd.revents & POLLIN) == 0))
			fprintf(stderr, "Socket Error in function: %s at line" \
					" %d file %s\n",
					__func__, __LINE__, __FILE__);
		numbytes = recvmsg(sockfd, &msg, 0);
		if (unlikely(numbytes == -1)) {
			fprintf(stderr, "recvmsg failed: %d, %s\n",
					errno, strerror(errno));
			param->error = errno;
			goto exit_20;
		}
		nlmsg = (struct nlmsghdr *)msgbuf;
		while (NLMSG_OK(nlmsg, numbytes)) {
			msglen = nlmsg->nlmsg_len;
			datlen = msglen - sizeof(*nlmsg);
			if (numbytes < msglen || datlen < 0) {
				fprintf(stderr, "Corrupted Message Ignored\n");
				break;
			}
			retv = parse_nlmsg(nlmsg, &nic);
			if (retv == 1) {
				status = link_up(param, &nic);
				if (status)
					fprintf(stderr, "Cannot Add New Link " \
							" %s to capture\n",
							nic.ifname);
			} else if (retv == -1)
				link_down(param, nic.ifidx);
			nlmsg = NLMSG_NEXT(nlmsg, numbytes);
		}
	} while (READ_ONCE(*param->stop_flag) == 0);

exit_20:
	close(sockfd);
exit_10:
	free(msgbuf);
	return arg;
}

struct watch_param *link_watch_start(struct can_list *cans,
		struct comm_info *info)
{
	struct watch_param *param;
	int sysret;

	param = malloc(sizeof(struct watch_param));
	if (unlikely(!param)) {
		fprintf(stderr, "Out of Memory!\n");
		return NULL;
	}
	param->peer = info->peer;
	param->cans = cans;
	param->u_sock = info->u_sock;
	param->inc = 0;
	param->dec = 0;
	param->debug = info->opts->debug;
	param->error = 0;
	param->stop_flag = info->stop_flag;
	sysret = pthread_create(&param->thid, NULL, watch_entry, param);
	if (unlikely(sysret)) {
		fprintf(stderr, "pthread_create failed: %d, %s\n",
				sysret, strerror(sysret));
		free(param);
		param = (void *)(long)sysret;
	}
	return param;
}

int link_watch_stop(struct watch_param *wparam)
{
	int count, sysret;
	struct watch_param *retparam;

	sysret = pthread_join(wparam->thid, (void **)&retparam);
	if (unlikely(sysret))
		fprintf(stderr, "Wait for thread failed: %d-%s\n", sysret,
				strerror(sysret));
	count = wparam->inc + wparam->dec;
	free(wparam);
	return count;
}

void canlist_free(struct can_list *cans)
{
	struct can_sock *node, *node_s;
	int sysret;

	pthread_mutex_lock(&cans->mutex);
	list_for_each_entry_safe(node, node_s, &cans->head, lnk) {
		list_del(&node->lnk, &cans->head);
		node->stop_cap = true;
		sysret = pthread_join(node->thid, NULL);
		if (unlikely(sysret))
			fprintf(stderr, "Wait for thread failed: %d-%s\n",
					sysret, strerror(sysret));
		free(node);
	}
	pthread_mutex_unlock(&cans->mutex);
}

int cansock_list_build(struct can_list *cans, struct comm_info *info)
{
	int sysret, link_type, link_idx;
	DIR *netdir;
	struct dirent *link_entry;
	char *pathbuf;
	int pos, len;
	FILE *fin;
	struct can_sock *cansock;
	int retv = 0, link_flag;

	netdir = opendir(SYS_NET_DIR);
	if (unlikely(netdir == NULL)) {
		fprintf(stderr, "opendir \"%s\" failed: %d, %s\n",
				SYS_NET_DIR, errno, strerror(errno));
		return errno;
	}
	pathbuf = malloc(512);
	if (unlikely(pathbuf == NULL)) {
		fprintf(stderr, "Out of Memory!\n");
		retv = ENOMEM;
		goto exit_10;
	}
	strcpy(pathbuf, SYS_NET_DIR);
	pos = strlen(pathbuf);
	errno = 0;
	link_entry = readdir(netdir);
	while (link_entry) {
		if (link_entry->d_name[0] == '.')
			goto loop;
		len = pos;
		len += sprintf(pathbuf+pos, "%s/", link_entry->d_name);
		strcpy(pathbuf+len, "type");
		fin = fopen(pathbuf, "r");
		if (unlikely(fin == NULL)) {
			fprintf(stderr, "Cannot read file %s: %d, %s\n",
					pathbuf, errno, strerror(errno));
			goto loop;
		}
		link_type = -1;
		sysret = fscanf(fin, "%d", &link_type);
		fclose(fin);
		if (sysret != 1) {
			fprintf(stderr, "Cannot read link type: %s\n",
					pathbuf);
			goto loop;
		}
		if (link_type != ETHERNET && link_type != CANBUS)
			goto loop;

		strcpy(pathbuf+len, "flags");
		fin = fopen(pathbuf, "r");
		if (unlikely(!fin)) {
			fprintf(stderr, "Cannot read file %s: %d, %s\n",
					pathbuf, errno, strerror(errno));
			goto loop;
		}
		link_flag = 0;
		sysret = fscanf(fin, "%x", &link_flag);
		fclose(fin);
		if (sysret != 1) {
			fprintf(stderr, "Cannot read link flags: %s\n",
					pathbuf);
			goto loop;
		}
		if ((link_flag & IFF_UP) == 0)
			goto loop;

		strcpy(pathbuf+len, "ifindex");
		fin = fopen(pathbuf, "r");
		if (unlikely(!fin)) {
			fprintf(stderr, "Cannot read file %s: %d, %s\n",
					pathbuf, errno, strerror(errno));
			goto loop;
		}
		link_idx = -1;
		sysret = fscanf(fin, "%d", &link_idx);
		fclose(fin);
		if (sysret != 1) {
			fprintf(stderr, "Cannot read link index: %s\n",
					pathbuf);
			goto loop;
		}
		cansock = malloc(sizeof(struct can_sock));
		if (unlikely(!cansock)) {
			retv = ENOMEM;
			fprintf(stderr, "Out of Memory!\n");
			goto exit_20;
		}
		strcpy(cansock->nic.ifname, link_entry->d_name);
		cansock->nic.ifidx = link_idx;
		cansock->u_sock = info->u_sock;
		cansock->peer = info->peer;
		cansock->nic.nictyp = link_type;
		INIT_LIST_HEAD(&cansock->lnk);
		sysret = insert_node(cansock, cans);
		if (sysret != 0) {
			fprintf(stderr, "Cannot add link %s to capture\n",
					cansock->nic.ifname);
			if (unlikely(sysret > 0))
				fprintf(stderr, "Duplicate link found. " \
						"Impossible!\n");
			free(cansock);
		}
loop:
		errno = 0;
		link_entry = readdir(netdir);
	}
	if (errno) {
		fprintf(stderr, "readdir %s failed: %d, %s\n", SYS_NET_DIR,
				errno, strerror(errno));
		retv = errno;
	}
exit_20:
	free(pathbuf);
exit_10:
	closedir(netdir);
	return retv;
}

static void *can_capture(void *arg)
{
	struct can_sock *can = (struct can_sock *)arg;
	union {
		struct sockaddr_ll ether;
		struct sockaddr_can can;
	} me;
	struct pollfd pfd;
	int sysret, numbs, msglen;
	struct cancomm *pkt;
	struct flow_statistics *pst = &can->st;

	pst->num_bytes = 0;
	pst->num_pkts = 0;
	if (can->nic.nictyp == ETHERNET)
		can->c_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	else if (can->nic.nictyp == CANBUS)
		can->c_sock = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (unlikely(can->c_sock == -1)) {
		fprintf(stderr, "Unable to get a socket for NIC %d-%s: %d-%s\n",
				can->nic.ifidx, can->nic.ifname,
				errno, strerror(errno));
		return NULL;
	}
	memset(&me, 0, sizeof(me));
	if (can->nic.nictyp == ETHERNET) {
		me.ether.sll_family = AF_PACKET;
		me.ether.sll_ifindex = can->nic.ifidx;
	} else if (can->nic.nictyp == CANBUS) {
		me.can.can_family = AF_CAN;
		me.can.can_ifindex = can->nic.ifidx;
	} else
		assert(0);
	sysret = bind(can->c_sock, (struct sockaddr *)&me, sizeof(me));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Unable to bind to NIC %d: %d-%s\n",
				can->nic.ifidx, errno, strerror(errno));
		goto exit_10;
	}
	pkt = malloc(sizeof(struct cancomm)+PACKET_LENGTH);
	if (unlikely(!pkt)) {
		fprintf(stderr, "Out of Memory!\n");
		goto exit_10;
	}
	pkt->ifidx = can->nic.ifidx;
	pkt->iftyp = can->nic.nictyp;
	pfd.fd = can->c_sock;
	pfd.events = POLLIN;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 200);
		if (sysret == 0)
			continue;
		else if (unlikely(sysret == -1)) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll failed for capturing socket %d: %d-%s\n",
					can->nic.ifidx, errno, strerror(errno));
			goto exit_20;
		}
		sysret = clock_gettime(CLOCK_MONOTONIC_COARSE, &pkt->tm);
		if (unlikely(sysret == -1))
			fprintf(stderr, "Unable to get the time stamp " \
					"for packet: %d-%s\n",
					errno, strerror(errno));
		numbs = recv(can->c_sock, pkt->buf, PACKET_LENGTH, 0);
		if (unlikely(numbs == -1)) {
			fprintf(stderr, "Unable to read from capturing " \
					"NIC %d: %d-%s\n",
					can->nic.ifidx, errno, strerror(errno));
			goto exit_20;
		}
		pst->num_bytes += numbs;
		pst->num_pkts += 1;

		if (READ_ONCE(can->peer->sun_family) != AF_UNIX)
			continue;
		msglen = numbs + sizeof(struct cancomm);
		numbs = sendto(can->u_sock, (char *)pkt, msglen, 0,
				(struct sockaddr *)can->peer,
				sizeof(*can->peer));
		if (unlikely(numbs == -1))
			fprintf(stderr, "Unable to send captured packets to " \
					"UNIX socket: %d-%s\n",
					errno, strerror(errno));
	} while (!READ_ONCE(can->stop_cap));

exit_20:
	free(pkt);
exit_10:
	close(can->c_sock);
	return NULL;
}
