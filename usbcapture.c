#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>

/*
 * Defined by USB 2.0 clause 9.3, table 9.2.
 */
#define SETUP_LEN  8

/* ioctl macros */
#define MON_IOC_MAGIC 0x92

#define MON_IOCQ_URB_LEN _IO(MON_IOC_MAGIC, 1)
/* #2 used to be MON_IOCX_URB, removed before it got into Linus tree */
#define MON_IOCG_STATS _IOR(MON_IOC_MAGIC, 3, struct mon_bin_stats)
#define MON_IOCT_RING_SIZE _IO(MON_IOC_MAGIC, 4)
#define MON_IOCQ_RING_SIZE _IO(MON_IOC_MAGIC, 5)
#define MON_IOCX_GET   _IOW(MON_IOC_MAGIC, 6, struct mon_bin_get)
#define MON_IOCX_MFETCH _IOWR(MON_IOC_MAGIC, 7, struct mon_bin_mfetch)
#define MON_IOCH_MFLUSH _IO(MON_IOC_MAGIC, 8)
/* #9 was MON_IOCT_SETAPI */
#define MON_IOCX_GETX   _IOW(MON_IOC_MAGIC, 10, struct mon_bin_get)

/*
 * The per-event API header (2 per URB).
 *
 * This structure is seen in userland as defined by the documentation.
 */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef long long s64;
typedef int s32;

static inline unsigned short le2cpu_16(unsigned short *u16)
{
	return *u16;
}

static int stop_flag = 0;

static void sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		stop_flag = 1;
}

struct mon_bin_hdr {
	u64 id;			/* URB ID - from submission to callback */
	unsigned char type;	/* Same as in text API; extensible. */
	unsigned char xfer_type;	/* ISO, Intr, Control, Bulk */
	unsigned char epnum;	/* Endpoint number and transfer direction */
	unsigned char devnum;	/* Device address */
	unsigned short busnum;	/* Bus number */
	char flag_setup;
	char flag_data;
	s64 ts_sec;		/* ktime_get_real_ts64 */
	s32 ts_usec;		/* ktime_get_real_ts64 */
	int status;
	unsigned int len_urb;	/* Length of data (submitted or actual) */
	unsigned int len_cap;	/* Delivered length */
	union {
		unsigned char setup[SETUP_LEN];	/* Only for Control S-type */
		struct iso_rec {
			int error_count;
			int numdesc;
		} iso;
	} s;
	int interval;
	int start_frame;
	unsigned int xfer_flags;
	unsigned int ndesc;	/* Actual number of ISO descriptors */
};

/* per file statistic */
struct mon_bin_stats {
	u32 queued;
	u32 dropped;
};

struct mon_bin_get {
	struct mon_bin_hdr *hdr;	/* Can be 48 bytes or 64. */
	void *data;
	size_t alloc;		/* Length of data (can be zero) */
};

struct cmdline_option {
	int bus;
	int device;
	int num_threads;
	int datlen;
	int debug;
	int endpoint;
};

static inline const char *getlstr(const struct option *lopts, char c)
{
	const struct option *opt = lopts;
	
	for (opt = lopts; opt->name; opt++)
		if (opt->val == c)
			return opt->name;
	return opt->name;
}

static void parse_options(int argc, char *argv[], struct cmdline_option *cmdline)
{
	int fin = 0, c;
	extern char *optarg;
	extern int opterr, optopt;
	static const struct option lopts[] = {
		{
			.name = "bus",
			.has_arg = 1,
			.flag = NULL,
			.val = 'b'
		},
		{
			.name = "device",
			.has_arg = 1,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "endpoint",
			.has_arg = 1,
			.flag = NULL,
			.val = 'e'
		},
		{
			.name = "threads",
			.has_arg = 1,
			.flag = NULL,
			.val = 't'
		},
		{
			.name = "length",
			.has_arg = 1,
			.flag = NULL,
			.val = 'l'
		},
		{
			.name = "debug",
			.has_arg = 0,
			.flag = NULL,
			.val = 'g'
		},
		{}
	};
	static const char *opts = ":b:d:t:l:g:e:";

	cmdline->bus = 0;
	cmdline->device = 0;
	cmdline->num_threads = 1;
	cmdline->debug = 0;
	cmdline->datlen = 128;
	opterr = 0;
	do {
		optopt = 0;
		c = getopt_long(argc, argv, opts, lopts, NULL);
		switch(c) {
		case 't':
			cmdline->num_threads = atoi(optarg);
			if (cmdline->num_threads <= 0) {
				fprintf(stderr, "Invalid number of threads: %d. Setting to 1\n", cmdline->num_threads);
				cmdline->num_threads = 1;
			}
			break;
		case 'e':
			cmdline->endpoint = atoi(optarg);
			if (cmdline->endpoint <= 0 || cmdline->endpoint > 15) {
				fprintf(stderr, "Invalid endpoint number: %d\n", cmdline->endpoint);
				cmdline->endpoint = 0;
			}
			break;
		case 'g':
			cmdline->debug = 1;
			break;
		case 'l':
			cmdline->datlen = atoi(optarg);
			if (cmdline->datlen <= 0 || cmdline->datlen > 1024) {
				fprintf(stderr, "Invalid data length: %d. Setting to 128\n", cmdline->datlen);
				cmdline->datlen = 128;
			}
			break;
		case 'b':
			cmdline->bus = atoi(optarg);
			break;
		case 'd':
			cmdline->device = atoi(optarg);
			break;
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
			fprintf(stderr, "Missing arguments for -%c/--%s\n", (char)optopt, getlstr(lopts, optopt));
			break;

		default:
			fprintf(stderr, "Logic Error in getopt_long\n");
			break;
		}
	} while (fin == 0);
}

#define READ_ONCE(x)	(*((const volatile typeof(x) *)&x))

struct thread_param {
	pthread_t thid;
	const struct cmdline_option *cmdl;
	pthread_mutex_t *rdmutex;
	int *stop;
	time_t tm_start;
	int usbfd;
	int creat;
	int id;
};

static void debug_output(int thidx, const struct mon_bin_hdr *hdr)
{

	printf("%08lld.%06d ", hdr->ts_sec, hdr->ts_usec);
	printf("%03hd:%03hhd:%02hhx ", hdr->busnum, hdr->devnum, hdr->epnum);
	printf("%02hhx:%02hhx:%02hhx:%02hhx ", hdr->type, hdr->xfer_type, hdr->flag_setup, hdr->flag_data);
	printf("len_urb: %d, len_cap: %d from thread %d\n",hdr->len_urb, hdr->len_cap, thidx);
}

static void process_received(struct thread_param *param, struct mon_bin_get *binget)
{
	struct mon_bin_hdr *hdr = binget->hdr;
	int submission, len, i;
	unsigned short v;
	unsigned char *curc;

	if (param->cmdl->debug)
		debug_output(param->id, hdr);
	printf("%16llx %08lld.%06d %c ", hdr->id, (hdr->ts_sec - param->tm_start),
			hdr->ts_usec, hdr->type);
	if (hdr->type == 'S' || hdr->type == 'E')
		submission = 1;
	else
		submission = 0;
	switch(hdr->xfer_type) {
	case 0:
		printf("Z");
		break;
	case 1:
		printf("I");
		break;
	case 2:
		printf("C");
		break;
	case 3:
		printf("B");
		break;
	default:
		printf("?");
	}
	if ((hdr->epnum >> 7))
		printf("i:");
	else
		printf("o:");
	printf("%02hu:%03hhu:%02u ", hdr->busnum, hdr->devnum, (unsigned int)(hdr->epnum & 0x0f));
	if (submission) {
		if (hdr->flag_setup == 0)
			printf("  s ");
		else
			printf("  x ");
	} else {
		printf(" %2d", hdr->status);
		if (hdr->xfer_type == 1)
			printf(":%d ", hdr->interval);
	}
	if (hdr->flag_setup == 0) {
		printf("%02x %02x %02x%02x %02x%02x ", 
					hdr->s.setup[0],
				        hdr->s.setup[1],
					hdr->s.setup[3],
					hdr->s.setup[2],
					hdr->s.setup[5],
					hdr->s.setup[4]);
		v = le2cpu_16((unsigned short *)(hdr->s.setup+6));
		printf("%hu ", v);
	}
	len = hdr->len_urb;
	printf("%3d ", hdr->len_urb);
	if (hdr->flag_data == 0) {
		for (curc = binget->data, i = 0; i < len; curc++, i++)
			printf(" %02x", *curc);
	} else
		printf("%c", hdr->flag_data);

	printf("\n");
}

static void *fetch(void *arg)
{
	struct thread_param *param = arg;
	int sysret, pret;
	struct mon_bin_get *binget;
	struct pollfd pfd;

	binget = malloc(sizeof(struct mon_bin_get)+sizeof(struct mon_bin_hdr)+param->cmdl->datlen);
	if (!binget) {
		fprintf(stderr, "Out of Memory!\n");
		goto exit_10;
	}

	binget->hdr = (struct mon_bin_hdr *)(binget + 1);
	binget->data = (binget->hdr + 1);
	binget->alloc = param->cmdl->datlen;

	pfd.fd = param->usbfd;
	pfd.events = POLLIN;
	while (READ_ONCE(*param->stop) == 0) {
		pthread_mutex_lock(param->rdmutex);
		pfd.revents = 0;
		do
			pret = poll(&pfd, 1, 500);
		while (pret == 0 && READ_ONCE(*param->stop) == 0);
		sysret = -2;
		if (pret == -1)
			fprintf(stderr, "poll failed: %s\n", strerror(errno));
		else if (pret > 0)
			sysret = ioctl(param->usbfd, MON_IOCX_GETX, binget);
		pthread_mutex_unlock(param->rdmutex);
		if (sysret == -1) {
			fprintf(stderr, "ioctl failed %d:%s\n", (int)MON_IOCX_GETX, strerror(errno));
			break;
		} else if (sysret == 0 && (param->cmdl->bus == 0 || binget->hdr->devnum == param->cmdl->device))
			process_received(param, binget);
	}
	free(binget);

exit_10:
	return NULL;
}

static char capdev[128];
int main(int argc, char *argv[])
{
	struct cmdline_option cmdl;
	int i, len, monfd, retv, thnums, sysret;
	struct thread_param *param, *curarg;
	pthread_mutex_t rdmutex;
	struct sigaction sigact;
	struct timeval mtime;

	retv = 0;
	parse_options(argc, argv, &cmdl);
	gettimeofday(&mtime, NULL);
	printf("Start at: %lu, ", (unsigned long)mtime.tv_sec);
	printf("Watching USB, bus: %d, device: %d. Number of threads: %d\n",
			cmdl.bus, cmdl.device, cmdl.num_threads);

	param = malloc(sizeof(struct thread_param)*cmdl.num_threads);
	if (!param) {
		fprintf(stderr, "Out of Memory!\n");
		return ENOMEM;
	}
	pthread_mutex_init(&rdmutex, NULL);
	len = sizeof(capdev);
	snprintf(capdev, len, "/dev/usbmon%d", cmdl.bus);
	capdev[len-1] = 0;
	monfd = open(capdev, O_RDONLY);
	if (monfd == -1) {
		fprintf(stderr, "Cannot open %s: %s\n", capdev, strerror(errno));
		retv = errno;
		goto exit_10;
	}
	thnums = 0;
	stop_flag = 0;
	for (i = 0, curarg = param; i < cmdl.num_threads; i++, curarg++) {
		curarg->stop = &stop_flag;
		curarg->cmdl = &cmdl;
		curarg->rdmutex = &rdmutex;
		curarg->creat = 0;
		curarg->usbfd = monfd;
		curarg->id = i;
		curarg->tm_start = mtime.tv_sec;
		sysret = pthread_create(&curarg->thid, NULL, fetch, curarg);
		if (sysret)
			fprintf(stderr, "pthread_create failed: %s\n", strerror(sysret));
		else {
			curarg->creat = 1;
			thnums += 1;
		}
	}
	if (thnums == 0)
		goto exit_20;

	memset(&sigact, 0, sizeof(sigact));
	sigact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &sigact, NULL) == -1) {
		stop_flag = 1;
		fprintf(stderr, "Cannot install signal hander for SIGINT: %s\n", strerror(errno));
	}
	if (sigaction(SIGINT, &sigact, NULL) == -1) {
		stop_flag = 1;
		fprintf(stderr, "Cannot install signal hander for SIGTERM: %s\n", strerror(errno));
	}

	for (i = 0, curarg = param; i < cmdl.num_threads; i++, curarg++) {
		if (curarg->creat == 0)
			continue;
		pthread_join(curarg->thid, NULL);
	}
	
exit_20:
	close(monfd);
exit_10:
	pthread_mutex_destroy(&rdmutex);
	free(param);
	return retv;
}
