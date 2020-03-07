// SPDX-License-Identifier: MIT
/* MLD Poker - A small utility that pokes sleepy devices for MLD Reports
 *
 * Copyright (c) 2020 Linus Lüssing <linus.luessing@c0d3.blue>
 *
 * License-Filename: LICENSES/preferred/MIT
 */

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "chksum.h"
#include "list.h"
#include "neigh.h"

#if __BYTE_ORDER == __BIG_ENDIAN
#include <linux/byteorder/big_endian.h>
#else /* __BYTE_ORDER == __LITTLE_ENDIAN */
#include <linux/byteorder/little_endian.h>
#endif

#define ETH_STRLEN strlen("00:00:00:00:00:00")
#define ETH_ZERO { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }

#define IN6_ZERO \
{ \
	.s6_addr32[0] = 0, .s6_addr32[1] = 0, \
	.s6_addr32[2] = 0, .s6_addr32[3] = 0, \
}

#define IN6_MC_ALL_NODES \
{ \
	.s6_addr32[0] = __constant_htonl(0xff020000), \
	.s6_addr32[1] = 0, \
	.s6_addr32[2] = 0, \
	.s6_addr32[3] = __constant_htonl(0x00000001), \
}

#define SNOOP_FMT "/sys/class/net/%s/brport/bridge/bridge/multicast_snooping"
#define QUERIER_FMT "/sys/class/net/%s/brport/bridge/bridge/multicast_querier"

/*
 * MLD maximum response delay, in msec
 */
#define MLDMAXDELAY 1000

struct mldquery_pkt {
	struct ethhdr ethhdr;
	struct ip6_hdr ip6hdr;
	struct ip6_hbh hbh;
	struct ip6_opt_router rtr_alert;
	struct ip6_opt pad1;
	struct mld_hdr mldhdr;
} __attribute__((__packed__));

#define MLDQUERY_PKT_LEN \
	(sizeof(struct mldquery_pkt) - ETH_HLEN - sizeof(struct ip6_hdr))

const struct mldquery_pkt __mldquery_pkt = {
	.ethhdr = {
		.h_dest = ETH_ZERO,
		.h_source = ETH_ZERO,
		.h_proto = __constant_htons(ETH_P_IPV6),
	},
	.ip6hdr = {
		.ip6_flow = __constant_htonl(0x60000000),
		.ip6_plen = __constant_htons(MLDQUERY_PKT_LEN),
		.ip6_nxt = IPPROTO_HOPOPTS,
		.ip6_hlim = 1,
		.ip6_src = IN6_ZERO,
		.ip6_dst = IN6_MC_ALL_NODES,
	},
	.hbh = {
		.ip6h_nxt = IPPROTO_ICMPV6,
		.ip6h_len = 0,
	},
	.rtr_alert = {
		.ip6or_type = IP6OPT_ROUTER_ALERT,
		.ip6or_len = 2,
		.ip6or_value = IP6_ALERT_MLD,
	},
	.pad1 = {
		.ip6o_type = IP6OPT_PAD1,
		.ip6o_len = 0,
	},
	.mldhdr = {
		.mld_type = MLD_LISTENER_QUERY,
		.mld_code = 0,
		.mld_cksum = 0,
		.mld_maxdelay = 0,
		.mld_reserved = 0,
		.mld_addr = IN6_ZERO,
	},
};

static void usage(FILE *file, const char *prog)
{
	fprintf(file, "Usage: %s IFNAME\n", prog);
}

static int open_socket(const char *ifname)
{
	struct ifreq ifr;
	int sd;

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
	if (sd < 0) {
		fprintf(stderr, "Error: Could not open socket\n");
		return -EINVAL;
	}

	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr,
		       sizeof(ifr)) < 0) {
		close(sd);
		fprintf(stderr, "Error: Could not bind socket to %s\n", ifname);
		return -EINVAL;
	}

	return sd;
}

static int read_br_param(const char *pathfmt, const char *ifname, char *dst,
			 size_t dst_len)
{
	char pathname[128];
	FILE *file;

	snprintf(pathname, sizeof(pathname), pathfmt, ifname);

	file = fopen(pathname, "r");
	if (!file) {
		fprintf(stderr, "Error: Could open file for read: %s\n",
			pathname);
		return -EACCES;
	}

	if (!fgets(dst, dst_len, file)) {
		fclose(file);
		fprintf(stderr, "Error: Could not read from file: %s\n",
			pathname);
		return -EINVAL;
	}

	fclose(file);
}

static int get_brmac(const char *ifname, struct ether_addr *brmac)
{
	char brmacstr[ETH_STRLEN + 1];
	struct ether_addr *brmacptr;
	int ret;

	ret = read_br_param("/sys/class/net/%s/brport/bridge/address", ifname,
			    brmacstr, sizeof(brmacstr));
	if (ret < 0)
		return ret;

	brmacptr = ether_aton(brmacstr);
	if (!brmacptr) {
		fprintf(stderr, "Error: Invalid MAC address: %s\n", brmacstr);
		return -EINVAL;
	}

	*brmac = *brmacptr;
	return 0;
}

int get_ifindex(int sd, const char *ifname)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	memcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(sd, SIOCGIFINDEX, &ifr) < 0) {
		fprintf(stderr, "Error: Could not determine ifindex for %s\n",
			ifname);
		return -EINVAL;
	}

	return ifr.ifr_ifindex;
}

int get_br_ifindex(const char *ifname)
{
	char *endptr, *ifindexptr;
	char ifindexstr[64];
	long ifindex;
	int ret;

	ret = read_br_param("/sys/class/net/%s/brport/bridge/ifindex", ifname,
			    ifindexstr, sizeof(ifindexstr));
	if (ret < 0)
		return ret;

	ifindex = strtol(ifindexstr, &endptr, 10);
	if (errno != 0 || ifindex > UINT32_MAX || ifindex < 0 ||
	    endptr == ifindexstr) {
		fprintf(stderr, "Error: Invalid ifindex: %s\n", ifindexstr);
		return -EINVAL;
	}

	return ifindex;
}

int get_br_ipv6_lladdr(const char *ifname, struct in6_addr *brip6)
{
	struct sockaddr_in6 *ifa_sin6;
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	int br_ifindex, ifa_ifindex;
	int ret = -EADDRNOTAVAIL;

	br_ifindex = get_br_ifindex(ifname);
	if (br_ifindex < 0)
		return br_ifindex;

	if (getifaddrs(&ifaddr) < 0) {
		fprintf(stderr, "Error: getifaddrs() failed\n");
		return ret;
	}

	for (ifa = ifaddr, n = 0; ifa; ifa = ifa->ifa_next, n++) {
		if (!ifa->ifa_addr)
			continue;

		if (ifa->ifa_addr->sa_family != AF_INET6)
			continue;

		ifa_ifindex = if_nametoindex(ifa->ifa_name);
		if (ifa_ifindex <= 0 || ifa_ifindex != br_ifindex)
			continue;

		ifa_sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
		if (!IN6_IS_ADDR_LINKLOCAL(&ifa_sin6->sin6_addr))
			continue;

		*brip6 = ifa_sin6->sin6_addr;
		ret = 0;
		break;
	}

	freeifaddrs(ifaddr);

	if (ret < 0)
		fprintf(stderr,
			"Error: Could not retrieve ipv6 link-local address for %s\n",
			ifname);

	return ret;
}

struct mldquery_pkt *get_mldquery_pkt(const char *ifname,
				      struct mldquery_pkt *mldquery_pkt)
{
	struct ether_addr brmac;
	struct in6_addr brip6;

	if (get_brmac(ifname, &brmac) < 0)
		return NULL;

	if (get_br_ipv6_lladdr(ifname, &brip6) < 0)
		return NULL;

	*mldquery_pkt = __mldquery_pkt;
	memcpy(&mldquery_pkt->ethhdr.h_source, &brmac, ETH_ALEN);
	memcpy(&mldquery_pkt->ip6hdr.ip6_src, &brip6,
	       sizeof(mldquery_pkt->ip6hdr.ip6_src));

	return mldquery_pkt;
}

void update_mld_maxdelay(struct mldquery_pkt *mldquery_pkt, uint16_t maxdelay)
{
	uint16_t chksum;

	mldquery_pkt->mldhdr.mld_maxdelay = htons(maxdelay);
	mldquery_pkt->mldhdr.mld_cksum = 0;
	chksum = in_chksum((void *)&mldquery_pkt->ip6hdr,
			   (void *)&mldquery_pkt->mldhdr,
			   sizeof(mldquery_pkt->mldhdr),
			   IPPROTO_ICMPV6);
	mldquery_pkt->mldhdr.mld_cksum = chksum;
}

static int mld_poker(int sd, const int ifindex, struct ether_addr *addr,
		     uint16_t maxdelay, struct mldquery_pkt *mldquery_pkt)
{
	const char *addrstr = ether_ntoa(addr);
	struct sockaddr_ll sock_dst;
	char *dstaddr;
	int ret;

	memset(&sock_dst, 0, sizeof(sock_dst));
	sock_dst.sll_ifindex = ifindex;
	memcpy(&mldquery_pkt->ethhdr.h_dest, addr, ETH_ALEN);

	update_mld_maxdelay(mldquery_pkt, maxdelay);

	ret = sendto(sd, mldquery_pkt, sizeof(*mldquery_pkt), 0,
		     (struct sockaddr *)&sock_dst, sizeof(sock_dst));
	if (ret < 0) {
		dstaddr = ether_ntoa(addr);
		fprintf(stderr, "Error: Could send packet to %s\n",
			dstaddr ? dstaddr : "?");
	}

	printf("New host %s, poking it!\n", addrstr ? addrstr : "?");
}

/* ToDo: Check if we are the selected querier, too */
int br_querier_off(const char *ifname)
{
	char *endptr, *ifindexptr;
	char strbuff[64];
	long snooping, querier;
	int ret;

	ret = read_br_param(SNOOP_FMT, ifname, strbuff, sizeof(strbuff));
	if (ret < 0)
		return ret;

	snooping = strtol(strbuff, &endptr, 10);
	if (errno != 0 || snooping > UINT32_MAX || snooping < 0 ||
	    endptr == strbuff) {
		fprintf(stderr, "Error: Invalid multicast_snooping: %s\n",
			strbuff);
		return -EINVAL;
	}

	if (!snooping) {
		fprintf(stderr, "Warning: multicast snooping disabled\n");
		return -EBUSY;
	}

	ret = read_br_param(QUERIER_FMT, ifname, strbuff, sizeof(strbuff));
	if (ret < 0)
		return ret;

	querier = strtol(strbuff, &endptr, 10);
	if (errno != 0 || querier > UINT32_MAX || querier < 0 ||
	    endptr == strbuff) {
		fprintf(stderr, "Error: Invalid multicast_querier: %s\n",
			strbuff);
		return -EINVAL;
	}

	if (!querier) {
		fprintf(stderr, "Warning: multicast querier disabled\n");
		return -EBUSY;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct mldquery_pkt mldquery_pkt;
	struct hlist_head *neigh_list;
	struct neigh_list *neigh;
	const char *ifname;
	uint16_t maxdelay;
	int ifindex;
	int ret = 1, ret2, sd;

	if (argc != 2) {
		usage(stderr, argv[0]);
		exit(1);
	}

	ifname = argv[1];

	if (neigh_init() < 0)
		return ret;

	sd = open_socket(ifname);
	if (sd < 0)
		goto err;

	ifindex = get_ifindex(sd, ifname);
	if (ifindex < 0)
		goto err;

	if (!get_mldquery_pkt(ifname, &mldquery_pkt))
		goto err;

	while (1) {
		neigh_list = neigh_get_active(ifindex);
		if (!neigh_list)
			goto err;

		ret2 = br_querier_off(ifname);
		if (ret2 == -EBUSY)
			goto sleep;
		else if (ret2 < 0)
			goto err;

		hlist_for_each_entry(neigh, neigh_list, active_list) {
			maxdelay = neigh->num_tx ? MLDMAXDELAY : 0;

			if (mld_poker(sd, ifindex, &neigh->addr, maxdelay,
				      &mldquery_pkt) < 0)
				goto err;
		}

sleep:
		sleep(CHECK_INTERVAL);
	}

	ret = 0;
err:
	if (sd >= 0)
		close(sd);

	return ret;
}
