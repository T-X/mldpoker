/* SPDX-License-Identifier: MIT */
/* MLD Poker - A small utility that pokes sleepy devices for MLD Reports
 *
 * Copyright (c) 2020 Linus Lüssing <linus.luessing@c0d3.blue>
 *
 * License-Filename: LICENSES/preferred/MIT
 */

#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <stdlib.h>
#include "libnetlink.h"
#include "list.h"
#include "neigh.h"

/*
 * Number of seconds after which we consider a host to be
 *(potentially) asleep
 */
#define SLUMBER_TIME 15

static struct hlist_head neigh_list;
static struct hlist_head neigh_active_list;

static unsigned int filter_index;

static int neigh_brport_filter(struct nlmsghdr *nlh, int reqlen)
{
	struct ndmsg *ndm = NLMSG_DATA(nlh);
	ndm->ndm_ifindex = filter_index;
	return 0;
}

static long hz;

static void neigh_age_entries(void)
{
	struct neigh_list *neigh;
	struct hlist_node *neigh_tmp;

	hlist_for_each_entry_safe(neigh, neigh_tmp, &neigh_list, list) {
		neigh->last_seen++;

		if (neigh->last_seen > SLUMBER_TIME) {
			hlist_del(&neigh->active_list);
			hlist_del(&neigh->list);
			free(neigh);
		}
	}
}

static void neigh_update_num_tx(void)
{
	struct neigh_list *neigh;
	struct hlist_node *neigh_tmp;

	hlist_for_each_entry_safe(neigh, neigh_tmp, &neigh_active_list,
				  active_list)
		if (++(neigh->num_tx) > 1)
			hlist_del(&neigh->active_list);
}

static int neigh_add_entry(struct ether_addr *addr)
{
	struct neigh_list *neigh = malloc(sizeof(*neigh));

	if (!neigh)
		return -ENOMEM;

	neigh->addr = *addr;
	neigh->last_seen = 0;
	neigh->num_tx = 0;

	hlist_add_head(&neigh->list, &neigh_list);
	hlist_add_head(&neigh->active_list, &neigh_active_list);

	return 0;
}

static int neigh_update_entry(struct ether_addr *addr, unsigned long last_seen)
{
	struct neigh_list *neigh;
	const char *addrstr = ether_ntoa(addr);
	int found = 0;

	if (last_seen > 3 * 1000 * CHECK_INTERVAL)
		return 0;

	hlist_for_each_entry(neigh, &neigh_list, list) {
		if (memcmp(&neigh->addr, addr, sizeof(*addr)))
			continue;

		neigh->last_seen = 0;
		found = 1;
		break;
	}

	if (!found)
		return neigh_add_entry(addr);

	return 0;
}

static int neigh_update_rtnl(struct nlmsghdr *n, void *arg)
{
	struct ether_addr *addr;
	struct nda_cacheinfo *ci;
	struct ndmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	unsigned int last_seen;
	struct rtattr *tb[NDA_MAX+1];

	if (n->nlmsg_type != RTM_NEWNEIGH && n->nlmsg_type != RTM_DELNEIGH) {
		fprintf(stderr, "Not RTM_NEWNEIGH: %08x %08x %08x\n",
			n->nlmsg_len, n->nlmsg_type, n->nlmsg_flags);
		return 0;
	}

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	if (r->ndm_family != AF_BRIDGE || (r->ndm_state & NUD_PERMANENT))
		return 0;

	if (filter_index != r->ndm_ifindex)
		return 0;

	parse_rtattr(tb, NDA_MAX, NDA_RTA(r),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));

	/* ignoring VLANs for now */
	if (tb[NDA_VLAN] || !tb[NDA_CACHEINFO] || !tb[NDA_LLADDR] ||
	    RTA_PAYLOAD(tb[NDA_LLADDR]) != ETH_ALEN)
		return 0;

	ci = RTA_DATA(tb[NDA_CACHEINFO]);
	addr = RTA_DATA(tb[NDA_LLADDR]);

	if (addr->ether_addr_octet[0] & 0x01)
		return 0;

	last_seen = ci->ndm_updated * 1000 / hz;
	last_seen = last_seen ? last_seen : 1;

	neigh_update_entry(addr, last_seen);

	return 0;
}



static int neigh_brport_get(const int ifindex)
{
	struct rtnl_handle rth = { .fd = -1 };
	int ret;

	ret = rtnl_open(&rth, 0);
	if (ret < 0)
		goto err;

	filter_index = ifindex;

	rtnl_set_strict_dump(&rth);

	ret = rtnl_neighdump_req(&rth, PF_BRIDGE, neigh_brport_filter);
	if (ret < 0)
		goto err;

	if (rtnl_dump_filter(&rth, neigh_update_rtnl, NULL) < 0)
		goto err;

	ret = 0;

err:
	rtnl_close(&rth);
	
	return ret;
}

struct hlist_head *neigh_get_active(const int ifindex)
{
	neigh_update_num_tx();
	neigh_age_entries();

	if (neigh_brport_get(ifindex) < 0)
		return NULL;

	return &neigh_active_list;
}

int neigh_init(void)
{
	INIT_HLIST_HEAD(&neigh_list);
	INIT_HLIST_HEAD(&neigh_active_list);

	hz = sysconf(_SC_CLK_TCK);
	if (hz < 0)
		return -EACCES;

	return 0;
}

void neigh_free(void)
{
	struct neigh_list *neigh;
	struct hlist_node *neigh_tmp;

	hlist_for_each_entry_safe(neigh, neigh_tmp, &neigh_list, list) {
		hlist_del(&neigh->active_list);
		hlist_del(&neigh->list);
		free(neigh);
	}
}
