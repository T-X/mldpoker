/* SPDX-License-Identifier: MIT */
/* MLD Poker - A small utility that pokes sleepy devices for MLD Reports
 *
 * Copyright (c) 2020 Linus Lüssing <linus.luessing@c0d3.blue>
 *
 * License-Filename: LICENSES/preferred/MIT
 */

#ifndef __MLDPOKER_NEIGH_H__
#define __MLDPOKER_NEIGH_H__

#include <net/ethernet.h>
#include "list.h"

#define CHECK_INTERVAL 1

struct neigh_list {
	struct ether_addr addr;
	unsigned long last_seen;
	unsigned short num_tx;
	struct hlist_node list;
	struct hlist_node active_list;
};

struct hlist_head *neigh_get_active(const int ifindex);
int neigh_init(void);
void neigh_free(void);

#endif /* __MLDPOKER_NEIGH_H__ */
