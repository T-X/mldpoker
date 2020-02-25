/*
 * Copyright (C) 2011-2018 Fernando Gont <fgont@si6networks.com>
 *
 * Programmed by Fernando Gont for SI6 Networks <http://www.si6networks.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * Build with: make libipv6
 * 
 * It requires that the libpcap library be installed on your system.
 *
 * Please send any bug reports to Fernando Gont <fgont@si6networks.com>
 *
 * From: ipv6toolkit / libipv6
 */

#include <linux/in6.h>
#include <inttypes.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <string.h>

struct ipv6pseudohdr{
    struct in6_addr srcaddr;
    struct in6_addr dstaddr;
    uint32_t	len;
    uint8_t zero[3];
    uint8_t	nh;
} __attribute__ ((__packed__));

/* 
 * Function: in_chksum()
 *
 * Calculate the 16-bit ICMPv6 checksum
 */

uint16_t in_chksum(void *ptr_ipv6, void *ptr_icmpv6, size_t len, uint8_t proto){
	struct ipv6pseudohdr pseudohdr;
	struct ip6_hdr *v6packet;
	size_t nleft;
	unsigned int sum = 0;
	uint16_t *w;
	uint16_t answer = 0;

	v6packet=ptr_ipv6;
	
	memset(&pseudohdr, 0, sizeof(struct ipv6pseudohdr));
	pseudohdr.srcaddr= v6packet->ip6_src;
	pseudohdr.dstaddr= v6packet->ip6_dst;
	pseudohdr.len = htons(len);
	pseudohdr.nh = proto;

	nleft=40;
	w= (uint16_t *) &pseudohdr;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	nleft= len;
	w= (uint16_t *) ptr_icmpv6;

	while(nleft > 1){
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1){
		*(unsigned char *) (&answer) = *(unsigned char *) w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;
	return(answer);
}
