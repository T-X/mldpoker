#ifndef __MLDPOKER_CHKSUM_H__
#define __MLDPOKER_CHKSUM_H__

uint16_t in_chksum(void *ptr_ipv6, void *ptr_icmpv6, size_t len, uint8_t proto);

#endif /* __MLDPOKER_CHKSUM_H__ */
