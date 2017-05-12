#ifndef CHECKSUM_H
#define CHECKSUM_H
#include "syshead.h"

struct pseudo_head {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t zero;
	uint8_t proto;
	uint16_t len;
};

uint32_t sum_every_16bits(void *addr, int count);
uint16_t checksum(void *addr, int count, int start_sum);
int tcp_udp_checksum(uint32_t saddr, uint32_t daddr, uint8_t proto,
	uint8_t *data, uint16_t len);

#endif //!CHECKSUM_H
