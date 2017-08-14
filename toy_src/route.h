#ifndef _ROUTE_H
#define _ROUTE_H

#include "list.h"

#define RT_LOOPBACK 0x01
#define RT_GATEWAY  0x02
#define RT_HOST		0x03
#define RT_REJECT	0x04
#define RT_UP		0x05

struct rtentry {
	struct list_head list;
	uint32_t dst;
	uint32_t gateway;		/* 网关 */
	uint32_t netmask;		/* 子网掩码 */
	uint8_t flags;
	uint32_t metric;		/* 在本应用中基本没有什么用处 */
	struct netdev *dev;     /* dev主要记录网关的地址信息,包括ip地址和mac地址 */
};

void route_init();
struct rtentry * route_lookup(uint32_t daddr);
void free_routes();

#endif // !_ROUTE_H_