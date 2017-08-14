#ifndef NETDEV_H
#define NETDEV_H

#define BUFLEN			 1600
#define MAX_ADDR_LEN	 32  

#include <inttypes.h>

#define netdev_dbg(fmt, ...)					\
do {											\
	print_debug("NETDEV:"fmt, ##__VAR_ARGS__);	\
} while (0)	

struct eth_hdr;
struct sk_buff;

struct netdev {
	uint32_t addr;			/* ip地址,主机字节序 */
	uint8_t addr_len;		
	uint8_t hwaddr[6];		/* mac地址,6个字节 */
	uint32_t mtu;			/* mtu,最大传输单元,一般默认为1500字节 */
};

void netdev_init();
int netdev_transmit(struct sk_buff *skb, uint8_t *dst, uint16_t ethertype);
void *netdev_rx_loop();
void free_netdev();
struct netdev *netdev_get(uint32_t sip);
int local_ipaddress(uint32_t addr);

#endif // !NETDEV_H
