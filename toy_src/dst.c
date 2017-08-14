#include "syshead.h"
#include "dst.h"
#include "ip.h"
#include "arp.h"

int
dst_neigh_output(struct sk_buff *skb)
{
	struct iphdr *iphdr = ip_hdr(skb);
	struct netdev *netdev = skb->dev;
	struct rtentry *rt = skb->rt;
	uint32_t daddr = ntohl(iphdr->daddr);
	uint32_t saddr = ntohl(iphdr->saddr);
	int count = 0;
	uint8_t *dmac;

	if (rt->flags & RT_GATEWAY) {
		daddr = rt->gateway;	  /*  需要发送到网关 */
	}

try_agin:
	dmac = arp_get_hwaddr(daddr); /* 根据ip地址获得mac地址 */

	if (dmac) {
		return netdev_transmit(skb, dmac, ETH_P_IP);
	}
	else {
		count += 1;
		arp_request(saddr, daddr, netdev);
        /* Inform upper layer that traffic was not sent, retry later */
		if (count < 3) {
			usleep(10000);
			goto try_agin;
		}
		return -1;
	}
}